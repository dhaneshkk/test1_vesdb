//! EventQL for vesdb, compiled to Apache DataFusion logical plans.
//!
//! `parse` turns text into an [`ast::Query`]; `run` compiles it into one DataFusion
//! `LogicalPlan` per query level (subqueries are run first and become in-memory tables) and
//! returns rows as JSON. Pipeline of the plan:
//!
//! ```text
//! scan(alias₁) × scan(alias₂) … → filter(WHERE) → window(row_number ORDER BY …) as _ord
//!   → [aggregate(GROUP BY; aggregates, min(_ord)) → filter(HAVING)] → project(PROJECT INTO, _ord)
//!   → [distinct: aggregate(all projected; min(_ord))] → sort(_ord) → limit(SKIP, TOP)
//! ```
//!
//! EventQL is dynamically typed. Every compiled expression carries a [`Kind`]: a typed column,
//! a JSON value (canonical JSON text, see [`udf`]) or a whole event row; operators coerce by
//! kind. Where behaviour deviates from EventSourcingDB it is listed in `DEVIATIONS`.

pub mod ast;
pub mod parser;
mod udf;

use ast::*;
use datafusion::arrow::array::{
    ArrayRef, RecordBatch, StringArray, TimestampNanosecondArray, UInt64Array,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef, TimeUnit};
use datafusion::common::{Column, ScalarValue, TableReference};
use datafusion::datasource::{provider_as_source, MemTable};
use datafusion::execution::runtime_env::RuntimeEnvBuilder;
use datafusion::functions::expr_fn as f;
use datafusion::functions_aggregate::expr_fn as agg;
use datafusion::functions_window::expr_fn::row_number;
use datafusion::logical_expr::{
    cast, lit, when, Expr as DExpr, ExprFunctionExt, LogicalPlan, LogicalPlanBuilder, ScalarUDF,
    SortExpr,
};
use datafusion::prelude::SessionContext;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

pub use datafusion::arrow;
pub use parser::parse;

/// Behaviour that differs from EventSourcingDB's EventQL (documented, tested where it matters).
pub const DEVIATIONS: &[&str] = &[
    "Integers are 64-bit (EventSourcingDB: exact up to 1,000 digits); larger literals are refused.",
    "`/` is floating-point division; `%` on integers stays integer.",
    "Aggregates ignore NULL inputs (SQL semantics) instead of failing on them.",
    "ORDER BY on a JSON field orders numbers; cast with AS STRING to order text.",
    "INSTR and SUBSTRING use 0-based UTF-8 byte offsets; INSTR returns -1 when absent.",
    "JSON values compare by canonical JSON text, so 1 == 1.0 between two JSON fields is false (number literals compare numerically).",
    "Objects and arrays may appear only in PROJECT INTO.",
];

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("query-malformed: {0}")]
    Malformed(String),
    #[error("query-too-long")]
    TooLong,
    #[error("query-too-deep")]
    TooDeep,
    #[error("query-unevaluable: {0}")]
    Unevaluable(String),
    #[error(
        "query-not-boolean: the query must return exactly one row with the value true or false"
    )]
    NotBoolean,
}

impl Error {
    pub fn slug(&self) -> &'static str {
        match self {
            Error::Malformed(_) => "query-malformed",
            Error::TooLong => "query-too-long",
            Error::TooDeep => "query-too-deep",
            Error::Unevaluable(_) => "query-unevaluable",
            Error::NotBoolean => "query-not-boolean",
        }
    }
}

fn uneval(e: impl std::fmt::Display) -> Error {
    Error::Unevaluable(e.to_string())
}

// ------------------------------------------------------------------------------------------ catalog

pub const EVENT_COLUMNS: &[&str] = &[
    "id",
    "time",
    "source",
    "subject",
    "type",
    "datacontenttype",
    "data",
    "predecessorhash",
    "hash",
    "traceparent",
    "tracestate",
    "signature",
];

/// Arrow schema of the `events` source: `_seq` (u64 id), then the CloudEvent fields. `time` is
/// a UTC timestamp, `data` the exact JSON text (NULL when redacted), everything else text.
pub fn events_schema() -> SchemaRef {
    let mut fields = vec![Field::new("_seq", DataType::UInt64, false)];
    for c in EVENT_COLUMNS {
        let dt = if *c == "time" {
            DataType::Timestamp(TimeUnit::Nanosecond, Some("UTC".into()))
        } else {
            DataType::Utf8
        };
        fields.push(Field::new(
            *c,
            dt,
            !matches!(*c, "id" | "time" | "source" | "subject" | "type"),
        ));
    }
    Arc::new(Schema::new(fields))
}

/// One event, as the server hands it to EventQL.
pub struct EventRow<'a> {
    pub id: u64,
    pub time_ns: u64,
    pub source: &'a str,
    pub subject: &'a str,
    pub ty: &'a str,
    pub data: Option<&'a str>,
    pub predecessorhash: &'a str,
    pub hash: &'a str,
    pub traceparent: Option<&'a str>,
    pub tracestate: Option<&'a str>,
}

pub fn events_batch(rows: &[EventRow<'_>]) -> RecordBatch {
    let s = |f: &dyn Fn(&EventRow) -> Option<String>| -> ArrayRef {
        Arc::new(rows.iter().map(f).collect::<StringArray>())
    };
    let cols: Vec<ArrayRef> = vec![
        Arc::new(rows.iter().map(|r| r.id).collect::<UInt64Array>()),
        s(&|r| Some(r.id.to_string())),
        Arc::new(
            TimestampNanosecondArray::from(
                rows.iter().map(|r| r.time_ns as i64).collect::<Vec<_>>(),
            )
            .with_timezone("UTC"),
        ),
        s(&|r| Some(r.source.into())),
        s(&|r| Some(r.subject.into())),
        s(&|r| Some(r.ty.into())),
        s(&|_| Some("application/json".into())),
        s(&|r| r.data.map(Into::into)),
        s(&|r| Some(r.predecessorhash.into())),
        s(&|r| Some(r.hash.into())),
        s(&|r| r.traceparent.map(Into::into)),
        s(&|r| r.tracestate.map(Into::into)),
        s(&|_| None),
    ];
    RecordBatch::try_new(events_schema(), cols).expect("events batch")
}

/// What a query can read: the event table (in id order), plus subjects and event types.
#[derive(Clone, Default)]
pub struct Catalog {
    pub events: Vec<RecordBatch>,
    pub subjects: Vec<String>,
    pub event_types: Vec<String>,
}

impl Catalog {
    fn event_count(&self) -> usize {
        self.events.iter().map(|b| b.num_rows()).sum()
    }
}

#[derive(Clone)]
pub struct Limits {
    pub max_rows: usize,
    pub memory_bytes: usize,
    pub timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_rows: 1_000_000,
            memory_bytes: 1 << 30,
            timeout: Duration::from_secs(60),
        }
    }
}

// ------------------------------------------------------------------------------------------ kinds

#[derive(Clone, Debug, PartialEq)]
enum Kind {
    Json,
    Str,
    Int,
    Float,
    Bool,
    Time,
    Date,
    Null,
    /// a whole event row of this alias
    Row(String),
}

#[derive(Clone, Debug)]
struct C {
    e: DExpr,
    k: Kind,
}

fn c(e: DExpr, k: Kind) -> C {
    C { e, k }
}

#[derive(Clone, PartialEq)]
enum AliasKind {
    Events,
    Value,
}

struct Udfs {
    jget: Arc<ScalarUDF>,
    jnum: Arc<ScalarUDF>,
    jint: Arc<ScalarUDF>,
    jfloat: Arc<ScalarUDF>,
    jstr: Arc<ScalarUDF>,
    jtostr: Arc<ScalarUDF>,
    jbool: Arc<ScalarUDF>,
    jtobool: Arc<ScalarUDF>,
    jquote: Arc<ScalarUDF>,
    ts_text: Arc<ScalarUDF>,
    strict_bool: Arc<ScalarUDF>,
    strict_f64: Arc<ScalarUDF>,
    instr: Arc<ScalarUDF>,
    substring: Arc<ScalarUDF>,
}

impl Udfs {
    fn new() -> Self {
        Self {
            jget: udf::jget(),
            jnum: udf::jnum(),
            jint: udf::jint(),
            jfloat: udf::jfloat(),
            jstr: udf::jstr(),
            jtostr: udf::jtostr(),
            jbool: udf::jbool(),
            jtobool: udf::jtobool(),
            jquote: udf::jquote(),
            ts_text: udf::ts_text(),
            strict_bool: udf::strict_bool(),
            strict_f64: udf::strict_f64(),
            instr: udf::instr(),
            substring: udf::substring(),
        }
    }
}

fn ts_type() -> DataType {
    DataType::Timestamp(TimeUnit::Nanosecond, Some("UTC".into()))
}

fn qcol(alias: &str, name: &str) -> DExpr {
    DExpr::Column(Column::new(Some(TableReference::bare(alias)), name))
}

fn ucol(name: &str) -> DExpr {
    DExpr::Column(Column::new_unqualified(name))
}

/// Aggregate collected while compiling HAVING / PROJECT INTO.
struct AggSlot {
    expr: DExpr,
    /// fails over an empty set (AVG, MIN, MAX, MEDIAN, STDDEV, VARIANCE, UNIQUE)
    needs_rows: bool,
    /// hidden COUNT(DISTINCT x) for UNIQUE
    unique_check: Option<String>,
}

struct Compiler<'a> {
    u: &'a Udfs,
    aliases: HashMap<String, AliasKind>,
    /// Some when compiling HAVING / PROJECT INTO of an aggregated query
    aggs: Option<Vec<AggSlot>>,
}

impl Compiler<'_> {
    // -------------------------------------------------------------------- coercions

    fn to_json(&self, x: C) -> Result<DExpr, Error> {
        Ok(match x.k {
            Kind::Json => x.e,
            Kind::Str => self.u.jquote.call(vec![x.e]),
            Kind::Int | Kind::Float | Kind::Bool => cast(x.e, DataType::Utf8),
            Kind::Time => self.u.jquote.call(vec![self.u.ts_text.call(vec![x.e])]),
            Kind::Date => self.u.jquote.call(vec![cast(x.e, DataType::Utf8)]),
            Kind::Null => lit(ScalarValue::Utf8(None)),
            Kind::Row(_) => {
                return Err(uneval("a whole event cannot be used inside an expression"))
            }
        })
    }

    fn to_f64(&self, x: C) -> Result<DExpr, Error> {
        Ok(match x.k {
            Kind::Json => self.u.jnum.call(vec![x.e]),
            Kind::Int | Kind::Float => cast(x.e, DataType::Float64),
            Kind::Null => lit(ScalarValue::Float64(None)),
            k => return Err(uneval(format!("expected a number, got {k:?}"))),
        })
    }

    fn to_bool(&self, x: C) -> Result<DExpr, Error> {
        Ok(match x.k {
            Kind::Bool => x.e,
            Kind::Json => self.u.jbool.call(vec![x.e]),
            Kind::Null => lit(ScalarValue::Boolean(None)),
            k => return Err(uneval(format!("expected a boolean, got {k:?}"))),
        })
    }

    fn to_str(&self, x: C) -> Result<DExpr, Error> {
        Ok(match x.k {
            Kind::Str => x.e,
            Kind::Json => self.u.jstr.call(vec![x.e]),
            Kind::Null => lit(ScalarValue::Utf8(None)),
            k => return Err(uneval(format!("expected a string, got {k:?}"))),
        })
    }

    fn to_time(&self, x: C) -> Result<DExpr, Error> {
        Ok(match x.k {
            Kind::Time => x.e,
            Kind::Str => cast(x.e, ts_type()),
            Kind::Json => cast(self.u.jstr.call(vec![x.e]), ts_type()),
            Kind::Null => lit(ScalarValue::TimestampNanosecond(None, Some("UTC".into()))),
            k => return Err(uneval(format!("expected a date-time, got {k:?}"))),
        })
    }

    // -------------------------------------------------------------------- expressions

    fn path(&self, alias: &str, path: &[PathSeg]) -> Result<C, Error> {
        let kind = self
            .aliases
            .get(alias)
            .ok_or_else(|| Error::Malformed(format!("unknown alias {alias}")))?;
        if self.aggs.is_some() {
            return Err(uneval("fields cannot be used outside aggregates in an aggregated projection or HAVING; use UNIQUE(...)"));
        }
        let json_path = |segs: &[PathSeg]| {
            Value::Array(
                segs.iter()
                    .map(|s| match s {
                        PathSeg::Key(k) => Value::String(k.clone()),
                        PathSeg::Index(i) => Value::from(*i),
                    })
                    .collect(),
            )
            .to_string()
        };
        match kind {
            AliasKind::Value => Ok(c(
                self.u
                    .jget
                    .call(vec![qcol(alias, "value"), lit(json_path(path))]),
                Kind::Json,
            )),
            AliasKind::Events => {
                let Some((first, rest)) = path.split_first() else {
                    return Ok(c(lit(1), Kind::Row(alias.into())));
                };
                let PathSeg::Key(name) = first else {
                    return Ok(c(lit(ScalarValue::Utf8(None)), Kind::Null));
                };
                match name.as_str() {
                    "data" => Ok(c(
                        self.u
                            .jget
                            .call(vec![qcol(alias, "data"), lit(json_path(rest))]),
                        Kind::Json,
                    )),
                    "time" if rest.is_empty() => Ok(c(qcol(alias, "time"), Kind::Time)),
                    "specversion" if rest.is_empty() => Ok(c(lit("1.0"), Kind::Str)),
                    n if EVENT_COLUMNS.contains(&n) && rest.is_empty() => {
                        Ok(c(qcol(alias, n), Kind::Str))
                    }
                    _ => Ok(c(lit(ScalarValue::Utf8(None)), Kind::Null)),
                }
            }
        }
    }

    fn expr(&mut self, e: &Expr) -> Result<C, Error> {
        stacker::maybe_grow(parser::RED_ZONE, parser::STACK_GROWTH, || {
            self.expr_inner(e)
        })
    }

    fn expr_inner(&mut self, e: &Expr) -> Result<C, Error> {
        match e {
            Expr::Lit(Lit::Int(v)) => Ok(c(lit(*v), Kind::Int)),
            Expr::Lit(Lit::Float(v)) => Ok(c(lit(*v), Kind::Float)),
            Expr::Lit(Lit::Str(s)) => Ok(c(lit(s.clone()), Kind::Str)),
            Expr::Lit(Lit::Bool(b)) => Ok(c(lit(*b), Kind::Bool)),
            Expr::Lit(Lit::Null) => Ok(c(lit(ScalarValue::Utf8(None)), Kind::Null)),
            Expr::Path { alias, path } => self.path(alias, path),
            Expr::Unary(UnOp::Not, x) => {
                let x = self.expr(x)?;
                Ok(c(DExpr::Not(Box::new(self.to_bool(x)?)), Kind::Bool))
            }
            Expr::Unary(UnOp::Neg, x) => {
                let x = self.expr(x)?;
                Ok(match x.k {
                    Kind::Int => c(DExpr::Negative(Box::new(x.e)), Kind::Int),
                    _ => c(DExpr::Negative(Box::new(self.to_f64(x)?)), Kind::Float),
                })
            }
            Expr::Binary(op, a, b) => self.binary(*op, a, b),
            Expr::Cast(x, ty) => self.cast(x, *ty),
            Expr::Call(name, args) => self.call(name, args),
            Expr::Object(_) | Expr::Array(_) => Err(uneval(
                "objects and arrays are only supported in PROJECT INTO",
            )),
        }
    }

    fn binary(&mut self, op: BinOp, a: &Expr, b: &Expr) -> Result<C, Error> {
        let (x, y) = (self.expr(a)?, self.expr(b)?);
        use BinOp::*;
        match op {
            And | Or | Xor => {
                let (p, q) = (self.to_bool(x)?, self.to_bool(y)?);
                Ok(c(
                    match op {
                        And => p.and(q),
                        Or => p.or(q),
                        _ => p.clone().or(q.clone()).and(DExpr::Not(Box::new(p.and(q)))),
                    },
                    Kind::Bool,
                ))
            }
            Add | Sub | Mul | Div | Mod => {
                if op == Add && (x.k == Kind::Str || y.k == Kind::Str) {
                    let (s1, s2) = (self.to_str(x)?, self.to_str(y)?);
                    return Ok(c(f::concat(vec![s1, s2]), Kind::Str));
                }
                let both_int = x.k == Kind::Int && y.k == Kind::Int;
                if both_int && op != Div {
                    let e = match op {
                        Add => x.e + y.e,
                        Sub => x.e - y.e,
                        Mul => x.e * y.e,
                        _ => x.e % y.e,
                    };
                    return Ok(c(e, Kind::Int));
                }
                let (p, q) = (self.to_f64(x)?, self.to_f64(y)?);
                Ok(c(
                    match op {
                        Add => p + q,
                        Sub => p - q,
                        Mul => p * q,
                        Div => p / q,
                        _ => p % q,
                    },
                    Kind::Float,
                ))
            }
            Eq | Ne | Lt | Le | Gt | Ge => self.compare(op, x, y),
        }
    }

    fn compare(&self, op: BinOp, x: C, y: C) -> Result<C, Error> {
        use BinOp::*;
        let mk = |p: DExpr, q: DExpr| match op {
            Eq => p.eq(q),
            Ne => p.not_eq(q),
            Lt => p.lt(q),
            Le => p.lt_eq(q),
            Gt => p.gt(q),
            _ => p.gt_eq(q),
        };
        // NULL literals: == / != test presence; ordering against NULL is a type error
        if x.k == Kind::Null || y.k == Kind::Null {
            let other = if x.k == Kind::Null { y } else { x };
            return match op {
                Eq => Ok(c(
                    if other.k == Kind::Null {
                        lit(true)
                    } else {
                        other.e.is_null()
                    },
                    Kind::Bool,
                )),
                Ne => Ok(c(
                    if other.k == Kind::Null {
                        lit(false)
                    } else {
                        other.e.is_not_null()
                    },
                    Kind::Bool,
                )),
                _ => Err(uneval("ordering comparison with NULL")),
            };
        }
        let num = |k: &Kind| matches!(k, Kind::Int | Kind::Float);
        let e = match (&x.k, &y.k) {
            (Kind::Int, Kind::Int)
            | (Kind::Str, Kind::Str)
            | (Kind::Bool, Kind::Bool)
            | (Kind::Date, Kind::Date) => mk(x.e, y.e),
            (Kind::Time, _) | (_, Kind::Time) => mk(self.to_time(x)?, self.to_time(y)?),
            (a, b) if num(a) && num(b) => mk(self.to_f64(x)?, self.to_f64(y)?),
            (Kind::Json, b) | (b, Kind::Json) if num(b) => mk(self.to_f64(x)?, self.to_f64(y)?),
            (Kind::Json, Kind::Str) | (Kind::Str, Kind::Json) => {
                mk(self.to_str(x)?, self.to_str(y)?)
            }
            (Kind::Json, Kind::Bool) | (Kind::Bool, Kind::Json) => {
                mk(self.to_bool(x)?, self.to_bool(y)?)
            }
            (Kind::Json, Kind::Json) => match op {
                Eq | Ne => mk(x.e, y.e),
                _ => mk(self.to_f64(x)?, self.to_f64(y)?),
            },
            // values of different types are unequal
            _ => match op {
                Eq => lit(false),
                Ne => lit(true),
                _ => return Err(uneval(format!("cannot order {:?} against {:?}", x.k, y.k))),
            },
        };
        Ok(c(e, Kind::Bool))
    }

    fn cast(&mut self, x: &Expr, ty: Ty) -> Result<C, Error> {
        let x = self.expr(x)?;
        let u = self.u;
        Ok(match ty {
            Ty::Int => match x.k {
                Kind::Json => c(u.jint.call(vec![x.e]), Kind::Int),
                Kind::Time => c(cast(x.e, DataType::Int64), Kind::Int),
                _ => c(cast(x.e, DataType::Int64), Kind::Int),
            },
            Ty::Float64 => match x.k {
                Kind::Json => c(u.jfloat.call(vec![x.e]), Kind::Float),
                _ => c(cast(x.e, DataType::Float64), Kind::Float),
            },
            Ty::String => match x.k {
                Kind::Json => c(u.jtostr.call(vec![x.e]), Kind::Str),
                Kind::Time => c(u.ts_text.call(vec![x.e]), Kind::Str),
                Kind::Row(_) => return Err(uneval("cannot cast an event")),
                _ => c(cast(x.e, DataType::Utf8), Kind::Str),
            },
            Ty::Boolean => match x.k {
                Kind::Json => c(u.jtobool.call(vec![x.e]), Kind::Bool),
                _ => c(cast(x.e, DataType::Boolean), Kind::Bool),
            },
            Ty::DateTime => c(self.to_time(x)?, Kind::Time),
            Ty::Date => match x.k {
                Kind::Json => c(cast(u.jstr.call(vec![x.e]), DataType::Date32), Kind::Date),
                _ => c(cast(x.e, DataType::Date32), Kind::Date),
            },
            Ty::Time => match x.k {
                Kind::Json => c(
                    cast(
                        u.jstr.call(vec![x.e]),
                        DataType::Time64(TimeUnit::Nanosecond),
                    ),
                    Kind::Str,
                ),
                _ => c(
                    cast(
                        cast(x.e, DataType::Time64(TimeUnit::Nanosecond)),
                        DataType::Utf8,
                    ),
                    Kind::Str,
                ),
            },
        })
    }

    fn args(&mut self, name: &str, args: &[Expr], n: usize) -> Result<Vec<C>, Error> {
        if args.len() != n {
            return Err(uneval(format!("{name} takes {n} argument(s)")));
        }
        args.iter().map(|a| self.expr(a)).collect()
    }

    fn call(&mut self, name: &str, args: &[Expr]) -> Result<C, Error> {
        if AGGREGATES.contains(&name) {
            return self.aggregate(name, args);
        }
        let u = self.u;
        let date_part = |this: &mut Self, part: &str| -> Result<C, Error> {
            let mut a = this.args(name, args, 1)?;
            let t = this.to_time(a.remove(0))?;
            Ok(c(
                cast(f::date_part(lit(part), t), DataType::Int64),
                Kind::Int,
            ))
        };
        let float1 = |this: &mut Self, g: fn(DExpr) -> DExpr| -> Result<C, Error> {
            let mut a = this.args(name, args, 1)?;
            Ok(c(g(this.to_f64(a.remove(0))?), Kind::Float))
        };
        let str1 = |this: &mut Self, g: fn(DExpr) -> DExpr| -> Result<C, Error> {
            let mut a = this.args(name, args, 1)?;
            Ok(c(g(this.to_str(a.remove(0))?), Kind::Str))
        };
        match name {
            "IF" => {
                let mut a = self.args(name, args, 3)?;
                let (cond, x, y) = (a.remove(0), a.remove(0), a.remove(0));
                let cond = self.to_bool(cond)?;
                let (x, y, k) = if x.k == y.k {
                    let k = x.k.clone();
                    (x.e, y.e, k)
                } else if matches!(x.k, Kind::Int | Kind::Float)
                    && matches!(y.k, Kind::Int | Kind::Float)
                {
                    (self.to_f64(x)?, self.to_f64(y)?, Kind::Float)
                } else {
                    (self.to_json(x)?, self.to_json(y)?, Kind::Json)
                };
                Ok(c(when(cond, x).otherwise(y).map_err(uneval)?, k))
            }
            "LOWER" => str1(self, f::lower),
            "UPPER" => str1(self, f::upper),
            "TRIM" => str1(self, |e| f::btrim(vec![e])),
            "LTRIM" => str1(self, |e| f::ltrim(vec![e])),
            "RTRIM" => str1(self, |e| f::rtrim(vec![e])),
            "LEN" => {
                let mut a = self.args(name, args, 1)?;
                Ok(c(
                    cast(f::octet_length(self.to_str(a.remove(0))?), DataType::Int64),
                    Kind::Int,
                ))
            }
            "INSTR" => {
                let mut a = self.args(name, args, 2)?;
                let (s, t) = (self.to_str(a.remove(0))?, self.to_str(a.remove(0))?);
                Ok(c(u.instr.call(vec![s, t]), Kind::Int))
            }
            "SUBSTRING" => {
                let mut a = self.args(name, args, 3)?;
                let s = self.to_str(a.remove(0))?;
                let (st, ln) = (a.remove(0), a.remove(0));
                Ok(c(
                    u.substring.call(vec![
                        s,
                        cast(st.e, DataType::Int64),
                        cast(ln.e, DataType::Int64),
                    ]),
                    Kind::Str,
                ))
            }
            "REPLACE" => {
                let mut a = self.args(name, args, 3)?;
                let (s, x, y) = (
                    self.to_str(a.remove(0))?,
                    self.to_str(a.remove(0))?,
                    self.to_str(a.remove(0))?,
                );
                Ok(c(f::replace(s, x, y), Kind::Str))
            }
            "STARTSWITH" | "ENDSWITH" => {
                let mut a = self.args(name, args, 2)?;
                let (s, p) = (self.to_str(a.remove(0))?, self.to_str(a.remove(0))?);
                Ok(c(
                    if name == "STARTSWITH" {
                        f::starts_with(s, p)
                    } else {
                        f::ends_with(s, p)
                    },
                    Kind::Bool,
                ))
            }
            "ABS" => {
                let mut a = self.args(name, args, 1)?;
                let x = a.remove(0);
                Ok(if x.k == Kind::Int {
                    c(f::abs(x.e), Kind::Int)
                } else {
                    c(f::abs(self.to_f64(x)?), Kind::Float)
                })
            }
            "CEIL" => float1(self, f::ceil),
            "FLOOR" => float1(self, f::floor),
            "ROUND" => float1(self, |e| f::round(vec![e])),
            "SIN" => float1(self, f::sin),
            "COS" => float1(self, f::cos),
            "TAN" => float1(self, f::tan),
            "EXP" => float1(self, f::exp),
            "SQRT" => float1(self, f::sqrt),
            "POW" => {
                let mut a = self.args(name, args, 2)?;
                let (x, y) = (self.to_f64(a.remove(0))?, self.to_f64(a.remove(0))?);
                Ok(c(f::power(x, y), Kind::Float))
            }
            "RAND" => Ok(c(f::random(), Kind::Float)),
            "PI" => Ok(c(f::pi(), Kind::Float)),
            "NOW" => Ok(c(cast(f::now(), ts_type()), Kind::Time)),
            "DATE" => {
                let mut a = self.args(name, args, 1)?;
                Ok(c(
                    cast(self.to_time(a.remove(0))?, DataType::Date32),
                    Kind::Date,
                ))
            }
            "TIME" => {
                let mut a = self.args(name, args, 1)?;
                let t = self.to_time(a.remove(0))?;
                Ok(c(
                    cast(
                        cast(t, DataType::Time64(TimeUnit::Nanosecond)),
                        DataType::Utf8,
                    ),
                    Kind::Str,
                ))
            }
            "YEAR" => date_part(self, "year"),
            "MONTH" => date_part(self, "month"),
            "DAY" => date_part(self, "day"),
            "HOUR" => date_part(self, "hour"),
            "MINUTE" => date_part(self, "minute"),
            "SECOND" => date_part(self, "second"),
            "WEEK" => date_part(self, "week"),
            "WEEKDAY" => date_part(self, "dow"),
            _ => Err(uneval(format!("unknown function {name}"))),
        }
    }

    fn aggregate(&mut self, name: &str, args: &[Expr]) -> Result<C, Error> {
        if self.aggs.is_none() {
            return Err(uneval(
                "aggregates are allowed only in HAVING and PROJECT INTO",
            ));
        }
        if args.iter().any(Expr::contains_aggregate) {
            return Err(uneval("aggregates cannot be nested"));
        }
        // arguments are row expressions: compile them with field access enabled
        let saved = self.aggs.take();
        let compiled: Result<Vec<C>, Error> = args.iter().map(|a| self.expr(a)).collect();
        self.aggs = saved;
        let mut a = compiled?;
        let one = |a: &mut Vec<C>| -> Result<C, Error> {
            if a.len() != 1 {
                return Err(uneval(format!("{name} takes one argument")));
            }
            Ok(a.remove(0))
        };
        let (expr, kind, needs_rows, unique) = match name {
            "COUNT" if a.is_empty() => (agg::count(lit(1)), Kind::Int, false, None),
            "COUNT" => {
                let x = one(&mut a)?;
                (agg::count(x.e), Kind::Int, false, None)
            }
            "SUM" => {
                let x = one(&mut a)?;
                if x.k == Kind::Int {
                    (agg::sum(x.e), Kind::Int, false, None)
                } else {
                    (agg::sum(self.to_f64(x)?), Kind::Float, false, None)
                }
            }
            "AVG" => {
                let x = one(&mut a)?;
                (agg::avg(self.to_f64(x)?), Kind::Float, true, None)
            }
            "MEDIAN" => {
                let x = one(&mut a)?;
                (agg::median(self.to_f64(x)?), Kind::Float, true, None)
            }
            "STDDEV" => {
                let x = one(&mut a)?;
                (agg::stddev(self.to_f64(x)?), Kind::Float, true, None)
            }
            "VARIANCE" => {
                let x = one(&mut a)?;
                (agg::var_sample(self.to_f64(x)?), Kind::Float, true, None)
            }
            "MIN" | "MAX" => {
                let x = one(&mut a)?;
                let (e, k) = match x.k {
                    Kind::Json => (self.to_f64(x)?, Kind::Float),
                    Kind::Row(_) | Kind::Null => {
                        return Err(uneval(format!("{name} needs a value")))
                    }
                    k => (x.e, k),
                };
                (
                    if name == "MIN" {
                        agg::min(e)
                    } else {
                        agg::max(e)
                    },
                    k,
                    true,
                    None,
                )
            }
            "UNIQUE" => {
                let x = one(&mut a)?;
                if matches!(x.k, Kind::Row(_)) {
                    return Err(uneval("UNIQUE needs a value"));
                }
                let k = x.k.clone();
                (
                    agg::max(x.e.clone()),
                    k,
                    true,
                    Some(agg::count_distinct(x.e)),
                )
            }
            _ => unreachable!(),
        };
        let slots = self.aggs.as_mut().unwrap();
        let idx = slots.len();
        let name_col = format!("_a{idx}");
        let unique_col = unique.as_ref().map(|_| format!("_u{idx}"));
        slots.push(AggSlot {
            expr: expr.alias(&name_col),
            needs_rows,
            unique_check: unique_col.clone(),
        });
        if let (Some(dc), Some(col)) = (unique, unique_col) {
            slots.push(AggSlot {
                expr: dc.alias(&col),
                needs_rows: false,
                unique_check: None,
            });
        }
        Ok(c(ucol(&name_col), kind))
    }
}

// ------------------------------------------------------------------------------------------ projection layout

/// A projection leaf: where it goes in the output JSON and how to read it back.
#[derive(Clone, Debug)]
enum Seg {
    Key(String),
    Idx(usize),
}

#[derive(Clone, Debug)]
enum Leaf {
    /// value of column `col` with `kind`
    Value {
        path: Vec<Seg>,
        col: String,
        kind: Kind,
    },
    /// a whole event: its columns are `{prefix}{column}`
    Event {
        path: Vec<Seg>,
        prefix: String,
    },
    /// container placeholders keep empty objects/arrays
    EmptyObject {
        path: Vec<Seg>,
    },
    EmptyArray {
        path: Vec<Seg>,
    },
}

fn flatten(
    cmp: &mut Compiler<'_>,
    e: &Expr,
    path: Vec<Seg>,
    leaves: &mut Vec<Leaf>,
    cols: &mut Vec<DExpr>,
) -> Result<(), Error> {
    stacker::maybe_grow(parser::RED_ZONE, parser::STACK_GROWTH, || {
        flatten_inner(cmp, e, path, leaves, cols)
    })
}

fn flatten_inner(
    cmp: &mut Compiler<'_>,
    e: &Expr,
    path: Vec<Seg>,
    leaves: &mut Vec<Leaf>,
    cols: &mut Vec<DExpr>,
) -> Result<(), Error> {
    match e {
        Expr::Object(kv) => {
            if kv.is_empty() {
                leaves.push(Leaf::EmptyObject { path: path.clone() });
            }
            for (k, v) in kv {
                let mut p = path.clone();
                p.push(Seg::Key(k.clone()));
                flatten(cmp, v, p, leaves, cols)?;
            }
        }
        Expr::Array(items) => {
            if items.is_empty() {
                leaves.push(Leaf::EmptyArray { path: path.clone() });
            }
            for (i, v) in items.iter().enumerate() {
                let mut p = path.clone();
                p.push(Seg::Idx(i));
                flatten(cmp, v, p, leaves, cols)?;
            }
        }
        _ => {
            let x = cmp.expr(e)?;
            match x.k {
                Kind::Row(alias) => {
                    let prefix = format!("_p{}_", cols.len());
                    for col in EVENT_COLUMNS {
                        cols.push(qcol(&alias, col).alias(format!("{prefix}{col}")));
                    }
                    leaves.push(Leaf::Event { path, prefix });
                }
                k => {
                    let col = format!("_p{}", cols.len());
                    cols.push(x.e.alias(&col));
                    leaves.push(Leaf::Value { path, col, kind: k });
                }
            }
        }
    }
    Ok(())
}

fn cell(batch: &RecordBatch, col: &str, row: usize) -> Result<ScalarValue, Error> {
    let a = batch
        .column_by_name(col)
        .ok_or_else(|| uneval(format!("missing column {col}")))?;
    ScalarValue::try_from_array(a, row).map_err(uneval)
}

fn scalar_json(v: ScalarValue, kind: &Kind) -> Result<Value, Error> {
    if v.is_null() {
        return Ok(Value::Null);
    }
    Ok(match (kind, v) {
        (
            Kind::Json,
            ScalarValue::Utf8(Some(s))
            | ScalarValue::Utf8View(Some(s))
            | ScalarValue::LargeUtf8(Some(s)),
        ) => serde_json::from_str(&s).map_err(uneval)?,
        (
            _,
            ScalarValue::Utf8(Some(s))
            | ScalarValue::Utf8View(Some(s))
            | ScalarValue::LargeUtf8(Some(s)),
        ) => Value::String(s),
        (_, ScalarValue::Boolean(Some(b))) => Value::Bool(b),
        (_, ScalarValue::Int64(Some(i))) => Value::from(i),
        (_, ScalarValue::Int32(Some(i))) => Value::from(i),
        (_, ScalarValue::UInt64(Some(i))) => Value::from(i),
        (_, ScalarValue::Float64(Some(x))) => {
            if !x.is_finite() {
                return Err(uneval(
                    "the query produced a non-numeric result (NaN or infinity)",
                ));
            }
            serde_json::Number::from_f64(x)
                .map(Value::Number)
                .unwrap_or(Value::Null)
        }
        (_, ScalarValue::TimestampNanosecond(Some(t), _)) => {
            Value::String(vesdb_core::time::rfc3339_ns(t.max(0) as u64))
        }
        (_, ScalarValue::Date32(Some(d))) => {
            let s = vesdb_core::time::rfc3339_ns((d.max(0) as u64) * 86_400 * 1_000_000_000);
            Value::String(s[..10].to_string())
        }
        (_, other) => Value::String(other.to_string()),
    })
}

fn put(root: &mut Value, path: &[Seg], v: Value) {
    let Some((last, init)) = path.split_last() else {
        *root = v;
        return;
    };
    let mut cur = root;
    for s in init {
        cur = match s {
            Seg::Key(k) => {
                if !cur.is_object() {
                    *cur = Value::Object(Map::new());
                }
                cur.as_object_mut()
                    .unwrap()
                    .entry(k.clone())
                    .or_insert(Value::Null)
            }
            Seg::Idx(i) => {
                if !cur.is_array() {
                    *cur = Value::Array(vec![]);
                }
                let arr = cur.as_array_mut().unwrap();
                while arr.len() <= *i {
                    arr.push(Value::Null);
                }
                &mut arr[*i]
            }
        };
    }
    match last {
        Seg::Key(k) => {
            if !cur.is_object() {
                *cur = Value::Object(Map::new());
            }
            cur.as_object_mut().unwrap().insert(k.clone(), v);
        }
        Seg::Idx(i) => {
            if !cur.is_array() {
                *cur = Value::Array(vec![]);
            }
            let arr = cur.as_array_mut().unwrap();
            while arr.len() <= *i {
                arr.push(Value::Null);
            }
            arr[*i] = v;
        }
    }
}

fn event_json(batch: &RecordBatch, prefix: &str, row: usize) -> Result<Value, Error> {
    let mut m = Map::new();
    m.insert("specversion".into(), Value::String("1.0".into()));
    for col in EVENT_COLUMNS {
        let v = cell(batch, &format!("{prefix}{col}"), row)?;
        let j = match *col {
            "data" => scalar_json(v, &Kind::Json)?,
            "time" => scalar_json(v, &Kind::Time)?,
            _ => scalar_json(v, &Kind::Str)?,
        };
        if matches!(*col, "traceparent" | "tracestate") && j.is_null() {
            continue;
        }
        m.insert((*col).into(), j);
    }
    Ok(Value::Object(m))
}

fn rows_to_json(batches: &[RecordBatch], leaves: &[Leaf]) -> Result<Vec<Value>, Error> {
    let mut out = Vec::new();
    for b in batches {
        for r in 0..b.num_rows() {
            let mut root = Value::Null;
            for leaf in leaves {
                match leaf {
                    Leaf::Value { path, col, kind } => {
                        put(&mut root, path, scalar_json(cell(b, col, r)?, kind)?)
                    }
                    Leaf::Event { path, prefix } => put(&mut root, path, event_json(b, prefix, r)?),
                    Leaf::EmptyObject { path } => put(&mut root, path, Value::Object(Map::new())),
                    Leaf::EmptyArray { path } => put(&mut root, path, Value::Array(vec![])),
                }
            }
            out.push(root);
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------ planning

fn value_table(values: &[Value]) -> Result<MemTable, Error> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("_seq", DataType::UInt64, false),
        Field::new("value", DataType::Utf8, true),
    ]));
    let seq: UInt64Array = (0..values.len() as u64).collect();
    let val: StringArray = values
        .iter()
        .map(|v| (!v.is_null()).then(|| v.to_string()))
        .collect();
    let b =
        RecordBatch::try_new(schema.clone(), vec![Arc::new(seq), Arc::new(val)]).map_err(uneval)?;
    MemTable::try_new(schema, vec![vec![b]]).map_err(uneval)
}

fn int_literal(e: &Option<Expr>, what: &str, min: i64) -> Result<Option<usize>, Error> {
    match e {
        None => Ok(None),
        Some(Expr::Lit(Lit::Int(v))) if *v >= min => Ok(Some(*v as usize)),
        Some(Expr::Lit(Lit::Int(_))) => Err(Error::Malformed(format!("{what} must be ≥ {min}"))),
        Some(_) => Err(uneval(format!("{what} must be an integer literal"))),
    }
}

struct Planned {
    plan: LogicalPlan,
    leaves: Vec<Leaf>,
    /// columns that must be checked after execution: (unique-check column) and empty-set rule
    unique_cols: Vec<String>,
    empty_set_check: bool,
}

fn plan_query<'a>(
    q: &'a Query,
    cat: &'a Catalog,
    u: &'a Udfs,
    limits: &'a Limits,
    ctx: &'a SessionContext,
) -> futures::future::BoxFuture<'a, Result<Planned, Error>> {
    Box::pin(async move {
        let mut aliases = HashMap::new();
        let mut builder: Option<LogicalPlanBuilder> = None;
        let mut product: usize = 1;
        let mut seq_cols = Vec::new();
        for (alias, src) in &q.sources {
            let (table, kind, rows): (MemTable, AliasKind, usize) = match src {
                Source::Events => (
                    MemTable::try_new(events_schema(), vec![cat.events.clone()]).map_err(uneval)?,
                    AliasKind::Events,
                    cat.event_count(),
                ),
                Source::Subjects => {
                    let v: Vec<Value> = cat
                        .subjects
                        .iter()
                        .map(|s| Value::String(s.clone()))
                        .collect();
                    (value_table(&v)?, AliasKind::Value, v.len())
                }
                Source::EventTypes => {
                    let v: Vec<Value> = cat
                        .event_types
                        .iter()
                        .map(|s| Value::String(s.clone()))
                        .collect();
                    (value_table(&v)?, AliasKind::Value, v.len())
                }
                Source::Query(sub) => {
                    let v = run_query(sub, cat, u, limits, ctx).await?;
                    let n = v.len();
                    (value_table(&v)?, AliasKind::Value, n)
                }
            };
            product = product.saturating_mul(rows.max(1));
            if q.sources.len() > 1 && product > limits.max_rows {
                return Err(uneval(format!(
                    "the join would hold more than {} rows in memory",
                    limits.max_rows
                )));
            }
            aliases.insert(alias.clone(), kind);
            seq_cols.push(qcol(alias, "_seq"));
            let scan =
                LogicalPlanBuilder::scan(alias.as_str(), provider_as_source(Arc::new(table)), None)
                    .map_err(uneval)?;
            builder = Some(match builder {
                None => scan,
                Some(b) => b
                    .cross_join(scan.build().map_err(uneval)?)
                    .map_err(uneval)?,
            });
        }
        let mut b = builder.expect("at least one source");
        let mut cmp = Compiler {
            u,
            aliases,
            aggs: None,
        };

        if let Some(w) = &q.filter {
            if w.contains_aggregate() {
                return Err(uneval("aggregates are not allowed in WHERE"));
            }
            let x = cmp.expr(w)?;
            let pred = u.strict_bool.call(vec![cmp.to_bool(x)?]);
            b = b.filter(pred).map_err(uneval)?;
        }

        // _ord: position of each row after ORDER BY (ties broken by source order)
        let mut sorts: Vec<SortExpr> = Vec::new();
        for k in &q.order {
            if k.expr.contains_aggregate() {
                return Err(uneval("aggregates are not allowed in ORDER BY"));
            }
            let x = cmp.expr(&k.expr)?;
            let e = match x.k {
                Kind::Json => u.strict_f64.call(vec![u.jnum.call(vec![x.e])]),
                Kind::Row(_) | Kind::Null => return Err(uneval("ORDER BY needs a value")),
                _ => x.e,
            };
            sorts.push(e.sort(!k.desc, false));
        }
        for s in &seq_cols {
            sorts.push(s.clone().sort(true, false));
        }
        let ord = row_number()
            .order_by(sorts)
            .build()
            .map_err(uneval)?
            .alias("_ord");
        b = b.window(vec![ord]).map_err(uneval)?;

        let aggregated = q.group.is_some()
            || q.project.contains_aggregate()
            || q.having.as_ref().is_some_and(Expr::contains_aggregate);
        let mut unique_cols = Vec::new();
        let mut empty_set_check = false;
        let mut leaves = Vec::new();
        let mut proj_cols = Vec::new();
        if aggregated {
            let mut groups = Vec::new();
            if let Some(g) = &q.group {
                if g.contains_aggregate() {
                    return Err(uneval("aggregates are not allowed in GROUP BY"));
                }
                let x = cmp.expr(g)?;
                let e = match x.k {
                    Kind::Row(_) => return Err(uneval("cannot GROUP BY a whole event")),
                    _ => x.e,
                };
                groups.push(e.alias("_g"));
            }
            cmp.aggs = Some(Vec::new());
            let having = match &q.having {
                Some(h) => {
                    let x = cmp.expr(h)?;
                    Some(u.strict_bool.call(vec![cmp.to_bool(x)?]))
                }
                None => None,
            };
            flatten(&mut cmp, &q.project, vec![], &mut leaves, &mut proj_cols)?;
            let slots = cmp.aggs.take().unwrap();
            let mut aggs: Vec<DExpr> = vec![
                agg::min(ucol("_ord")).alias("_ord"),
                agg::count(lit(1)).alias("_n"),
            ];
            for s in &slots {
                aggs.push(s.expr.clone());
                if let Some(col) = &s.unique_check {
                    unique_cols.push(col.clone());
                }
                empty_set_check |= s.needs_rows && q.group.is_none();
            }
            b = b.aggregate(groups, aggs).map_err(uneval)?;
            if let Some(h) = having {
                b = b.filter(h).map_err(uneval)?;
            }
        } else {
            flatten(&mut cmp, &q.project, vec![], &mut leaves, &mut proj_cols)?;
        }
        let mut cols = proj_cols.clone();
        cols.push(ucol("_ord"));
        for uc in &unique_cols {
            cols.push(ucol(uc));
        }
        if empty_set_check {
            cols.push(ucol("_n"));
        }
        b = b.project(cols).map_err(uneval)?;

        if q.distinct {
            let group: Vec<DExpr> = proj_cols
                .iter()
                .map(|e| match e {
                    DExpr::Alias(a) => ucol(&a.name),
                    other => other.clone(),
                })
                .collect();
            b = b
                .aggregate(group, vec![agg::min(ucol("_ord")).alias("_ord")])
                .map_err(uneval)?;
        }
        b = b
            .sort(vec![ucol("_ord").sort(true, false)])
            .map_err(uneval)?;
        let skip = int_literal(&q.skip, "SKIP", 0)?.unwrap_or(0);
        let top = int_literal(&q.top, "TOP", 1)?;
        if skip > 0 || top.is_some() {
            b = b.limit(skip, top).map_err(uneval)?;
        }
        Ok(Planned {
            plan: b.build().map_err(uneval)?,
            leaves,
            unique_cols,
            empty_set_check,
        })
    })
}

fn run_query<'a>(
    q: &'a Query,
    cat: &'a Catalog,
    u: &'a Udfs,
    limits: &'a Limits,
    ctx: &'a SessionContext,
) -> futures::future::BoxFuture<'a, Result<Vec<Value>, Error>> {
    Box::pin(async move {
        let p = plan_query(q, cat, u, limits, ctx).await?;
        let df = ctx.execute_logical_plan(p.plan).await.map_err(uneval)?;
        let batches = df.collect().await.map_err(|e| uneval(strip(e)))?;
        for b in &batches {
            for col in &p.unique_cols {
                for r in 0..b.num_rows() {
                    if let ScalarValue::Int64(Some(n)) = cell(b, col, r)? {
                        if n > 1 {
                            return Err(uneval("UNIQUE saw more than one distinct value"));
                        }
                    }
                }
            }
            if p.empty_set_check {
                for r in 0..b.num_rows() {
                    if let ScalarValue::Int64(Some(0)) = cell(b, "_n", r)? {
                        return Err(uneval("AVG, MIN, MAX, MEDIAN, STDDEV, VARIANCE and UNIQUE fail over an empty set"));
                    }
                }
            }
        }
        let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
        if rows > limits.max_rows {
            return Err(uneval(format!("more than {} result rows", limits.max_rows)));
        }
        rows_to_json(&batches, &p.leaves)
    })
}

fn strip(e: datafusion::error::DataFusionError) -> String {
    let s = e.to_string();
    s.rsplit("Execution error: ")
        .next()
        .unwrap_or(&s)
        .to_string()
}

fn session(limits: &Limits) -> Result<SessionContext, Error> {
    let rt = RuntimeEnvBuilder::new()
        .with_memory_limit(limits.memory_bytes, 1.0)
        .build_arc()
        .map_err(uneval)?;
    let cfg = datafusion::prelude::SessionConfig::new()
        .with_target_partitions(2)
        .with_batch_size(8192);
    Ok(SessionContext::new_with_config_rt(cfg, rt))
}

/// EventQL runs on its own runtime whose threads have large stacks: legal queries can nest 256
/// levels deep and hold 10,000 operands, and parts of DataFusion's planning and evaluation recurse
/// per level. The stack is a virtual reservation; memory is committed only as it is used.
fn eql_runtime() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("vesdb-eventql")
            .thread_stack_size(256 * 1024 * 1024)
            .enable_all()
            .build()
            .expect("EventQL runtime")
    })
}

/// Run `f` on the EventQL runtime. The timeout is applied to the caller's wait, not inside the
/// task: a long synchronous planning step cannot hold the caller (or the write lock during a
/// precondition) past `timeout`. A timed-out task is aborted at its next await point and can occupy
/// at most one of the two EventQL threads meanwhile.
async fn on_eql_runtime<T: Send + 'static>(
    timeout: Duration,
    f: impl std::future::Future<Output = Result<T, Error>> + Send + 'static,
) -> Result<T, Error> {
    let handle = eql_runtime().spawn(f);
    let abort = handle.abort_handle();
    match tokio::time::timeout(timeout, handle).await {
        Ok(joined) => joined.map_err(|e| uneval(format!("query task failed: {e}")))?,
        Err(_) => {
            abort.abort();
            Err(uneval(format!(
                "the query did not finish within {timeout:?}"
            )))
        }
    }
}

/// Run an EventQL query against `cat`, returning one JSON value per result row.
pub async fn run(query: &str, cat: &Catalog, limits: &Limits) -> Result<Vec<Value>, Error> {
    let (query, cat, limits) = (query.to_string(), cat.clone(), limits.clone());
    let timeout = limits.timeout;
    on_eql_runtime(timeout, async move {
        let q = parse(&query)?;
        let ctx = session(&limits)?;
        let u = Udfs::new();
        run_query(&q, &cat, &u, &limits, &ctx).await
    })
    .await
}

/// `isEventQlQueryTrue`: the query must return exactly one row whose value is a boolean.
pub async fn eval_bool(query: &str, cat: &Catalog, limits: &Limits) -> Result<bool, Error> {
    match run(query, cat, limits).await?.as_slice() {
        [Value::Bool(b)] => Ok(*b),
        _ => Err(Error::NotBoolean),
    }
}

/// The DataFusion logical plan for a query (subqueries are executed while planning).
pub async fn explain(query: &str, cat: &Catalog) -> Result<String, Error> {
    let (query, cat) = (query.to_string(), cat.clone());
    on_eql_runtime(Limits::default().timeout, async move {
        let q = parse(&query)?;
        let limits = Limits::default();
        let ctx = session(&limits)?;
        let u = Udfs::new();
        let p = plan_query(&q, &cat, &u, &limits, &ctx).await?;
        let text = p.plan.display_indent().to_string();
        Ok(text)
    })
    .await
}

#[cfg(test)]
mod tests;
