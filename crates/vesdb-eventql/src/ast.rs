//! EventQL abstract syntax tree.

#[derive(Clone, Debug, PartialEq)]
pub enum Lit {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    Null,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PathSeg {
    /// `.name` or `["name"]`
    Key(String),
    /// `[i]`, negative counts from the end
    Index(i64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    Or,
    Xor,
    And,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnOp {
    Not,
    Neg,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ty {
    String,
    Int,
    Float64,
    Boolean,
    Date,
    Time,
    DateTime,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    Lit(Lit),
    /// `alias` followed by zero or more path segments
    Path {
        alias: String,
        path: Vec<PathSeg>,
    },
    Unary(UnOp, Box<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
    Cast(Box<Expr>, Ty),
    /// function name upper-cased
    Call(String, Vec<Expr>),
    Object(Vec<(String, Expr)>),
    Array(Vec<Expr>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Source {
    Events,
    Subjects,
    EventTypes,
    Query(Box<Query>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct OrderKey {
    pub expr: Expr,
    pub desc: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Query {
    pub sources: Vec<(String, Source)>,
    pub filter: Option<Expr>,
    pub order: Vec<OrderKey>,
    pub group: Option<Expr>,
    pub having: Option<Expr>,
    pub skip: Option<Expr>,
    pub top: Option<Expr>,
    pub distinct: bool,
    pub project: Expr,
}

pub const AGGREGATES: &[&str] = &[
    "COUNT", "SUM", "AVG", "MIN", "MAX", "MEDIAN", "STDDEV", "VARIANCE", "UNIQUE",
];

impl Expr {
    pub fn contains_aggregate(&self) -> bool {
        stacker::maybe_grow(256 * 1024, 4 * 1024 * 1024, || {
            self.contains_aggregate_inner()
        })
    }

    fn contains_aggregate_inner(&self) -> bool {
        match self {
            Expr::Call(n, args) => {
                AGGREGATES.contains(&n.as_str()) || args.iter().any(Expr::contains_aggregate)
            }
            Expr::Unary(_, e) | Expr::Cast(e, _) => e.contains_aggregate(),
            Expr::Binary(_, a, b) => a.contains_aggregate() || b.contains_aggregate(),
            Expr::Object(kv) => kv.iter().any(|(_, e)| e.contains_aggregate()),
            Expr::Array(v) => v.iter().any(Expr::contains_aggregate),
            Expr::Lit(_) | Expr::Path { .. } => false,
        }
    }
}
