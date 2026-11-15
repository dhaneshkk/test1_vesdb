//! Scalar UDFs that give DataFusion EventQL's dynamic JSON semantics.
//!
//! JSON values travel as canonical JSON text (`Utf8`). `jget` re-serializes the selected value
//! with serde_json (sorted object keys, compact), so equal JSON values have equal text. JSON
//! `null` and missing fields both become SQL NULL, which is EventQL's NULL.

use datafusion::arrow::array::{
    Array, ArrayRef, BooleanArray, Float64Array, Int64Array, StringArray, TimestampNanosecondArray,
};
use datafusion::arrow::datatypes::{DataType, TimeUnit};
use datafusion::common::{DataFusionError, Result};
use datafusion::logical_expr::{create_udf, ColumnarValue, ScalarUDF, Volatility};
use serde_json::Value;
use std::sync::Arc;

fn strings(a: &ArrayRef) -> Result<StringArray> {
    let a = datafusion::arrow::compute::cast(a, &DataType::Utf8)?;
    Ok(a.as_any()
        .downcast_ref::<StringArray>()
        .expect("utf8")
        .clone())
}

fn parse(s: &str) -> Option<Value> {
    match serde_json::from_str::<Value>(s) {
        Ok(Value::Null) | Err(_) => None,
        Ok(v) => Some(v),
    }
}

fn unary_json<O, F>(name: &str, out: DataType, f: F) -> Arc<ScalarUDF>
where
    F: Fn(&Value) -> Option<O> + Send + Sync + 'static,
    O: Into<Scalar>,
{
    let out2 = out.clone();
    Arc::new(create_udf(
        name,
        vec![DataType::Utf8],
        out,
        Volatility::Immutable,
        Arc::new(move |args: &[ColumnarValue]| {
            let a = ColumnarValue::values_to_arrays(args)?;
            let s = strings(&a[0])?;
            let vals: Vec<Option<Scalar>> = (0..s.len())
                .map(|i| {
                    if s.is_null(i) {
                        None
                    } else {
                        parse(s.value(i)).and_then(|v| f(&v)).map(Into::into)
                    }
                })
                .collect();
            Ok(ColumnarValue::Array(build(&out2, vals)))
        }),
    ))
}

pub enum Scalar {
    F(f64),
    I(i64),
    S(String),
    B(bool),
}
impl From<f64> for Scalar {
    fn from(v: f64) -> Self {
        Scalar::F(v)
    }
}
impl From<i64> for Scalar {
    fn from(v: i64) -> Self {
        Scalar::I(v)
    }
}
impl From<String> for Scalar {
    fn from(v: String) -> Self {
        Scalar::S(v)
    }
}
impl From<bool> for Scalar {
    fn from(v: bool) -> Self {
        Scalar::B(v)
    }
}

fn build(dt: &DataType, vals: Vec<Option<Scalar>>) -> ArrayRef {
    match dt {
        DataType::Float64 => Arc::new(
            vals.into_iter()
                .map(|v| match v {
                    Some(Scalar::F(x)) => Some(x),
                    _ => None,
                })
                .collect::<Float64Array>(),
        ),
        DataType::Int64 => Arc::new(
            vals.into_iter()
                .map(|v| match v {
                    Some(Scalar::I(x)) => Some(x),
                    _ => None,
                })
                .collect::<Int64Array>(),
        ),
        DataType::Boolean => Arc::new(
            vals.into_iter()
                .map(|v| match v {
                    Some(Scalar::B(x)) => Some(x),
                    _ => None,
                })
                .collect::<BooleanArray>(),
        ),
        _ => Arc::new(
            vals.into_iter()
                .map(|v| match v {
                    Some(Scalar::S(x)) => Some(x),
                    _ => None,
                })
                .collect::<StringArray>(),
        ),
    }
}

/// `jget(json, path)` where `path` is a JSON array of keys and indexes (negative = from end).
pub fn jget() -> Arc<ScalarUDF> {
    Arc::new(create_udf(
        "jget",
        vec![DataType::Utf8, DataType::Utf8],
        DataType::Utf8,
        Volatility::Immutable,
        Arc::new(|args: &[ColumnarValue]| {
            let a = ColumnarValue::values_to_arrays(args)?;
            let s = strings(&a[0])?;
            let p = strings(&a[1])?;
            let path: Vec<Value> = if p.is_empty() {
                vec![]
            } else {
                serde_json::from_str(p.value(0))
                    .map_err(|e| DataFusionError::Execution(e.to_string()))?
            };
            let out: StringArray = (0..s.len())
                .map(|i| {
                    if s.is_null(i) {
                        return None;
                    }
                    let mut v = parse(s.value(i))?;
                    for seg in &path {
                        v = match (seg, v) {
                            (Value::String(k), Value::Object(mut m)) => m.remove(k)?,
                            (Value::Number(n), Value::Array(mut arr)) => {
                                let i = n.as_i64()?;
                                let idx = if i < 0 { arr.len() as i64 + i } else { i };
                                if idx < 0 || idx as usize >= arr.len() {
                                    return None;
                                }
                                arr.swap_remove(idx as usize)
                            }
                            _ => return None,
                        };
                    }
                    if v.is_null() {
                        None
                    } else {
                        Some(v.to_string())
                    }
                })
                .collect();
            Ok(ColumnarValue::Array(Arc::new(out)))
        }),
    ))
}

pub fn jnum() -> Arc<ScalarUDF> {
    unary_json("jnum", DataType::Float64, |v| v.as_f64())
}
pub fn jint() -> Arc<ScalarUDF> {
    unary_json("jint", DataType::Int64, |v| match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f.trunc() as i64)),
        Value::String(s) => s.trim().parse().ok(),
        Value::Bool(b) => Some(*b as i64),
        _ => None,
    })
}
pub fn jfloat() -> Arc<ScalarUDF> {
    unary_json("jfloat", DataType::Float64, |v| match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    })
}
/// strict: only JSON strings
pub fn jstr() -> Arc<ScalarUDF> {
    unary_json("jstr", DataType::Utf8, |v| v.as_str().map(str::to_string))
}
/// `AS STRING`: string content, or the JSON text of any other value
pub fn jtostr() -> Arc<ScalarUDF> {
    unary_json("jtostr", DataType::Utf8, |v| {
        Some(
            v.as_str()
                .map(str::to_string)
                .unwrap_or_else(|| v.to_string()),
        )
    })
}
pub fn jbool() -> Arc<ScalarUDF> {
    unary_json("jbool", DataType::Boolean, |v| v.as_bool())
}
pub fn jtobool() -> Arc<ScalarUDF> {
    unary_json("jtobool", DataType::Boolean, |v| match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_f64().map(|f| f != 0.0),
        _ => None,
    })
}

/// Quote a string as a JSON string literal.
pub fn jquote() -> Arc<ScalarUDF> {
    Arc::new(create_udf(
        "jquote",
        vec![DataType::Utf8],
        DataType::Utf8,
        Volatility::Immutable,
        Arc::new(|args: &[ColumnarValue]| {
            let a = ColumnarValue::values_to_arrays(args)?;
            let s = strings(&a[0])?;
            let out: StringArray = (0..s.len())
                .map(|i| (!s.is_null(i)).then(|| Value::String(s.value(i).into()).to_string()))
                .collect();
            Ok(ColumnarValue::Array(Arc::new(out)))
        }),
    ))
}

/// Timestamp(ns, UTC) -> RFC 3339 with nanoseconds.
pub fn ts_text() -> Arc<ScalarUDF> {
    Arc::new(create_udf(
        "ts_text",
        vec![DataType::Timestamp(
            TimeUnit::Nanosecond,
            Some("UTC".into()),
        )],
        DataType::Utf8,
        Volatility::Immutable,
        Arc::new(|args: &[ColumnarValue]| {
            let a = ColumnarValue::values_to_arrays(args)?;
            let t = a[0]
                .as_any()
                .downcast_ref::<TimestampNanosecondArray>()
                .ok_or_else(|| DataFusionError::Execution("ts_text expects a timestamp".into()))?;
            let out: StringArray = (0..t.len())
                .map(|i| {
                    (!t.is_null(i)).then(|| vesdb_core::time::rfc3339_ns(t.value(i).max(0) as u64))
                })
                .collect();
            Ok(ColumnarValue::Array(Arc::new(out)))
        }),
    ))
}

/// Fails the query on NULL: EventQL's WHERE/HAVING need a strict boolean.
pub fn strict_bool() -> Arc<ScalarUDF> {
    Arc::new(create_udf(
        "strict_bool",
        vec![DataType::Boolean],
        DataType::Boolean,
        Volatility::Immutable,
        Arc::new(|args: &[ColumnarValue]| {
            let a = ColumnarValue::values_to_arrays(args)?;
            if a[0].null_count() > 0 {
                return Err(DataFusionError::Execution(
                    "condition evaluated to NULL (guard optional fields with != NULL)".into(),
                ));
            }
            Ok(ColumnarValue::Array(a[0].clone()))
        }),
    ))
}

/// Fails on NULL: ORDER BY and arithmetic inputs must not be NULL.
pub fn strict_f64() -> Arc<ScalarUDF> {
    Arc::new(create_udf(
        "strict_f64",
        vec![DataType::Float64],
        DataType::Float64,
        Volatility::Immutable,
        Arc::new(|args: &[ColumnarValue]| {
            let a = ColumnarValue::values_to_arrays(args)?;
            if a[0].null_count() > 0 {
                return Err(DataFusionError::Execution(
                    "ORDER BY on NULL or a non-number".into(),
                ));
            }
            Ok(ColumnarValue::Array(a[0].clone()))
        }),
    ))
}

/// INSTR(s, sub): 0-based byte offset of `sub` in `s`, or -1.
pub fn instr() -> Arc<ScalarUDF> {
    Arc::new(create_udf(
        "instr_bytes",
        vec![DataType::Utf8, DataType::Utf8],
        DataType::Int64,
        Volatility::Immutable,
        Arc::new(|args: &[ColumnarValue]| {
            let a = ColumnarValue::values_to_arrays(args)?;
            let (s, t) = (strings(&a[0])?, strings(&a[1])?);
            let out: Int64Array = (0..s.len())
                .map(|i| {
                    (!s.is_null(i) && !t.is_null(i))
                        .then(|| s.value(i).find(t.value(i)).map_or(-1, |p| p as i64))
                })
                .collect();
            Ok(ColumnarValue::Array(Arc::new(out)))
        }),
    ))
}

/// SUBSTRING(s, start, len): byte offsets, clamped; invalid UTF-8 boundaries fail the query.
pub fn substring() -> Arc<ScalarUDF> {
    Arc::new(create_udf(
        "substring_bytes",
        vec![DataType::Utf8, DataType::Int64, DataType::Int64],
        DataType::Utf8,
        Volatility::Immutable,
        Arc::new(|args: &[ColumnarValue]| {
            let a = ColumnarValue::values_to_arrays(args)?;
            let s = strings(&a[0])?;
            let st = datafusion::arrow::compute::cast(&a[1], &DataType::Int64)?;
            let ln = datafusion::arrow::compute::cast(&a[2], &DataType::Int64)?;
            let st = st.as_any().downcast_ref::<Int64Array>().unwrap();
            let ln = ln.as_any().downcast_ref::<Int64Array>().unwrap();
            let mut out = Vec::with_capacity(s.len());
            for i in 0..s.len() {
                if s.is_null(i) || st.is_null(i) || ln.is_null(i) {
                    out.push(None);
                    continue;
                }
                let v = s.value(i);
                let b = (st.value(i).max(0) as usize).min(v.len());
                let e = (b + ln.value(i).max(0) as usize).min(v.len());
                let piece = v.get(b..e).ok_or_else(|| {
                    DataFusionError::Execution("SUBSTRING splits a UTF-8 character".into())
                })?;
                out.push(Some(piece.to_string()));
            }
            Ok(ColumnarValue::Array(Arc::new(StringArray::from(out))))
        }),
    ))
}
