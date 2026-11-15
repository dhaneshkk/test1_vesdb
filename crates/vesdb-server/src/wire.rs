//! Wire formats: CloudEvents as EventSourcingDB v2 returns them, NDJSON envelopes, errors.

use serde::Serialize;
use serde_json::value::RawValue;
use vesdb_core::time::rfc3339_ns;
use vesdb_store::StoredEvent;

pub const ERROR_BASE: &str = "https://vesdb.dev/errors/";

#[derive(Serialize)]
struct WireEvent<'a> {
    specversion: &'static str,
    id: String,
    time: String,
    source: &'a str,
    subject: &'a str,
    #[serde(rename = "type")]
    ty: &'a str,
    datacontenttype: &'static str,
    data: &'a RawValue,
    predecessorhash: &'a str,
    hash: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    traceparent: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tracestate: Option<&'a str>,
    signature: Option<String>,
    /// vesdb extension: hex Merkle leaf hash (CloudEvents extension attribute).
    vesdbleaf: String,
    /// vesdb extension: payload erased by redaction.
    vesdbredacted: bool,
}

/// Serialize a stored event to its CloudEvent JSON. `sign` produces the compat read-time
/// signature over the `hash` text.
pub fn event_json(ev: &StoredEvent, sign: Option<&dyn Fn(&[u8]) -> [u8; 64]>) -> String {
    let m = &ev.meta;
    let null = RawValue::from_string("null".into()).unwrap();
    let data_raw;
    let data: &RawValue = match &ev.payload {
        Some((_, d)) => {
            data_raw = RawValue::from_string(d.clone()).unwrap_or(null.clone());
            &data_raw
        }
        None => &null,
    };
    let w = WireEvent {
        specversion: "1.0",
        id: m.id.to_string(),
        time: rfc3339_ns(m.time_ns),
        source: &m.source,
        subject: &m.subject,
        ty: &m.ty,
        datacontenttype: "application/json",
        data,
        predecessorhash: &m.predecessorhash,
        hash: &m.hash,
        traceparent: m.traceparent.as_deref(),
        tracestate: m.tracestate.as_deref(),
        signature: sign.map(|f| format!("esdb:signature:v1:{}", hex::encode(f(m.hash.as_bytes())))),
        vesdbleaf: hex::encode(m.leaf()),
        vesdbredacted: ev.payload.is_none(),
    };
    serde_json::to_string(&w).expect("event serializes")
}

/// `{"type":<ty>,"data":<data>}` + newline.
pub fn item(ty: &str, data_json: &str) -> String {
    format!("{{\"type\":\"{ty}\",\"data\":{data_json}}}\n")
}

pub fn end() -> String {
    item("end", "{}")
}

pub fn heartbeat() -> String {
    item("heartbeat", "{}")
}

pub fn error(slug: &str, description: &str, details: serde_json::Value) -> String {
    let d = serde_json::json!({"code": format!("{ERROR_BASE}{slug}"), "description": description, "details": details});
    item("error", &d.to_string())
}

/// Management event (ping, token verification) envelope.
pub fn management_event(ty: &str, subject: &str, source: &str, data: serde_json::Value) -> String {
    let now = vesdb_core::time::now_ns();
    let ev = serde_json::json!({
        "specversion": "1.0",
        "id": now.to_string(),
        "time": rfc3339_ns(now),
        "source": source,
        "subject": subject,
        "type": ty,
        "datacontenttype": "application/json",
        "data": data,
    });
    serde_json::json!({"type": "event", "data": ev}).to_string()
}
