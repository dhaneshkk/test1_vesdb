//! vesdb HTTP server.
//!
//! * `/api/v2/...` – EventSourcingDB 1.3 v2-compatible routes (write, read, observe, subjects,
//!   event types, verify-store, audit-history, read-only mode, ping, health, verify-token).
//! * `/api/v2/tlog/...` and `/tlog/...` – transparency-log routes (checkpoints, receipts,
//!   consistency proofs, evidence bundles) and `/api/v2/management/redact-events`.
//! * `/api/v2/ts/...` – time series: points in Gorilla chunks, each sealed chunk one log event
//!   (see `vesdb-ts`), with raw and downsampled queries, retention and per-reading proofs.
//!
//! One store, one writer: every write runs on a blocking thread under the store mutex, fsyncs,
//! issues its receipt and only then answers.

#![allow(clippy::result_large_err, clippy::type_complexity)]

pub mod ha;
pub mod migrate;
pub mod ts;
pub mod wire;

use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get},
    Router,
};
use futures::stream::{self, StreamExt};
use serde::Deserialize;
use serde_json::{json, value::RawValue, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;
use vesdb_core::{
    crypto::{HybridKey, PublicKey},
    time::now_ns,
    witness::{AddCheckpoint, WitnessError},
};
use vesdb_store::{
    Bound, Candidate, FromLatest, Order, Precondition, ReadOptions, Store, StoreError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    Read,
    Write,
    Audit,
    Redact,
    Admin,
}

impl Scope {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "read" => Scope::Read,
            "write" => Scope::Write,
            "audit" => Scope::Audit,
            "redact" => Scope::Redact,
            "admin" => Scope::Admin,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug)]
pub struct WitnessConfig {
    pub url: String,
    pub key: PublicKey,
}

pub struct ServerConfig {
    /// token secret -> scopes
    pub tokens: HashMap<String, BTreeSet<Scope>>,
    pub witnesses: Vec<WitnessConfig>,
    /// cosignatures required for a checkpoint to count as published
    pub quorum: usize,
    pub checkpoint_interval: Duration,
    pub checkpoint_max_events: u64,
    /// Answer with `Server: EventSourcingDB/1.3 (compatible; vesdb/x)` so the official SDKs accept us.
    pub compat_server_header: bool,
    /// Add the EventSourcingDB-compatible read-time Ed25519 `signature` to events.
    pub compat_signatures: bool,
    /// Key used for compat signatures (same seed as the store key).
    pub compat_key: Option<HybridKey>,
    /// Enable the time-series engine.
    pub ts: Option<vesdb_ts::TsConfig>,
    /// High availability on a shared bucket: role settings and a handle on the same bucket the
    /// store uses (for `writer.json`).
    pub ha: Option<(ha::HaConfig, vesdb_store::ObjectBackend)>,
}

/// Columnar copy of the log for EventQL. Append-only like the log; rebuilt after a redaction.
#[derive(Default)]
pub struct EqlCache {
    batches: Vec<vesdb_eventql::arrow::array::RecordBatch>,
    covered: u64,
    epoch: u64,
    types: BTreeSet<String>,
}

pub struct App {
    pub store: Mutex<Store>,
    pub eql: Mutex<EqlCache>,
    pub cfg: ServerConfig,
    pub new_events: broadcast::Sender<u64>,
    pub witness_sizes: Mutex<HashMap<String, u64>>,
    pub http: reqwest::Client,
    pub origin: String,
    pub log_key: PublicKey,
    pub ts: Option<Mutex<vesdb_ts::TsEngine>>,
    pub ha: Option<ha::Ha>,
}

pub type Shared = Arc<App>;

pub fn new_app(store: Store, cfg: ServerConfig) -> Shared {
    try_new_app(store, cfg).expect("open time-series engine")
}

/// Like [`new_app`], reporting a time-series recovery failure instead of panicking.
pub fn try_new_app(store: Store, mut cfg: ServerConfig) -> Result<Shared, String> {
    let ts = match cfg.ts.take() {
        Some(c) => Some(Mutex::new(ts::open_engine(c, &store)?)),
        None => None,
    };
    let ha = cfg.ha.take().map(|(c, b)| ha::Ha::new(c, b));
    let (tx, _) = broadcast::channel(4096);
    Ok(Arc::new(App {
        ts,
        ha,
        origin: store.origin().to_string(),
        log_key: store.public_key(),
        store: Mutex::new(store),
        eql: Mutex::new(EqlCache::default()),
        cfg,
        new_events: tx,
        witness_sizes: Mutex::new(HashMap::new()),
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("http client"),
    }))
}

// ------------------------------------------------------------------------------------ plumbing

fn ndjson(body: String) -> Response {
    ([(header::CONTENT_TYPE, "application/x-ndjson")], body).into_response()
}

fn status(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, msg.into()).into_response()
}

fn authorize(app: &App, headers: &HeaderMap, need: Scope) -> Result<(), Response> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, t)| t.trim());
    let Some(scopes) = token.and_then(|t| app.cfg.tokens.get(t)) else {
        let mut r = status(StatusCode::UNAUTHORIZED, "API token missing or invalid");
        r.headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        return Err(r);
    };
    if scopes.contains(&Scope::Admin) || scopes.contains(&need) {
        Ok(())
    } else {
        Err(status(
            StatusCode::FORBIDDEN,
            format!("token lacks scope {need:?}"),
        ))
    }
}

fn parse_body<T: for<'de> Deserialize<'de>>(
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<T, Response> {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !ct.starts_with("application/json") {
        return Err(status(
            StatusCode::BAD_REQUEST,
            "content-type must be application/json",
        ));
    }
    serde_json::from_slice(body)
        .map_err(|e| status(StatusCode::BAD_REQUEST, format!("invalid body: {e}")))
}

fn is_query(m: &Method) -> bool {
    m.as_str() == "QUERY" || m == Method::POST
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f)
        .await
        .expect("blocking task panicked")
}

/// A write this server cannot take now (lost the writer race, or a standby): 503 and
/// `Retry-After`, so clients and load balancers retry, with the same idempotency key.
fn retryable(e: &StoreError) -> Response {
    let mut r = (StatusCode::SERVICE_UNAVAILABLE, store_error(e)).into_response();
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    r
}

fn store_error(e: &StoreError) -> String {
    let details = match e {
        StoreError::PreconditionViolated { index } => json!({ "precondition": index }),
        StoreError::Input { index, .. } => json!({ "event": index }),
        _ => json!({}),
    };
    wire::error(&e.slug(), &e.to_string(), details) + &wire::end()
}

fn sign_fn(app: &App) -> Option<impl Fn(&[u8]) -> [u8; 64] + '_> {
    if app.cfg.compat_signatures {
        app.cfg
            .compat_key
            .as_ref()
            .map(|k| move |m: &[u8]| k.sign_ed25519(m))
    } else {
        None
    }
}

fn event_line(app: &App, ev: &vesdb_store::StoredEvent) -> String {
    let s = sign_fn(app);
    let f: Option<&dyn Fn(&[u8]) -> [u8; 64]> = s.as_ref().map(|f| f as &dyn Fn(&[u8]) -> [u8; 64]);
    wire::item("event", &wire::event_json(ev, f))
}

// ------------------------------------------------------------------------------------ EventQL

/// Snapshot of the log as an EventQL catalog. Call with the store lock held.
fn catalog(app: &App, s: &Store) -> Result<vesdb_eventql::Catalog, StoreError> {
    let mut c = app.eql.lock().unwrap();
    if c.epoch != s.redaction_epoch() {
        *c = EqlCache {
            epoch: s.redaction_epoch(),
            ..Default::default()
        };
    }
    let n = s.len();
    if c.covered < n {
        let mut owned = Vec::with_capacity((n - c.covered) as usize);
        for id in c.covered..n {
            owned.push(s.event(id)?);
        }
        let rows: Vec<vesdb_eventql::EventRow> = owned
            .iter()
            .map(|e| vesdb_eventql::EventRow {
                id: e.meta.id,
                time_ns: e.meta.time_ns,
                source: &e.meta.source,
                subject: &e.meta.subject,
                ty: &e.meta.ty,
                data: e.payload.as_ref().map(|(_, d)| d.as_str()),
                predecessorhash: &e.meta.predecessorhash,
                hash: &e.meta.hash,
                traceparent: e.meta.traceparent.as_deref(),
                tracestate: e.meta.tracestate.as_deref(),
            })
            .collect();
        for e in &owned {
            c.types.insert(e.meta.ty.clone());
        }
        c.batches.push(vesdb_eventql::events_batch(&rows));
        c.covered = n;
        if c.batches.len() > 64 {
            let merged = vesdb_eventql::arrow::compute::concat_batches(
                &vesdb_eventql::events_schema(),
                &c.batches,
            )
            .map_err(|e| StoreError::Invalid(e.to_string()))?;
            c.batches = vec![merged];
        }
    }
    Ok(vesdb_eventql::Catalog {
        events: c.batches.clone(),
        subjects: s.subjects().cloned().collect(),
        event_types: c.types.iter().cloned().collect(),
    })
}

fn eql_error(e: &vesdb_eventql::Error) -> String {
    wire::error(e.slug(), &e.to_string(), json!({})) + &wire::end()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryBody {
    query: String,
}

async fn run_eventql_query(
    State(app): State<Shared>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_query(&method) {
        return status(StatusCode::METHOD_NOT_ALLOWED, "use QUERY");
    }
    if let Err(r) = authorize(&app, &headers, Scope::Read) {
        return r;
    }
    let qb: QueryBody = match parse_body(&headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    if qb.query.trim().is_empty() {
        return ndjson(wire::error("query-missing", "query is required", json!({})) + &wire::end());
    }
    let app2 = app.clone();
    let cat = match blocking(move || {
        let s = app2.store.lock().unwrap();
        catalog(&app2, &s)
    })
    .await
    {
        Ok(c) => c,
        Err(e) => return ndjson(store_error(&e)),
    };
    match vesdb_eventql::run(&qb.query, &cat, &vesdb_eventql::Limits::default()).await {
        Ok(rows) => {
            let mut out = String::new();
            for v in rows {
                out += &wire::item("row", &json!({ "value": v }).to_string());
            }
            ndjson(out + &wire::end())
        }
        Err(e) => ndjson(eql_error(&e)),
    }
}

// ------------------------------------------------------------------------------------ router

pub fn router(app: Shared) -> Router {
    let compat = app.cfg.compat_server_header;
    Router::new()
        .route("/api/v2/system/ping", get(ping))
        .route("/api/v2/system/verify-token", any(verify_token))
        .route("/api/v2/system/health", get(health))
        .route("/api/v2/data/write-events", any(write_events))
        .route("/api/v2/data/read-events", any(read_events))
        .route("/api/v2/data/observe-events", any(observe_events))
        .route("/api/v2/data/read-subjects", any(read_subjects))
        .route("/api/v2/data/read-event-types", any(read_event_types))
        .route("/api/v2/data/run-eventql-query", any(run_eventql_query))
        .route(
            "/api/v2/data/register-event-schema",
            any(not_implemented_schema),
        )
        .route("/api/v2/management/verify-store", any(verify_store))
        .route("/api/v2/management/audit-history", any(audit_history))
        .route(
            "/api/v2/management/enable-read-only-mode",
            any(enable_read_only),
        )
        .route("/api/v2/management/redact-events", any(redact_events))
        .route("/api/v2/tlog/receipt", any(tlog_receipt))
        .route("/api/v2/tlog/consistency", any(tlog_consistency))
        .route("/api/v2/tlog/bundle", any(tlog_bundle))
        .route("/api/v2/ts/write", any(ts::write))
        .route("/api/v2/ts/query", any(ts::query))
        .route("/api/v2/ts/series", get(ts::series).post(ts::series))
        .route("/api/v2/ts/flush", any(ts::flush))
        .route("/api/v2/ts/expire", any(ts::expire))
        .route("/api/v2/ts/proof", any(ts::proof))
        .route("/health/writer", get(ha::health_writer))
        .route("/health/ready", get(ha::health_ready))
        .route("/tlog/checkpoint", get(tlog_checkpoint))
        .route("/tlog/key", get(tlog_key))
        .layer(middleware::from_fn(move |req: Request, next: Next| {
            server_header(compat, req, next)
        }))
        .with_state(app)
}

async fn server_header(compat: bool, req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let v = if compat {
        concat!(
            "EventSourcingDB/1.3 (compatible; vesdb/",
            env!("CARGO_PKG_VERSION"),
            ")"
        )
    } else {
        concat!("vesdb/", env!("CARGO_PKG_VERSION"))
    };
    res.headers_mut()
        .insert(header::SERVER, HeaderValue::from_static(v));
    res
}

// ------------------------------------------------------------------------------------ system

async fn ping(State(app): State<Shared>) -> Response {
    let body = wire::management_event(
        "io.eventsourcingdb.api.ping-received",
        "/api/v2/system/ping",
        &format!("https://{}", app.origin),
        json!({"message": "OK"}),
    );
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

async fn verify_token(State(app): State<Shared>, method: Method, headers: HeaderMap) -> Response {
    if method != Method::POST {
        return status(StatusCode::METHOD_NOT_ALLOWED, "use POST");
    }
    if let Err(r) = authorize(&app, &headers, Scope::Read) {
        return r;
    }
    let body = wire::management_event(
        "io.eventsourcingdb.api.token-verified",
        "/api/v2/system/verify-token",
        &format!("https://{}", app.origin),
        json!({}),
    );
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

async fn health(State(app): State<Shared>, headers: HeaderMap) -> Response {
    if let Err(r) = authorize(&app, &headers, Scope::Read) {
        return r;
    }
    let s = app.store.lock().unwrap();
    let wit: Vec<PublicKey> = app.cfg.witnesses.iter().map(|w| w.key.clone()).collect();
    let cos = s.latest_cosigned(&wit, app.cfg.quorum).map(|c| c.size);
    let ok = s.failure().is_none();
    let body = json!({
        "status": if ok { "ok" } else { "failed" },
        "store": {
            "eventCount": s.len(),
            "operationMode": if s.is_read_only() { "read-only" } else { "read-write" },
            "failure": s.failure(),
            "latestCheckpointSize": s.checkpoints().last().map(|c| c.size),
            "latestCosignedSize": cos,
            "witnessQuorum": app.cfg.quorum,
        }
    });
    (
        if ok {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        axum::Json(body),
    )
        .into_response()
}

// ------------------------------------------------------------------------------------ write

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteBody {
    events: Vec<CandidateIn>,
    #[serde(default)]
    preconditions: Vec<PreconditionIn>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateIn {
    source: String,
    subject: String,
    #[serde(rename = "type")]
    ty: String,
    data: Box<RawValue>,
    #[serde(default)]
    traceparent: Option<String>,
    #[serde(default)]
    tracestate: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreconditionIn {
    #[serde(rename = "type")]
    ty: String,
    payload: Value,
}

enum Pc {
    Store(Precondition),
    EventQl(String),
}

fn to_precondition(p: &PreconditionIn) -> Result<Pc, (String, String)> {
    let subject = p
        .payload
        .get("subject")
        .and_then(Value::as_str)
        .map(str::to_string);
    let recursive = p
        .payload
        .pointer("/options/recursive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let need_subject = || {
        subject.clone().ok_or((
            "subject-missing".to_string(),
            "payload.subject is required".to_string(),
        ))
    };
    Ok(Pc::Store(match p.ty.as_str() {
        "isSubjectPristine" => Precondition::IsSubjectPristine {
            subject: need_subject()?,
            recursive,
        },
        "isSubjectPopulated" => Precondition::IsSubjectPopulated {
            subject: need_subject()?,
            recursive,
        },
        "isSubjectOnEventId" => {
            let id = p.payload.get("eventId").and_then(Value::as_str).ok_or((
                "event-id-missing".to_string(),
                "payload.eventId is required".to_string(),
            ))?;
            let event_id = id.parse().map_err(|_| {
                (
                    "event-id-malformed".to_string(),
                    format!("bad eventId {id}"),
                )
            })?;
            Precondition::IsSubjectOnEventId {
                subject: need_subject()?,
                event_id,
                recursive,
            }
        }
        "isEventQlQueryTrue" => {
            let q = p.payload.get("query").and_then(Value::as_str).ok_or((
                "query-missing".to_string(),
                "payload.query is required".to_string(),
            ))?;
            if q.len() > vesdb_eventql::parser::MAX_QUERY_BYTES {
                return Err((
                    "query-too-long".into(),
                    "EventQL preconditions are limited to 100 KiB".into(),
                ));
            }
            return Ok(Pc::EventQl(q.to_string()));
        }
        other => {
            return Err((
                "precondition-unknown".into(),
                format!("unknown precondition type {other}"),
            ))
        }
    }))
}

async fn write_events(
    State(app): State<Shared>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if method != Method::POST {
        return status(StatusCode::METHOD_NOT_ALLOWED, "use POST");
    }
    if let Err(r) = authorize(&app, &headers, Scope::Write) {
        return r;
    }
    if app.store.lock().unwrap().is_standby() {
        return retryable(&StoreError::NotWriter);
    }
    // Idempotency-Key: a retried request (same key, same body) gets the original answer
    let idem = match headers.get("idempotency-key").map(|v| v.to_str()) {
        None => None,
        Some(Ok(k)) if !k.is_empty() && k.len() <= 256 => Some(vesdb_core::objects::IdemRecord {
            key: k.to_string(),
            request: hex::encode(vesdb_core::sha256(&[&body])),
        }),
        Some(_) => {
            return status(
                StatusCode::BAD_REQUEST,
                "Idempotency-Key must be 1 to 256 visible characters",
            )
        }
    };
    let wb: WriteBody = match parse_body(&headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    // (original index, precondition): store preconditions first, EventQL ones evaluated last
    let mut pcs: Vec<(usize, Precondition)> = Vec::new();
    let mut eql: Vec<(usize, String)> = Vec::new();
    for (i, p) in wb.preconditions.iter().enumerate() {
        match to_precondition(p) {
            Ok(Pc::Store(pc)) => pcs.push((i, pc)),
            Ok(Pc::EventQl(q)) => eql.push((i, q)),
            Err((slug, d)) => {
                return ndjson(wire::error(&slug, &d, json!({ "precondition": i })) + &wire::end())
            }
        }
    }
    let cands: Vec<Candidate> = wb
        .events
        .into_iter()
        .map(|c| Candidate {
            source: c.source,
            subject: c.subject,
            ty: c.ty,
            data: c.data.get().to_string(),
            traceparent: c.traceparent,
            tracestate: c.tracestate,
        })
        .collect();
    let app2 = app.clone();
    let rt = tokio::runtime::Handle::current();
    let res: Result<Result<(Vec<vesdb_store::StoredEvent>, bool), StoreError>, Response> =
        blocking(move || {
            // the whole check-then-write runs under the store lock: other writes wait (as in EventSourcingDB)
            let mut s = app2.store.lock().unwrap();
            let store_pcs: Vec<Precondition> = pcs.iter().map(|(_, p)| p.clone()).collect();
            if let Some(i) = s.first_failing(&store_pcs) {
                return Err(ndjson(store_error(&StoreError::PreconditionViolated {
                    index: pcs[i].0,
                })));
            }
            if !eql.is_empty() {
                let cat = match catalog(&app2, &s) {
                    Ok(c) => c,
                    Err(e) => return Err(ndjson(store_error(&e))),
                };
                let limits = vesdb_eventql::Limits {
                    timeout: Duration::from_secs(5),
                    ..Default::default()
                };
                for (i, q) in &eql {
                    match rt.block_on(vesdb_eventql::eval_bool(q, &cat, &limits)) {
                        Ok(true) => {}
                        Ok(false) => {
                            return Err(ndjson(store_error(&StoreError::PreconditionViolated {
                                index: *i,
                            })))
                        }
                        Err(e) => {
                            return Err(ndjson(
                                wire::error(e.slug(), &e.to_string(), json!({ "precondition": i }))
                                    + &wire::end(),
                            ))
                        }
                    }
                }
            }
            Ok(s.write_ext(now_ns(), cands, &store_pcs, idem)
                .and_then(|o| {
                    let evs = o
                        .events
                        .iter()
                        .map(|m| s.event(m.id))
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok((evs, o.replayed))
                }))
        })
        .await;
    let res = match res {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match res {
        Ok((evs, replayed)) => {
            let mut out = String::new();
            for e in &evs {
                out += &event_line(&app, e);
                if !replayed {
                    let _ = app.new_events.send(e.meta.id);
                }
            }
            let mut r = ndjson(out + &wire::end());
            if replayed {
                r.headers_mut()
                    .insert("idempotent-replayed", HeaderValue::from_static("true"));
            }
            r
        }
        Err(e) if e.retryable() => retryable(&e),
        Err(e) => ndjson(store_error(&e)),
    }
}

// ------------------------------------------------------------------------------------ read / observe

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BoundIn {
    id: String,
    #[serde(rename = "type")]
    ty: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FromLatestIn {
    subject: String,
    #[serde(rename = "type")]
    ty: String,
    if_event_is_missing: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OptionsIn {
    #[serde(default)]
    recursive: bool,
    #[serde(default)]
    order: Option<String>,
    #[serde(default)]
    lower_bound: Option<BoundIn>,
    #[serde(default)]
    upper_bound: Option<BoundIn>,
    #[serde(default)]
    from_latest_event: Option<FromLatestIn>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadBody {
    subject: String,
    #[serde(default)]
    options: Option<OptionsIn>,
}

fn bound(b: &Option<BoundIn>) -> Result<Option<Bound>, String> {
    let Some(b) = b else { return Ok(None) };
    let id: u64 = b.id.parse().map_err(|_| "event-id-malformed".to_string())?;
    let inclusive = match b.ty.as_str() {
        "inclusive" => true,
        "exclusive" => false,
        _ => return Err("bound-type-unknown".into()),
    };
    Ok(Some(Bound { id, inclusive }))
}

fn read_options(o: &Option<OptionsIn>, observe: bool) -> Result<ReadOptions, String> {
    let d = OptionsIn::default();
    let o = o.as_ref().unwrap_or(&d);
    if o.from_latest_event.is_some() && o.lower_bound.is_some() {
        return Err("selection-conflicting".into());
    }
    let order = match o.order.as_deref() {
        None | Some("chronological") => Some(Order::Chronological),
        Some("antichronological") if !observe => Some(Order::Antichronological),
        _ => return Err("order-unknown".into()),
    };
    let from_latest = match &o.from_latest_event {
        None => None,
        Some(f) => Some(FromLatest {
            subject: f.subject.clone(),
            ty: f.ty.clone(),
            read_everything_if_missing: match f.if_event_is_missing.as_str() {
                "read-everything" => true,
                "read-nothing" | "wait-for-event" => false,
                _ => return Err("if-event-is-missing-unknown".into()),
            },
        }),
    };
    Ok(ReadOptions {
        recursive: o.recursive,
        order,
        lower: bound(&o.lower_bound)?,
        upper: bound(&o.upper_bound)?,
        from_latest,
    })
}

/// Stream events with the given ids in batches, taking the store lock per batch.
fn stream_ids(
    app: Shared,
    ids: Vec<u64>,
) -> impl futures::Stream<Item = Result<String, std::io::Error>> {
    stream::iter(ids.chunks(256).map(|c| c.to_vec()).collect::<Vec<_>>()).then(move |chunk| {
        let app = app.clone();
        async move {
            let s = app.store.lock().unwrap();
            let mut out = String::new();
            for id in chunk {
                match s.event(id) {
                    Ok(ev) => out += &event_line(&app, &ev),
                    Err(e) => {
                        out +=
                            &wire::error("file-unreadable", &e.to_string(), json!({ "event": id }))
                    }
                }
            }
            Ok(out)
        }
    })
}

async fn read_events(
    State(app): State<Shared>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_query(&method) {
        return status(StatusCode::METHOD_NOT_ALLOWED, "use QUERY");
    }
    if let Err(r) = authorize(&app, &headers, Scope::Read) {
        return r;
    }
    let rb: ReadBody = match parse_body(&headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let opts = match read_options(&rb.options, false) {
        Ok(o) => o,
        Err(slug) => return ndjson(wire::error(&slug, &slug, json!({})) + &wire::end()),
    };
    let ids = match app.store.lock().unwrap().read_ids(&rb.subject, &opts) {
        Ok(ids) => ids,
        Err(e) => return ndjson(store_error(&e)),
    };
    let s = stream_ids(app, ids).chain(stream::once(async { Ok(wire::end()) }));
    (
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        Body::from_stream(s),
    )
        .into_response()
}

async fn observe_events(
    State(app): State<Shared>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_query(&method) {
        return status(StatusCode::METHOD_NOT_ALLOWED, "use QUERY");
    }
    if let Err(r) = authorize(&app, &headers, Scope::Read) {
        return r;
    }
    let rb: ReadBody = match parse_body(&headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let mut opts = match read_options(&rb.options, true) {
        Ok(o) => o,
        Err(slug) => return ndjson(wire::error(&slug, &slug, json!({}))),
    };
    let wait_for_event = rb
        .options
        .as_ref()
        .and_then(|o| o.from_latest_event.as_ref())
        .is_some_and(|f| f.if_event_is_missing == "wait-for-event");
    // subscribe BEFORE reading history, so nothing written in between is missed
    let mut rx = app.new_events.subscribe();
    let subject = match vesdb_core::validate::subject(&rb.subject) {
        Ok(s) => s,
        Err(e) => return ndjson(wire::error(&e.slug(), &e.slug(), json!({}))),
    };
    let ids = match app.store.lock().unwrap().read_ids(&subject, &opts) {
        Ok(ids) => ids,
        Err(e) => return ndjson(store_error(&e)),
    };
    // with wait-for-event and no match yet, live events start at the first matching type
    let mut waiting_type = if wait_for_event && ids.is_empty() {
        opts.from_latest
            .as_ref()
            .map(|f| (f.subject.clone(), f.ty.clone()))
    } else {
        None
    };
    opts.from_latest = None;
    let mut last = ids.last().copied().or(opts.lower.map(|b| {
        if b.inclusive {
            b.id.wrapping_sub(1)
        } else {
            b.id
        }
    }));
    let recursive = opts.recursive;
    let history = stream_ids(app.clone(), ids);
    // live part: a dedicated task feeds a channel; it stops when the client disconnects
    let (tx_out, rx_out) = tokio::sync::mpsc::channel::<String>(256);
    let app_live = app.clone();
    tokio::spawn(async move {
        loop {
            match tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
                Err(_) => {
                    if tx_out.send(wire::heartbeat()).await.is_err() {
                        return;
                    }
                }
                Ok(Err(broadcast::error::RecvError::Closed)) => return,
                Ok(recv) => {
                    // on lag, catch up from the store; otherwise take ids up to the newest seen
                    let upto = match recv {
                        Ok(id) => id,
                        Err(_) => app_live.store.lock().unwrap().len().saturating_sub(1),
                    };
                    let from = last.map_or(0, |l| l.wrapping_add(1));
                    if upto < from {
                        continue;
                    }
                    let lines = {
                        let s = app_live.store.lock().unwrap();
                        let mut lines = Vec::new();
                        for id in from..=upto {
                            let Some(m) = s.meta(id) else { break };
                            last = Some(id);
                            if !vesdb_core::validate::under(&m.subject, &subject, recursive) {
                                continue;
                            }
                            if let Some((ws, wt)) = &waiting_type {
                                if !(m.subject == *ws && m.ty == *wt) {
                                    continue;
                                }
                                waiting_type = None;
                            }
                            if let Ok(ev) = s.event(id) {
                                lines.push(event_line(&app_live, &ev));
                            }
                        }
                        lines
                    };
                    for l in lines {
                        if tx_out.send(l).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    });
    let live = tokio_stream_from(rx_out);
    let s = history.chain(live);
    (
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        Body::from_stream(s),
    )
        .into_response()
}

fn tokio_stream_from(
    mut rx: tokio::sync::mpsc::Receiver<String>,
) -> impl futures::Stream<Item = Result<String, std::io::Error>> {
    stream::poll_fn(move |cx| rx.poll_recv(cx).map(|o| o.map(Ok)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectsBody {
    #[serde(alias = "baseSubject")]
    subject: String,
    #[serde(default)]
    options: Option<Value>,
}

async fn read_subjects(
    State(app): State<Shared>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_query(&method) {
        return status(StatusCode::METHOD_NOT_ALLOWED, "use QUERY");
    }
    if let Err(r) = authorize(&app, &headers, Scope::Read) {
        return r;
    }
    let b: SubjectsBody = match parse_body(&headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let recursive = b
        .options
        .as_ref()
        .and_then(|o| o.get("recursive"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let s = app.store.lock().unwrap();
    let mut out = String::new();
    for subj in s.subjects() {
        if vesdb_core::validate::under(subj, &b.subject, recursive) {
            out += &wire::item("subject", &json!({ "subject": subj }).to_string());
        }
    }
    ndjson(out + &wire::end())
}

async fn read_event_types(
    State(app): State<Shared>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if !is_query(&method) {
        return status(StatusCode::METHOD_NOT_ALLOWED, "use QUERY");
    }
    if let Err(r) = authorize(&app, &headers, Scope::Read) {
        return r;
    }
    let s = app.store.lock().unwrap();
    let mut types = BTreeSet::new();
    for i in 0..s.len() {
        if let Some(m) = s.meta(i) {
            types.insert(m.ty.clone());
        }
    }
    let mut out = String::new();
    for t in types {
        out += &wire::item(
            "eventType",
            &json!({"type": t, "hasEvents": true, "schema": null}).to_string(),
        );
    }
    ndjson(out + &wire::end())
}

async fn not_implemented_schema() -> Response {
    ndjson(
        wire::error(
            "event-schema-unsupported",
            "event schemas are not implemented in this vesdb version",
            json!({}),
        ) + &wire::end(),
    )
}

// ------------------------------------------------------------------------------------ management

async fn verify_store(State(app): State<Shared>, method: Method, headers: HeaderMap) -> Response {
    if method != Method::POST {
        return status(StatusCode::METHOD_NOT_ALLOWED, "use POST");
    }
    if let Err(r) = authorize(&app, &headers, Scope::Audit) {
        return r;
    }
    let app2 = app.clone();
    let res = blocking(move || {
        let mut f = app2.store.lock().unwrap().verify()?;
        if let Some(t) = &app2.ts {
            for x in t.lock().unwrap().verify() {
                f.push(vesdb_store::Finding {
                    severity: x.severity,
                    description: format!("time series: {}", x.description),
                });
            }
        }
        Ok::<_, StoreError>(f)
    })
    .await;
    match res {
        Ok(findings) => {
            let mut out = String::new();
            for f in findings {
                out += &wire::item("finding", &serde_json::to_string(&f).unwrap());
            }
            ndjson(out + &wire::end())
        }
        Err(e) => ndjson(store_error(&e)),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuditBody {
    last_audited_event: Option<AnchorIn>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorIn {
    id: String,
    hash: String,
}

async fn audit_history(
    State(app): State<Shared>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if method != Method::POST {
        return status(StatusCode::METHOD_NOT_ALLOWED, "use POST");
    }
    if let Err(r) = authorize(&app, &headers, Scope::Audit) {
        return r;
    }
    let raw: Value = match parse_body(&headers, &body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if raw.get("lastAuditedEvent").is_none() {
        return ndjson(
            wire::error(
                "last-audited-event-missing",
                "lastAuditedEvent is required (null for a first audit)",
                json!({}),
            ) + &wire::end(),
        );
    }
    let ab: AuditBody = match serde_json::from_value(raw) {
        Ok(b) => b,
        Err(e) => return status(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let anchor = match ab.last_audited_event {
        None => None,
        Some(a) => match a.id.parse::<u64>() {
            Ok(id) => Some((id, a.hash)),
            Err(_) => {
                return ndjson(
                    wire::error("event-id-malformed", "bad id", json!({})) + &wire::end(),
                )
            }
        },
    };
    let app2 = app.clone();
    match blocking(move || app2.store.lock().unwrap().audit(anchor)).await {
        Ok(Some((id, hash))) => ndjson(
            wire::item(
                "lastAuditedEvent",
                &json!({"id": id.to_string(), "hash": hash}).to_string(),
            ) + &wire::end(),
        ),
        Ok(None) => ndjson(wire::end()),
        Err(e) => {
            let (slug, desc) = e.split_once(": ").unwrap_or((e.as_str(), ""));
            ndjson(
                wire::error(slug, if desc.is_empty() { slug } else { desc }, json!({}))
                    + &wire::end(),
            )
        }
    }
}

async fn enable_read_only(
    State(app): State<Shared>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::POST {
        return status(StatusCode::METHOD_NOT_ALLOWED, "use POST");
    }
    if let Err(r) = authorize(&app, &headers, Scope::Admin) {
        return r;
    }
    app.store.lock().unwrap().set_read_only(true);
    ndjson(wire::item("readOnlyModeEnabled", "{}") + &wire::end())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedactBody {
    ids: Vec<String>,
    reason: String,
}

async fn redact_events(
    State(app): State<Shared>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if method != Method::POST {
        return status(StatusCode::METHOD_NOT_ALLOWED, "use POST");
    }
    if let Err(r) = authorize(&app, &headers, Scope::Redact) {
        return r;
    }
    let b: RedactBody = match parse_body(&headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Ok(ids) = b
        .ids
        .iter()
        .map(|s| s.parse::<u64>())
        .collect::<Result<Vec<_>, _>>()
    else {
        return ndjson(
            wire::error(
                "event-id-malformed",
                "ids must be decimal strings",
                json!({}),
            ) + &wire::end(),
        );
    };
    let app2 = app.clone();
    let res = blocking(move || {
        let mut s = app2.store.lock().unwrap();
        let before = s.len();
        s.redact(now_ns(), &ids, &b.reason)
            .map(|_| (before, s.len()))
    })
    .await;
    match res {
        Ok((a, b)) => {
            for id in a..b {
                let _ = app.new_events.send(id);
            }
            ndjson(
                wire::item(
                    "redacted",
                    &json!({"systemEvents": [a.to_string(), (b - 1).to_string()]}).to_string(),
                ) + &wire::end(),
            )
        }
        Err(e) => ndjson(store_error(&e)),
    }
}

// ------------------------------------------------------------------------------------ tlog

async fn tlog_key(State(app): State<Shared>) -> Response {
    axum::Json(app.log_key.clone()).into_response()
}

fn witness_keys(app: &App) -> Vec<PublicKey> {
    app.cfg.witnesses.iter().map(|w| w.key.clone()).collect()
}

/// Latest checkpoint with a witness quorum (public: it reveals only size and root).
async fn tlog_checkpoint(State(app): State<Shared>) -> Response {
    let s = app.store.lock().unwrap();
    match s.latest_cosigned(&witness_keys(&app), app.cfg.quorum) {
        Some(cp) => axum::Json(cp.clone()).into_response(),
        None => status(
            StatusCode::NOT_FOUND,
            "no checkpoint with a witness quorum yet",
        ),
    }
}

#[derive(Deserialize)]
struct ReceiptBody {
    id: String,
}

async fn tlog_receipt(
    State(app): State<Shared>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_query(&method) {
        return status(StatusCode::METHOD_NOT_ALLOWED, "use QUERY");
    }
    if let Err(r) = authorize(&app, &headers, Scope::Audit) {
        return r;
    }
    let b: ReceiptBody = match parse_body(&headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Ok(id) = b.id.parse::<u64>() else {
        return status(StatusCode::BAD_REQUEST, "bad id");
    };
    let s = app.store.lock().unwrap();
    let Some(r) = s.receipt_for(id) else {
        return status(StatusCode::NOT_FOUND, "unknown event");
    };
    let proof = s.tree().inclusion_proof(id, r.size);
    axum::Json(json!({
        "id": id.to_string(),
        "leaf": vesdb_core::b64::encode(&s.tree().leaf(id).unwrap()),
        "receipt": r,
        "inclusion": proof.iter().map(|h| vesdb_core::b64::encode(h)).collect::<Vec<_>>(),
    }))
    .into_response()
}

#[derive(Deserialize)]
struct ConsistencyBody {
    from: u64,
    to: u64,
}

async fn tlog_consistency(
    State(app): State<Shared>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_query(&method) {
        return status(StatusCode::METHOD_NOT_ALLOWED, "use QUERY");
    }
    if let Err(r) = authorize(&app, &headers, Scope::Audit) {
        return r;
    }
    let b: ConsistencyBody = match parse_body(&headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let s = app.store.lock().unwrap();
    if b.from > b.to || b.to > s.len() {
        return status(StatusCode::BAD_REQUEST, "need from <= to <= size");
    }
    let p = s.tree().consistency_proof(b.from, b.to);
    axum::Json(json!({"from": b.from, "to": b.to, "proof": p.iter().map(|h| vesdb_core::b64::encode(h)).collect::<Vec<_>>()}))
        .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleBody {
    ids: Vec<String>,
    /// Size of the cosigned checkpoint to prove against; default: latest with a quorum.
    #[serde(default)]
    checkpoint_size: Option<u64>,
}

async fn tlog_bundle(
    State(app): State<Shared>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_query(&method) {
        return status(StatusCode::METHOD_NOT_ALLOWED, "use QUERY");
    }
    if let Err(r) = authorize(&app, &headers, Scope::Audit) {
        return r;
    }
    let b: BundleBody = match parse_body(&headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Ok(ids) = b
        .ids
        .iter()
        .map(|s| s.parse::<u64>())
        .collect::<Result<Vec<_>, _>>()
    else {
        return status(StatusCode::BAD_REQUEST, "ids must be decimal strings");
    };
    let s = app.store.lock().unwrap();
    let wk = witness_keys(&app);
    let cp = match b.checkpoint_size {
        Some(n) => s
            .checkpoints()
            .iter()
            .rev()
            .find(|c| c.size == n && c.valid_cosigners(&wk).len() >= app.cfg.quorum),
        None => s.latest_cosigned(&wk, app.cfg.quorum),
    };
    let Some(cp) = cp.cloned() else {
        return status(
            StatusCode::CONFLICT,
            "no cosigned checkpoint covers the request yet",
        );
    };
    match s.bundle(&ids, &cp) {
        Ok(bundle) => axum::Json(bundle).into_response(),
        Err(e) => status(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

// ------------------------------------------------------------------------------------ checkpointer

/// One checkpoint round: sign a new checkpoint if the tree grew (or the latest lacks a quorum),
/// then collect cosignatures from every witness that has not cosigned it yet.
pub async fn checkpoint_round(app: &Shared) {
    let app2 = app.clone();
    let cp = blocking(move || {
        let mut s = app2.store.lock().unwrap();
        if s.is_standby() {
            return None; // only the writer signs checkpoints
        }
        let wk: Vec<PublicKey> = app2.cfg.witnesses.iter().map(|w| w.key.clone()).collect();
        let n = s.len();
        let last = s.checkpoints().last().cloned();
        match last {
            Some(c) if c.size == n => {
                if c.valid_cosigners(&wk).len() >= wk.len() {
                    None
                } else {
                    Some(c)
                }
            }
            _ if n == 0 => None,
            _ => s.checkpoint(now_ns()).ok(),
        }
    })
    .await;
    let Some(mut cp) = cp else { return };
    let mut changed = false;
    for w in &app.cfg.witnesses {
        if cp.cosigs.contains_key(&w.key.name) {
            continue;
        }
        for _attempt in 0..2 {
            let old = *app
                .witness_sizes
                .lock()
                .unwrap()
                .get(&w.key.name)
                .unwrap_or(&0);
            if old > cp.size {
                tracing::error!(witness = %w.key.name, old, size = cp.size, "witness has seen a larger tree than this log");
                break;
            }
            let proof = app
                .store
                .lock()
                .unwrap()
                .tree()
                .consistency_proof(old, cp.size);
            let req = AddCheckpoint {
                old_size: old,
                proof,
                checkpoint: cp.clone(),
            };
            let resp = app
                .http
                .post(format!("{}/add-checkpoint", w.url.trim_end_matches('/')))
                .json(&req)
                .send()
                .await;
            match resp {
                Ok(r) if r.status().is_success() => match r
                    .json::<vesdb_core::crypto::HybridSig>()
                    .await
                {
                    Ok(sig) => {
                        cp.cosigs.insert(w.key.name.clone(), sig);
                        app.witness_sizes
                            .lock()
                            .unwrap()
                            .insert(w.key.name.clone(), cp.size);
                        changed = true;
                    }
                    Err(e) => tracing::warn!(witness = %w.key.name, "bad cosignature body: {e}"),
                },
                Ok(r) if r.status() == StatusCode::CONFLICT => {
                    if let Ok(WitnessError::Conflict { witnessed, .. }) =
                        r.json::<WitnessError>().await
                    {
                        app.witness_sizes
                            .lock()
                            .unwrap()
                            .insert(w.key.name.clone(), witnessed);
                        continue; // retry with the witness's size
                    }
                }
                Ok(r) => {
                    let code = r.status();
                    let text = r.text().await.unwrap_or_default();
                    tracing::error!(witness = %w.key.name, %code, "witness refused checkpoint: {text}");
                }
                Err(e) => tracing::warn!(witness = %w.key.name, "witness unreachable: {e}"),
            }
            break;
        }
    }
    if changed {
        let app2 = app.clone();
        let _ = blocking(move || app2.store.lock().unwrap().record_checkpoint(cp)).await;
    }
}

pub fn spawn_checkpointer(app: Shared) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut last_size = 0u64;
        let mut tick = tokio::time::interval(Duration::from_millis(50));
        let mut since = std::time::Instant::now();
        loop {
            tick.tick().await;
            let n = app.store.lock().unwrap().len();
            if since.elapsed() >= app.cfg.checkpoint_interval
                || n >= last_size + app.cfg.checkpoint_max_events
            {
                checkpoint_round(&app).await;
                last_size = n;
                since = std::time::Instant::now();
            }
        }
    })
}

pub use vesdb_store::StoreConfig;

/// Witness name -> public key map, for configuration convenience.
pub fn witness_map(w: &[WitnessConfig]) -> BTreeMap<String, PublicKey> {
    w.iter()
        .map(|w| (w.key.name.clone(), w.key.clone()))
        .collect()
}
