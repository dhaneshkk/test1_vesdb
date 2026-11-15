//! Time-series routes (`/api/v2/ts/...`) and the sealer.
//!
//! Lock order is always time-series engine, then store; nothing holds the store lock while
//! taking the engine lock.

use super::*;
use vesdb_core::{
    time::parse_rfc3339_ns,
    ts::{PointProof, POINT_PROOF_FORMAT},
};
use vesdb_ts::{TsConfig, TsEngine, TsError};

pub(crate) fn open_engine(cfg: TsConfig, s: &Store) -> Result<TsEngine, String> {
    let ids = s
        .read_ids(
            "/ts",
            &ReadOptions {
                recursive: true,
                ..Default::default()
            },
        )
        .map_err(|e| e.to_string())?;
    let mut evs = Vec::with_capacity(ids.len());
    for id in ids {
        let e = s.event(id).map_err(|e| e.to_string())?;
        evs.push((id, e.meta.ty, e.payload.map(|(_, d)| d)));
    }
    let (eng, findings) = TsEngine::open(
        cfg,
        evs.iter().map(|(i, t, d)| (*i, t.as_str(), d.as_deref())),
    )
    .map_err(|e| e.to_string())?;
    for f in findings {
        tracing::info!(severity = f.severity, "{}", f.description);
    }
    Ok(eng)
}

fn ts_error(e: &TsError) -> Response {
    let code = match e {
        TsError::Invalid(_) | TsError::TooMany(_) => StatusCode::BAD_REQUEST,
        TsError::NotFound(_) => StatusCode::NOT_FOUND,
        TsError::NotSealed => StatusCode::CONFLICT,
        TsError::Busy(_) => StatusCode::SERVICE_UNAVAILABLE,
        TsError::Tampered { .. } | TsError::Damaged(_) | TsError::Io(_) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    (
        code,
        axum::Json(json!({ "error": e.slug(), "message": e.to_string() })),
    )
        .into_response()
}

fn engine(app: &App) -> Result<&Mutex<TsEngine>, Response> {
    app.ts.as_ref().ok_or_else(|| {
        status(
            StatusCode::NOT_FOUND,
            "time series are not enabled on this server",
        )
    })
}

/// A time: integer nanoseconds since the epoch, as a number or decimal string, or RFC 3339.
#[derive(Deserialize, Clone)]
#[serde(untagged)]
pub(crate) enum TimeIn {
    Ns(i64),
    Text(String),
}

impl TimeIn {
    fn ns(&self) -> Result<i64, String> {
        match self {
            TimeIn::Ns(n) => Ok(*n),
            TimeIn::Text(s) => s
                .parse::<i64>()
                .ok()
                .or_else(|| parse_rfc3339_ns(s).and_then(|n| i64::try_from(n).ok()))
                .ok_or_else(|| format!("{s:?} is neither nanoseconds nor RFC 3339")),
        }
    }
}

/// `"500ms"`, `"10s"`, `"5m"`, `"1h"`, `"1d"`, or integer nanoseconds.
#[derive(Deserialize, Clone)]
#[serde(untagged)]
pub(crate) enum StepIn {
    Ns(i64),
    Text(String),
}

impl StepIn {
    fn ns(&self) -> Result<i64, String> {
        match self {
            StepIn::Ns(n) => Ok(*n),
            StepIn::Text(s) => {
                let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
                let (num, unit) = s.split_at(split);
                let n: i64 = num.parse().map_err(|_| format!("bad step {s:?}"))?;
                let mul: i64 = match unit {
                    "" | "ns" => 1,
                    "us" => 1_000,
                    "ms" => 1_000_000,
                    "s" => 1_000_000_000,
                    "m" => 60_000_000_000,
                    "h" => 3_600_000_000_000,
                    "d" => 86_400_000_000_000,
                    _ => return Err(format!("bad step unit in {s:?}")),
                };
                n.checked_mul(mul)
                    .ok_or_else(|| format!("step {s:?} too large"))
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SeriesIn {
    name: String,
    times: Vec<TimeIn>,
    values: Vec<f64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteBody {
    series: Vec<SeriesIn>,
}

fn bad(m: impl Into<String>) -> Response {
    ts_error(&TsError::Invalid(m.into()))
}

pub(crate) async fn write(
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
    if let Err(r) = engine(&app) {
        return r;
    }
    let b: WriteBody = match parse_body(&headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let mut batches = Vec::with_capacity(b.series.len());
    for s in b.series {
        if s.times.len() != s.values.len() {
            return bad(format!("{}: times and values differ in length", s.name));
        }
        let mut pts = Vec::with_capacity(s.times.len());
        for (t, v) in s.times.iter().zip(s.values) {
            match t.ns() {
                Ok(t) => pts.push((t, v)),
                Err(e) => return bad(e),
            }
        }
        batches.push((s.name, pts));
    }
    let app2 = app.clone();
    match blocking(move || app2.ts.as_ref().unwrap().lock().unwrap().write(&batches)).await {
        Ok(n) => axum::Json(json!({ "accepted": n })).into_response(),
        Err(e) => ts_error(&e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryBody {
    series: String,
    from: TimeIn,
    to: TimeIn,
    #[serde(default)]
    step: Option<StepIn>,
}

pub(crate) async fn query(
    State(app): State<Shared>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_query(&method) {
        return status(StatusCode::METHOD_NOT_ALLOWED, "use POST");
    }
    if let Err(r) = authorize(&app, &headers, Scope::Read) {
        return r;
    }
    if let Err(r) = engine(&app) {
        return r;
    }
    let q: QueryBody = match parse_body(&headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let (from, to) = match (q.from.ns(), q.to.ns()) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => return bad(e),
    };
    let step = match q.step.as_ref().map(StepIn::ns).transpose() {
        Ok(s) => s,
        Err(e) => return bad(e),
    };
    let app2 = app.clone();
    blocking(move || {
        let eng = app2.ts.as_ref().unwrap().lock().unwrap();
        match step {
            None => match eng.query(&q.series, from, to) {
                Ok(r) => axum::Json(json!({
                    "series": q.series,
                    "points": r.points,
                    "expired": r.expired.iter().map(|c| json!({
                        "chunk": c.event_id.to_string(),
                        "expiredBy": c.expired_by.map(|x| x.to_string()),
                        "from": c.summary.from, "to": c.summary.to, "count": c.summary.count,
                    })).collect::<Vec<_>>(),
                }))
                .into_response(),
                Err(e) => ts_error(&e),
            },
            Some(step) => match eng.downsample(&q.series, from, to, step) {
                Ok(b) => axum::Json(json!({ "series": q.series, "step": step, "buckets": b }))
                    .into_response(),
                Err(e) => ts_error(&e),
            },
        }
    })
    .await
}

pub(crate) async fn series(State(app): State<Shared>, headers: HeaderMap) -> Response {
    if let Err(r) = authorize(&app, &headers, Scope::Read) {
        return r;
    }
    let eng = match engine(&app) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let list = eng.lock().unwrap().series();
    axum::Json(json!({ "series": list })).into_response()
}

/// Seal closed windows (all windows when `force`) and apply retention, as one log write.
/// Returns the sealed chunks as `(event id, summary)`.
pub fn ts_round(
    app: &App,
    now: i64,
    force: bool,
) -> Result<Vec<(u64, vesdb_core::ts::ChunkSummary)>, String> {
    let Some(ts) = &app.ts else {
        return Ok(vec![]);
    };
    let mut eng = ts.lock().unwrap();
    let pending = eng.prepare_seals(now, force).map_err(|e| e.to_string())?;
    let expiries = match eng.config().retention_ns {
        Some(r) => eng.prepare_expiry(now.saturating_sub(r), "retention policy"),
        None => vec![],
    };
    if pending.is_empty() && expiries.is_empty() {
        return Ok(vec![]);
    }
    let ids = {
        let mut s = app.store.lock().unwrap();
        let src = s.system_source().to_string();
        let cand = |subject, ty: &str, data| Candidate {
            source: src.clone(),
            subject,
            ty: ty.into(),
            data,
            traceparent: None,
            tracestate: None,
        };
        let mut cands: Vec<Candidate> = pending
            .iter()
            .map(|p| cand(p.subject(), p.event_type(), p.data()))
            .collect();
        cands.extend(
            expiries
                .iter()
                .map(|x| cand(x.subject(), x.event_type(), x.data())),
        );
        match s.write(now_ns(), cands, &[]) {
            Ok((metas, _)) => metas.iter().map(|m| m.id).collect::<Vec<u64>>(),
            Err(e) => {
                drop(s);
                eng.abort_seals(pending);
                return Err(format!("could not log sealed chunks: {e}"));
            }
        }
    };
    let n = pending.len();
    let sealed: Vec<(u64, vesdb_core::ts::ChunkSummary)> = pending
        .iter()
        .zip(&ids)
        .map(|(p, &id)| (id, p.summary.clone()))
        .collect();
    eng.commit_seals(pending.into_iter().zip(ids[..n].iter().copied()).collect())
        .map_err(|e| e.to_string())?;
    eng.commit_expiry(expiries.into_iter().zip(ids[n..].iter().copied()).collect())
        .map_err(|e| e.to_string())?;
    for id in ids {
        let _ = app.new_events.send(id);
    }
    Ok(sealed)
}

pub fn spawn_sealer(app: Shared, every: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let a = app.clone();
            if let Err(e) = blocking(move || ts_round(&a, now_ns() as i64, false)).await {
                tracing::warn!("time-series sealing: {e}");
            }
        }
    })
}

fn sealed_json(v: &[(u64, vesdb_core::ts::ChunkSummary)]) -> Value {
    v.iter()
        .map(|(id, s)| {
            json!({ "chunk": id.to_string(), "series": s.series, "from": s.from, "to": s.to,
                    "count": s.count, "bytes": s.bytes, "late": s.late })
        })
        .collect()
}

pub(crate) async fn flush(
    State(app): State<Shared>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::POST {
        return status(StatusCode::METHOD_NOT_ALLOWED, "use POST");
    }
    if let Err(r) = authorize(&app, &headers, Scope::Write) {
        return r;
    }
    if let Err(r) = engine(&app) {
        return r;
    }
    let a = app.clone();
    match blocking(move || ts_round(&a, now_ns() as i64, true)).await {
        Ok(v) => axum::Json(json!({ "sealed": sealed_json(&v) })).into_response(),
        Err(e) => status(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpireBody {
    before: TimeIn,
    #[serde(default)]
    reason: Option<String>,
}

pub(crate) async fn expire(
    State(app): State<Shared>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if method != Method::POST {
        return status(StatusCode::METHOD_NOT_ALLOWED, "use POST");
    }
    if let Err(r) = authorize(&app, &headers, Scope::Admin) {
        return r;
    }
    if let Err(r) = engine(&app) {
        return r;
    }
    let b: ExpireBody = match parse_body(&headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let before = match b.before.ns() {
        Ok(t) => t,
        Err(e) => return bad(e),
    };
    let reason = b.reason.unwrap_or_else(|| "manual expiry".into());
    let a = app.clone();
    let res = blocking(move || -> Result<Vec<(u64, u64)>, String> {
        let mut eng = a.ts.as_ref().unwrap().lock().unwrap();
        let x = eng.prepare_expiry(before, &reason);
        if x.is_empty() {
            return Ok(vec![]);
        }
        let ids = {
            let mut s = a.store.lock().unwrap();
            let src = s.system_source().to_string();
            let cands = x
                .iter()
                .map(|p| Candidate {
                    source: src.clone(),
                    subject: p.subject(),
                    ty: p.event_type().into(),
                    data: p.data(),
                    traceparent: None,
                    tracestate: None,
                })
                .collect();
            s.write(now_ns(), cands, &[])
                .map_err(|e| e.to_string())?
                .0
                .iter()
                .map(|m| m.id)
                .collect::<Vec<_>>()
        };
        let pairs: Vec<(u64, u64)> = x
            .iter()
            .map(|p| p.chunk_event)
            .zip(ids.iter().copied())
            .collect();
        eng.commit_expiry(x.into_iter().zip(ids.iter().copied()).collect())
            .map_err(|e| e.to_string())?;
        for id in ids {
            let _ = a.new_events.send(id);
        }
        Ok(pairs)
    })
    .await;
    match res {
        Ok(v) => axum::Json(json!({ "expired": v.iter().map(|(c, by)| json!({
            "chunk": c.to_string(), "expiredBy": by.to_string() })).collect::<Vec<_>>() }))
        .into_response(),
        Err(e) => status(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProofBody {
    series: String,
    time: TimeIn,
    #[serde(default)]
    checkpoint_size: Option<u64>,
}

pub(crate) async fn proof(
    State(app): State<Shared>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_query(&method) {
        return status(StatusCode::METHOD_NOT_ALLOWED, "use POST");
    }
    if let Err(r) = authorize(&app, &headers, Scope::Audit) {
        return r;
    }
    if let Err(r) = engine(&app) {
        return r;
    }
    let b: ProofBody = match parse_body(&headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let t = match b.time.ns() {
        Ok(t) => t,
        Err(e) => return bad(e),
    };
    let a = app.clone();
    blocking(move || {
        let parts = match a
            .ts
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .point_proof(&b.series, t)
        {
            Ok(p) => p,
            Err(e) => return ts_error(&e),
        };
        let s = a.store.lock().unwrap();
        let wk = witness_keys(&a);
        let cp = match b.checkpoint_size {
            Some(n) => s
                .checkpoints()
                .iter()
                .rev()
                .find(|c| c.size == n && c.valid_cosigners(&wk).len() >= a.cfg.quorum),
            None => s.latest_cosigned(&wk, a.cfg.quorum),
        }
        .filter(|c| c.size > parts.chunk_event)
        .cloned();
        let Some(cp) = cp else {
            return status(
                StatusCode::CONFLICT,
                "no cosigned checkpoint covers the chunk yet",
            );
        };
        match s.bundle(&[parts.chunk_event], &cp) {
            Ok(bundle) => axum::Json(PointProof {
                format: POINT_PROOF_FORMAT.into(),
                series: b.series,
                time: t,
                value: parts.value,
                index: parts.index,
                count: parts.count,
                inclusion: parts.inclusion,
                bundle,
            })
            .into_response(),
            Err(e) => status(StatusCode::BAD_REQUEST, e.to_string()),
        }
    })
    .await
}
