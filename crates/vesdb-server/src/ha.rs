//! High availability: writer and standby roles on a shared bucket.
//!
//! The bucket's create-only-if-new write decides who may write (see `vesdb_store::backend`);
//! `writer.json` only keeps two servers from trying at once. A standby tails the bucket every
//! `tail_interval`. When the writer's heartbeat in `writer.json` is older than `stale_after`, a
//! standby in `auto` role claims it with a conditional replace, catches up and starts writing at
//! the next position. A writer that loses its claim, or whose create is refused, steps down.

use super::*;
use vesdb_core::objects::{WriterObject, WRITER_FORMAT, WRITER_KEY};
use vesdb_store::ObjectBackend;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Claim the writer role whenever it is free or stale.
    Auto,
    /// As `Auto`, and claim at start even before the heartbeat is stale (planned switchover).
    Writer,
    /// Never write; tail and serve reads.
    Standby,
}

impl std::str::FromStr for Role {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "auto" => Ok(Role::Auto),
            "writer" => Ok(Role::Writer),
            "standby" => Ok(Role::Standby),
            _ => Err(format!("role must be writer, standby or auto, not {s:?}")),
        }
    }
}

pub struct HaConfig {
    pub role: Role,
    /// Stable name of this server in `writer.json` (host name, pod name).
    pub identity: String,
    pub tail_interval: Duration,
    pub heartbeat_interval: Duration,
    pub stale_after: Duration,
}

type Version = (Option<String>, Option<String>);

#[derive(Default)]
struct HaState {
    /// version of `writer.json` as last written by us, while we hold the claim
    claim: Option<Version>,
    last_heartbeat: Option<std::time::Instant>,
    last_catch_up_ok: Option<std::time::Instant>,
    lag_events: u64,
    claims: u64,
    step_downs: u64,
}

pub struct Ha {
    pub cfg: HaConfig,
    bucket: ObjectBackend,
    state: Mutex<HaState>,
}

impl Ha {
    /// `bucket` must point at the same objects as the store's backend.
    pub fn new(cfg: HaConfig, bucket: ObjectBackend) -> Self {
        Self {
            cfg,
            bucket,
            state: Mutex::new(HaState::default()),
        }
    }

    fn read_writer(&self) -> Result<Option<(WriterObject, Version)>, String> {
        Ok(
            match self
                .bucket
                .get_versioned(WRITER_KEY)
                .map_err(|e| e.to_string())?
            {
                Some((b, v)) => serde_json::from_slice(&b).ok().map(|w| (w, v)),
                None => None,
            },
        )
    }

    fn writer_body(&self, since_ns: u64) -> Vec<u8> {
        serde_json::to_vec(&WriterObject {
            format: WRITER_FORMAT.into(),
            writer: self.cfg.identity.clone(),
            since_ns,
            heartbeat_ns: now_ns(),
        })
        .unwrap()
    }
}

/// One round of the role loop. Public so tests can drive it step by step.
pub fn ha_round(app: &App, force_claim: bool) -> Result<(), String> {
    let Some(ha) = &app.ha else { return Ok(()) };
    let standby = app.store.lock().unwrap().is_standby();
    if standby {
        // a refused create (or a lost claim) made us a standby: forget the claim
        if ha.state.lock().unwrap().claim.take().is_some() {
            ha.state.lock().unwrap().step_downs += 1;
            tracing::warn!("stepped down: another server writes this log");
        }
        // keep up with the writer
        let applied = app.store.lock().unwrap().catch_up();
        {
            let mut st = ha.state.lock().unwrap();
            match &applied {
                Ok(n) => {
                    st.last_catch_up_ok = Some(std::time::Instant::now());
                    st.lag_events = 0;
                    if *n > 0 {
                        let s = app.store.lock().unwrap();
                        let len = s.len();
                        // keep the time-series index current with chunks the writer sealed
                        let ts_events: Vec<(u64, String, Option<String>)> = (len - n..len)
                            .filter(|&id| s.meta(id).is_some_and(|m| m.subject.starts_with("/ts/")))
                            .filter_map(|id| s.event(id).ok())
                            .map(|e| (e.meta.id, e.meta.ty.clone(), e.payload.map(|p| p.1)))
                            .collect();
                        drop(s);
                        if let (Some(ts), false) = (&app.ts, ts_events.is_empty()) {
                            ts.lock().unwrap().absorb(
                                ts_events
                                    .iter()
                                    .map(|(i, t, d)| (*i, t.as_str(), d.as_deref())),
                            );
                        }
                        for id in len - n..len {
                            let _ = app.new_events.send(id);
                        }
                    }
                }
                Err(e) => tracing::error!("standby catch-up failed: {e}"),
            }
        }
        applied.map_err(|e| e.to_string())?;
        if ha.cfg.role == Role::Standby {
            return Ok(());
        }
        // claim the writer role if it is free, stale, or (role writer / forced) ours to take
        let current = ha.read_writer()?;
        let now = now_ns();
        let stale = |w: &WriterObject| {
            now.saturating_sub(w.heartbeat_ns) > ha.cfg.stale_after.as_nanos() as u64
        };
        let expect = match &current {
            None => None,
            Some((w, v)) if stale(w) || w.writer == ha.cfg.identity || force_claim => {
                Some(v.clone())
            }
            Some(_) => return Ok(()),
        };
        let body = ha.writer_body(now);
        let Some(v) = ha
            .bucket
            .replace_if(WRITER_KEY, body, expect)
            .map_err(|e| e.to_string())?
        else {
            return Ok(()); // someone else claimed first
        };
        // we hold the claim: catch up to the last stored batch and start writing after it
        let pos = app
            .store
            .lock()
            .unwrap()
            .become_writer()
            .map_err(|e| e.to_string())?;
        let mut st = ha.state.lock().unwrap();
        st.claim = Some(v);
        st.last_heartbeat = Some(std::time::Instant::now());
        st.claims += 1;
        tracing::info!(position = pos, "claimed the writer role");
        return Ok(());
    }
    // writer: heartbeat
    let due = {
        let st = ha.state.lock().unwrap();
        st.last_heartbeat
            .is_none_or(|t| t.elapsed() >= ha.cfg.heartbeat_interval)
    };
    if !due {
        return Ok(());
    }
    let claim = ha.state.lock().unwrap().claim.clone();
    let since = ha
        .read_writer()?
        .map(|(w, _)| w.since_ns)
        .unwrap_or_else(now_ns);
    match ha
        .bucket
        .replace_if(
            WRITER_KEY,
            ha.writer_body(since),
            Some(claim.unwrap_or_default()),
        )
        .map_err(|e| e.to_string())?
    {
        Some(v) => {
            let mut st = ha.state.lock().unwrap();
            st.claim = Some(v);
            st.last_heartbeat = Some(std::time::Instant::now());
        }
        None => {
            // another server claimed writer.json: stop writing (its creates decide anyway)
            app.store.lock().unwrap().step_down();
            let mut st = ha.state.lock().unwrap();
            st.claim = None;
            st.step_downs += 1;
            tracing::warn!("lost the writer claim; stepped down");
        }
    }
    Ok(())
}

pub fn spawn_ha(app: Shared) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let Some(ha) = &app.ha else { return };
        let mut tick = tokio::time::interval(ha.cfg.tail_interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut first = ha.cfg.role == Role::Writer;
        loop {
            tick.tick().await;
            let a = app.clone();
            let force = std::mem::take(&mut first);
            if let Err(e) = blocking(move || ha_round(&a, force)).await {
                tracing::warn!("high-availability round: {e}");
            }
        }
    })
}

/// `GET /health/writer`: 200 on the writer, 503 elsewhere. For the load balancer's write pool;
/// unauthenticated, like a health check.
pub(crate) async fn health_writer(State(app): State<Shared>) -> Response {
    let s = app.store.lock().unwrap();
    let writer = !s.is_standby() && s.failure().is_none() && !s.is_read_only();
    let body = json!({
        "role": if writer { "writer" } else { "standby" },
        "position": s.len(),
        "identity": app.ha.as_ref().map(|h| h.cfg.identity.clone()),
    });
    let code = if writer {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, axum::Json(body)).into_response()
}

/// `GET /health/ready`: 200 when this server can serve reads: the writer, or a standby whose last
/// catch-up succeeded within three tail intervals.
pub(crate) async fn health_ready(State(app): State<Shared>) -> Response {
    let s = app.store.lock().unwrap();
    let (ready, detail) = match &app.ha {
        None => (s.failure().is_none(), json!({})),
        Some(ha) => {
            let st = ha.state.lock().unwrap();
            let fresh = st.last_catch_up_ok.is_some_and(|t| {
                t.elapsed() <= ha.cfg.tail_interval * 3 + Duration::from_millis(500)
            });
            let r = s.failure().is_none() && (!s.is_standby() || fresh);
            (
                r,
                json!({
                    "lastCatchUpMsAgo": st.last_catch_up_ok.map(|t| t.elapsed().as_millis() as u64),
                    "claims": st.claims,
                    "stepDowns": st.step_downs,
                    "lagEvents": st.lag_events,
                }),
            )
        }
    };
    let body = json!({
        "ready": ready,
        "role": if s.is_standby() { "standby" } else { "writer" },
        "position": s.len(),
        "storage": s.backend_description(),
        "ha": detail,
    });
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, axum::Json(body)).into_response()
}

/// Chunk files shared through the bucket, under `ts/chunks/`.
pub struct BucketChunks(pub ObjectBackend);

impl vesdb_ts::ChunkMirror for BucketChunks {
    fn put(&self, key: &str, bytes: &[u8]) -> std::io::Result<()> {
        self.0
            .create_raw(&format!("ts/chunks/{key}"), bytes.to_vec())
            .map(|_| ())
            .map_err(std::io::Error::other)
    }
    fn get(&self, key: &str) -> std::io::Result<Option<Vec<u8>>> {
        self.0
            .get_raw(&format!("ts/chunks/{key}"))
            .map_err(std::io::Error::other)
    }
    fn delete(&self, key: &str) -> std::io::Result<()> {
        self.0
            .delete_raw(&format!("ts/chunks/{key}"))
            .map_err(std::io::Error::other)
    }
}
