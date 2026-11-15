//! vesdb witness service. `POST /add-checkpoint` with an [`AddCheckpoint`] body:
//! * 200 + hybrid cosignature when the checkpoint extends what this witness last cosigned,
//! * 409 + `{"error":"conflict","witnessed":n}` when the log's idea of our size is stale,
//! * 422 when the history changed or rolled back, 403 for a bad log signature.
//!
//! State (latest size and root per log) is written atomically (temp file + fsync + rename)
//! BEFORE the cosignature is returned, so a crash can never make the witness forget a tree it
//! vouched for.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use vesdb_core::{
    crypto::{HybridKey, PublicKey},
    witness::{AddCheckpoint, WitnessError, WitnessState},
};

pub struct Witness {
    pub key: HybridKey,
    pub logs: BTreeMap<String, PublicKey>,
    pub state_path: Option<PathBuf>,
    pub state: Mutex<WitnessState>,
}

impl Witness {
    pub fn new(
        key: HybridKey,
        logs: Vec<PublicKey>,
        state_path: Option<PathBuf>,
    ) -> std::io::Result<Self> {
        let state = match &state_path {
            Some(p) if p.exists() => serde_json::from_slice(&std::fs::read(p)?)?,
            _ => WitnessState::default(),
        };
        Ok(Self {
            key,
            logs: logs.into_iter().map(|k| (k.name.clone(), k)).collect(),
            state_path,
            state: Mutex::new(state),
        })
    }

    fn persist(&self, st: &WitnessState) -> std::io::Result<()> {
        let Some(p) = &self.state_path else {
            return Ok(());
        };
        let tmp = p.with_extension("tmp");
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(st)?)?;
        f.sync_all()?;
        std::fs::rename(&tmp, p)?;
        if let Some(dir) = p.parent() {
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }
}

async fn add_checkpoint(State(w): State<Arc<Witness>>, Json(req): Json<AddCheckpoint>) -> Response {
    let mut st = w.state.lock().unwrap();
    let mut next = st.clone();
    match next.add_checkpoint(&w.key, &w.logs, &req) {
        Ok(sig) => {
            if let Err(e) = w.persist(&next) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("cannot persist witness state: {e}"),
                )
                    .into_response();
            }
            *st = next;
            tracing::info!(origin = %req.checkpoint.origin, size = req.checkpoint.size, "cosigned");
            Json(sig).into_response()
        }
        Err(e) => {
            tracing::warn!(origin = %req.checkpoint.origin, size = req.checkpoint.size, "refused: {e}");
            let code = match e {
                WitnessError::Conflict { .. } => StatusCode::CONFLICT,
                WitnessError::BadSignature => StatusCode::FORBIDDEN,
                WitnessError::UnknownLog { .. } => StatusCode::NOT_FOUND,
                WitnessError::Rollback { .. } | WitnessError::Inconsistent { .. } => {
                    StatusCode::UNPROCESSABLE_ENTITY
                }
            };
            (code, Json(e)).into_response()
        }
    }
}

async fn state(State(w): State<Arc<Witness>>) -> Response {
    Json(w.state.lock().unwrap().clone()).into_response()
}

async fn key(State(w): State<Arc<Witness>>) -> Response {
    Json(w.key.public()).into_response()
}

pub fn router(w: Arc<Witness>) -> Router {
    Router::new()
        .route("/add-checkpoint", post(add_checkpoint))
        .route("/state", get(state))
        .route("/key", get(key))
        .with_state(w)
}
