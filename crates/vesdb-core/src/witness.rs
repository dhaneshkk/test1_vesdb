//! Honest witness state machine (C2SP tlog-witness behaviour).
//!
//! A witness remembers the latest checkpoint it cosigned per log origin and cosigns a new one only
//! if the log signature verifies and a consistency proof shows the new tree extends the old one
//! (Lean: `Witness.step`, `no_split_view`). Witnesses never see payloads.

use crate::{
    b64,
    checkpoint::{cosig_message, Checkpoint},
    crypto::{HybridKey, HybridSig, PublicKey},
    merkle::{empty_root, verify_consistency},
    Hash,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Request a log sends to a witness.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddCheckpoint {
    /// Size the log believes the witness last cosigned.
    pub old_size: u64,
    #[serde(with = "b64::hashes")]
    pub proof: Vec<Hash>,
    pub checkpoint: Checkpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "kebab-case")]
pub enum WitnessError {
    #[error("unknown log origin {origin}")]
    UnknownLog { origin: String },
    #[error("log signature invalid")]
    BadSignature,
    #[error("old size {sent} does not match witnessed size {witnessed}")]
    Conflict { sent: u64, witnessed: u64 },
    #[error("rollback: size {size} < witnessed {witnessed}")]
    Rollback { size: u64, witnessed: u64 },
    #[error("consistency proof {from}->{to} fails: history changed")]
    Inconsistent { from: u64, to: u64 },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Latest {
    pub size: u64,
    #[serde(with = "b64::hash")]
    pub root: Hash,
}

/// Persistent witness state: latest cosigned tree per origin.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WitnessState {
    pub latest: BTreeMap<String, Latest>,
}

impl WitnessState {
    pub fn latest(&self, origin: &str) -> Latest {
        self.latest.get(origin).cloned().unwrap_or(Latest {
            size: 0,
            root: empty_root(),
        })
    }

    /// One witness step. On success the state advances and the cosignature is returned.
    pub fn add_checkpoint(
        &mut self,
        key: &HybridKey,
        logs: &BTreeMap<String, PublicKey>,
        req: &AddCheckpoint,
    ) -> Result<HybridSig, WitnessError> {
        let cp = &req.checkpoint;
        let log_pub = logs
            .get(&cp.origin)
            .ok_or_else(|| WitnessError::UnknownLog {
                origin: cp.origin.clone(),
            })?;
        if !cp.verify_log_sig(log_pub) {
            return Err(WitnessError::BadSignature);
        }
        let last = self.latest(&cp.origin);
        if cp.size < last.size {
            return Err(WitnessError::Rollback {
                size: cp.size,
                witnessed: last.size,
            });
        }
        if req.old_size != last.size {
            return Err(WitnessError::Conflict {
                sent: req.old_size,
                witnessed: last.size,
            });
        }
        if !verify_consistency(last.size, cp.size, &last.root, &cp.root, &req.proof) {
            return Err(WitnessError::Inconsistent {
                from: last.size,
                to: cp.size,
            });
        }
        self.latest.insert(
            cp.origin.clone(),
            Latest {
                size: cp.size,
                root: cp.root,
            },
        );
        Ok(key.sign(&cosig_message(&cp.body())))
    }
}
