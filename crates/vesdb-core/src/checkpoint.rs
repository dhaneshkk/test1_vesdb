//! Checkpoints (signed tree heads), write-time receipts and witness cosignatures.
//!
//! The checkpoint body is the C2SP `tlog-checkpoint` body: `<origin>\n<size>\n<base64 root>\n`.
//! Signatures are carried in JSON next to the body (hybrid Ed25519 + ML-DSA-65 has no registered
//! C2SP signed-note signature type yet).

use crate::{b64, crypto, crypto::HybridSig, crypto::PublicKey, Hash};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub fn checkpoint_body(origin: &str, size: u64, root: &Hash) -> Vec<u8> {
    format!("{origin}\n{size}\n{}\n", b64::encode(root)).into_bytes()
}

pub fn receipt_message(origin: &str, size: u64, root: &Hash) -> Vec<u8> {
    let mut m = b"vesdb/receipt/v1\n".to_vec();
    m.extend(checkpoint_body(origin, size, root));
    m
}

pub fn cosig_message(body: &[u8]) -> Vec<u8> {
    let mut m = b"vesdb/cosig/v1\n".to_vec();
    m.extend_from_slice(body);
    m
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub origin: String,
    pub size: u64,
    #[serde(with = "b64::hash")]
    pub root: Hash,
    pub time_ns: u64,
    pub log_sig: HybridSig,
    /// witness name -> cosignature over [`cosig_message`]
    #[serde(default)]
    pub cosigs: BTreeMap<String, HybridSig>,
}

impl Checkpoint {
    pub fn body(&self) -> Vec<u8> {
        checkpoint_body(&self.origin, self.size, &self.root)
    }

    pub fn verify_log_sig(&self, log_pub: &PublicKey) -> bool {
        crypto::verify(log_pub, &self.body(), &self.log_sig)
    }

    /// Names of witnesses (from `witnesses`) whose cosignature verifies.
    pub fn valid_cosigners(&self, witnesses: &[PublicKey]) -> Vec<String> {
        let msg = cosig_message(&self.body());
        witnesses
            .iter()
            .filter(|w| {
                self.cosigs
                    .get(&w.name)
                    .is_some_and(|s| crypto::verify(w, &msg, s))
            })
            .map(|w| w.name.clone())
            .collect()
    }
}

/// Signed promise, issued inside the commit before the write is acknowledged: the first `size`
/// leaves have root `root`, so every leaf below `size` is in every later tree the log signs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub size: u64,
    #[serde(with = "b64::hash")]
    pub root: Hash,
    pub sig: HybridSig,
}

impl Receipt {
    pub fn verify(&self, origin: &str, log_pub: &PublicKey) -> bool {
        crypto::verify(
            log_pub,
            &receipt_message(origin, self.size, &self.root),
            &self.sig,
        )
    }
}
