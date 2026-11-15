//! Object-storage encodings (high-availability plan, "Object layout"). Pure functions only.
//!
//! | object | contents | write rule |
//! |---|---|---|
//! | `log/<position>.batch` | one write batch: event metadata and commitments, the signed receipt | create only if new |
//! | `data/<commitment>` | one event's payload body (salt and data) | create only if new; replaced on redaction |
//! | `cp/<size>.json` | a signed checkpoint without cosignatures | create only if new |
//! | `cp/<size>/<witness>.sig` | one witness cosignature | create only if new |
//! | `snap/<position>.snap` | in-memory state up to a position, for fast restart | create only if new |
//! | `writer.json` | who is writing now (advisory) | replaced with `If-Match` |
//!
//! `<position>` is the batch's first event id, zero-padded to 20 digits so names sort in log
//! order. The create-only-if-new rule on `log/` is what decides who may write: of two writers
//! racing for one position, the store accepts exactly one (Lean: `VesdbStore.no_fork`).

use crate::{
    checkpoint::{Checkpoint, Receipt},
    crypto::HybridSig,
    encoding::EventMeta,
    Hash,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const BATCH_FORMAT: &str = "vesdb-batch/v1";
pub const SNAPSHOT_FORMAT: &str = "vesdb-snapshot/v1";
pub const WRITER_FORMAT: &str = "vesdb-writer/v1";

pub fn position(first: u64) -> String {
    format!("{first:020}")
}
pub fn batch_key(first: u64) -> String {
    format!("log/{}.batch", position(first))
}
pub fn data_key(commit: &Hash) -> String {
    format!("data/{}", hex::encode(commit))
}
pub fn checkpoint_key(size: u64) -> String {
    format!("cp/{}.json", position(size))
}
pub fn cosig_key(size: u64, witness: &str) -> String {
    format!("cp/{}/{}.sig", position(size), escape(witness))
}
pub fn snapshot_key(size: u64) -> String {
    format!("snap/{}.snap", position(size))
}
pub const WRITER_KEY: &str = "writer.json";

/// Witness names are host names; anything else is percent-escaped to stay one path segment.
fn escape(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Parse a `log/…` or `snap/…` key back to its position.
pub fn parse_position(key: &str) -> Option<u64> {
    let name = key.rsplit('/').next()?;
    let digits = name.split('.').next()?;
    (digits.len() == 20).then(|| digits.parse().ok()).flatten()
}

/// Idempotency key of the write request that produced a batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdemRecord {
    pub key: String,
    /// Hex SHA-256 of the request (events and preconditions), so a reused key with a different
    /// request is refused instead of answered with someone else's result.
    pub request: String,
}

/// One write batch. Payload bodies are separate `data/` objects, named by commitment.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchObject {
    pub format: String,
    pub first: u64,
    pub events: Vec<EventMeta>,
    pub receipt: Receipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idem: Option<IdemRecord>,
}

impl BatchObject {
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("batch serializes")
    }
    pub fn decode(b: &[u8]) -> Result<Self, String> {
        let o: Self = serde_json::from_slice(b).map_err(|e| e.to_string())?;
        if o.format != BATCH_FORMAT {
            return Err(format!("unknown batch format {}", o.format));
        }
        if o.events.is_empty() {
            return Err("empty batch".into());
        }
        for (j, e) in o.events.iter().enumerate() {
            if e.id != o.first + j as u64 {
                return Err(format!("batch {}: event {j} carries id {}", o.first, e.id));
            }
        }
        if o.receipt.size != o.first + o.events.len() as u64 {
            return Err(format!(
                "batch {}: receipt size {} does not end the batch",
                o.first, o.receipt.size
            ));
        }
        Ok(o)
    }
}

/// A checkpoint as stored in `cp/<size>.json`: everything but the cosignatures.
pub fn checkpoint_object(cp: &Checkpoint) -> Vec<u8> {
    let mut c = cp.clone();
    c.cosigs = BTreeMap::new();
    serde_json::to_vec(&c).expect("checkpoint serializes")
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CosigObject {
    pub witness: String,
    pub size: u64,
    pub sig: HybridSig,
}

/// Idempotency entry kept in memory and in snapshots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdemEntry {
    pub key: String,
    pub request: String,
    pub first: u64,
    pub count: u64,
    pub time_ns: u64,
}

/// State up to `size`, so a restarting server reads one object plus the batches after it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotObject {
    pub format: String,
    pub size: u64,
    pub events: Vec<EventMeta>,
    pub receipts: Vec<Receipt>,
    pub redacted: Vec<u64>,
    pub idem: Vec<IdemEntry>,
    /// Merkle root at `size`; checked against the rebuilt tree on load.
    #[serde(with = "crate::b64::hash")]
    pub root: Hash,
}

impl SnapshotObject {
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("snapshot serializes")
    }
    pub fn decode(b: &[u8]) -> Result<Self, String> {
        let o: Self = serde_json::from_slice(b).map_err(|e| e.to_string())?;
        if o.format != SNAPSHOT_FORMAT || o.events.len() as u64 != o.size {
            return Err("not a vesdb snapshot of the stated size".into());
        }
        Ok(o)
    }
}

/// `writer.json`: advisory only; correctness never depends on it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WriterObject {
    pub format: String,
    pub writer: String,
    pub since_ns: u64,
    pub heartbeat_ns: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{checkpoint::receipt_message, crypto::HybridKey, encoding::ZERO_HASH_HEX};

    fn meta(id: u64) -> EventMeta {
        EventMeta {
            id,
            time_ns: 1_000 + id,
            source: "https://rig-07.example".into(),
            subject: "/rigs/rig-07".into(),
            ty: "io.example.e".into(),
            traceparent: None,
            tracestate: None,
            commit: [id as u8; 32],
            predecessorhash: ZERO_HASH_HEX.into(),
            hash: "x".into(),
        }
    }

    #[test]
    fn keys_sort_in_log_order_and_parse_back() {
        let ks: Vec<String> = [0u64, 9, 10, 99, 100, 12_345]
            .iter()
            .map(|&p| batch_key(p))
            .collect();
        let mut sorted = ks.clone();
        sorted.sort();
        assert_eq!(ks, sorted);
        assert_eq!(parse_position(&batch_key(12_345)), Some(12_345));
        assert_eq!(parse_position(&snapshot_key(7)), Some(7));
        assert_eq!(parse_position("log/12.batch"), None);
        assert_eq!(
            cosig_key(3, "witness.innoura.example"),
            "cp/00000000000000000003/witness.innoura.example.sig"
        );
        assert_eq!(cosig_key(3, "a/b"), "cp/00000000000000000003/a%2Fb.sig");
    }

    #[test]
    fn batch_round_trip_and_validation() {
        let k = HybridKey::from_seed("o", &[1; 32]);
        let root = [7; 32];
        let b = BatchObject {
            format: BATCH_FORMAT.into(),
            first: 5,
            events: vec![meta(5), meta(6)],
            receipt: Receipt {
                size: 7,
                root,
                sig: k.sign(&receipt_message("o", 7, &root)),
            },
            idem: Some(IdemRecord {
                key: "k1".into(),
                request: "ab".into(),
            }),
        };
        assert_eq!(BatchObject::decode(&b.encode()).unwrap(), b);
        let mut bad = b.clone();
        bad.events[1].id = 9;
        assert!(BatchObject::decode(&bad.encode()).is_err());
        let mut bad = b.clone();
        bad.receipt.size = 6;
        assert!(BatchObject::decode(&bad.encode()).is_err());
        let mut no_idem = b.clone();
        no_idem.idem = None;
        assert!(!String::from_utf8(no_idem.encode())
            .unwrap()
            .contains("idem"));
    }
}
