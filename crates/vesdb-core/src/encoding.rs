//! Event metadata, the canonical Merkle-leaf encoding (`enc`), payload commitments and the
//! EventSourcingDB-compatible `esdb:hash:v2`.
//!
//! The leaf commits to metadata plus `c = SHA256("vesdb/payload/v1" || salt || data)`, never to
//! the payload itself, so a payload can be erased (redaction) without changing any leaf, root,
//! checkpoint or proof.

use crate::{b64, merkle::leaf_hash, sha256, time::rfc3339_ns, Hash};
use serde::{Deserialize, Serialize};

pub const PAYLOAD_TAG: &[u8] = b"vesdb/payload/v1";
pub const LEAF_VERSION: u8 = 1;
/// Compat hash prefix, also the first hashed field (trailing colon included), as in the official
/// SDK's `compute_hash_v2`.
pub const COMPAT_PREFIX: &str = "esdb:hash:v2:";
/// Hash string used for event types configured as personal data (no unsalted compat hash).
pub const LEAF_HASH_PREFIX: &str = "vesdb:leaf:v1:";
pub const ZERO_HASH_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Everything about an event that is committed in its Merkle leaf (plus the compat fields).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventMeta {
    pub id: u64,
    pub time_ns: u64,
    pub source: String,
    pub subject: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traceparent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracestate: Option<String>,
    /// Payload commitment `c`.
    #[serde(with = "b64::hash")]
    pub commit: Hash,
    /// Compat chain: the previous event's full `hash` string, or 64 zeros for event 0.
    pub predecessorhash: String,
    /// `esdb:hash:v2:<hex>`, or `vesdb:leaf:v1:<leaf hex>` for event types configured as personal
    /// data (an unsalted hash over `data` would let low-entropy values be guessed after redaction).
    pub hash: String,
}

fn u32be(n: usize) -> [u8; 4] {
    (u32::try_from(n).expect("field longer than 2^32 bytes")).to_be_bytes()
}

fn lp(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&u32be(b.len()));
    out.extend_from_slice(b);
}

fn opt(out: &mut Vec<u8>, s: &Option<String>) {
    match s {
        None => out.push(0),
        Some(s) => {
            out.push(1);
            lp(out, s.as_bytes());
        }
    }
}

impl EventMeta {
    /// Canonical leaf encoding (Lean: `Vesdb.enc`). Length-prefixed, so injective for
    /// well-formed events (Lean: `encode_injective`).
    pub fn enc(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(128 + self.source.len() + self.subject.len() + self.ty.len());
        out.push(LEAF_VERSION);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.time_ns.to_be_bytes());
        lp(&mut out, self.source.as_bytes());
        lp(&mut out, self.subject.as_bytes());
        lp(&mut out, self.ty.as_bytes());
        opt(&mut out, &self.traceparent);
        opt(&mut out, &self.tracestate);
        out.extend_from_slice(&self.commit);
        out
    }

    /// RFC 9162 leaf hash of [`EventMeta::enc`].
    pub fn leaf(&self) -> Hash {
        leaf_hash(&self.enc())
    }

    /// Does this event carry an EventSourcingDB-verifiable compat hash?
    pub fn has_compat_hash(&self) -> bool {
        self.hash.starts_with(COMPAT_PREFIX)
    }

    /// The `hash` value for personal-data event types.
    pub fn leaf_hash_string(&self) -> String {
        format!("{LEAF_HASH_PREFIX}{}", hex::encode(self.leaf()))
    }
}

/// RFC 3339 with trailing zeros of the fraction trimmed (no fraction when zero), which is how the
/// official SDK formats `time` before hashing.
pub fn rfc3339_trimmed(t_ns: u64) -> String {
    let full = rfc3339_ns(t_ns); // ...SS.nnnnnnnnnZ
    let (head, frac) = full
        .trim_end_matches('Z')
        .split_once('.')
        .expect("fraction");
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() {
        format!("{head}Z")
    } else {
        format!("{head}.{frac}Z")
    }
}

/// `c = SHA256("vesdb/payload/v1" || salt || data)`.
pub fn commitment(salt: &[u8; 32], data: &[u8]) -> Hash {
    sha256(&[PAYLOAD_TAG, salt, data])
}

/// EventSourcingDB v2 compat hash, byte-compatible with the official SDK's `compute_hash_v2`
/// (checked against the SDK's own test events): prefix and fields each on a line of their own,
/// absent fields as `-`, `time` trimmed, `data` byte-exact and last. Every field before `data` is
/// LF-free (Lean: `compat_join_injective`); [`crate::validate`] guarantees this.
pub fn compat_hash_v2(m: &EventMeta, data: &[u8]) -> String {
    let id = m.id.to_string();
    let time = rfc3339_trimmed(m.time_ns);
    let fields: [&str; 11] = [
        COMPAT_PREFIX,
        "1.0",
        &id,
        &m.predecessorhash,
        &time,
        &m.source,
        &m.subject,
        &m.ty,
        "application/json",
        m.traceparent.as_deref().unwrap_or("-"),
        m.tracestate.as_deref().unwrap_or("-"),
    ];
    let mut buf = Vec::with_capacity(256 + data.len());
    for f in fields {
        debug_assert!(!f.contains('\n'));
        buf.extend_from_slice(f.as_bytes());
        buf.push(b'\n');
    }
    buf.extend_from_slice(data);
    format!("{COMPAT_PREFIX}{}", hex::encode(sha256(&[&buf])))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev() -> EventMeta {
        EventMeta {
            id: 0,
            time_ns: 0,
            source: "https://a.example".into(),
            subject: "/a".into(),
            ty: "io.example.thing-happened".into(),
            traceparent: None,
            tracestate: None,
            commit: [0; 32],
            predecessorhash: ZERO_HASH_HEX.into(),
            hash: String::new(),
        }
    }

    #[test]
    fn enc_distinguishes_field_boundaries() {
        let mut a = ev();
        let mut b = ev();
        a.subject = "/ab".into();
        a.ty = "c.d.e".into();
        b.subject = "/a".into();
        b.ty = "bc.d.e".into();
        assert_ne!(a.enc(), b.enc());
        let mut c = ev();
        c.traceparent = Some(String::new());
        assert_ne!(ev().enc(), c.enc());
    }
}
