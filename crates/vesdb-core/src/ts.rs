//! Time-series evidence formats shared by the server (`vesdb-ts`) and the offline verifier.
//!
//! Raw points are not log entries. They are stored in compressed chunks, and each sealed chunk is
//! committed to the log as one event of type [`CHUNK_SEALED_TYPE`] whose data is a
//! [`ChunkSummary`]. The summary carries `pointsRoot`, the RFC 9162 Merkle root over the chunk's
//! points in stored order, so a single reading is provable with two inclusion proofs:
//!
//! ```text
//! point leaf ──(inclusion in pointsRoot)──▶ chunk-sealed event ──(inclusion in a cosigned checkpoint)──▶ witnesses
//! ```
//!
//! Lean: `point_proof_sound` (design doc, time-series section).

use crate::{
    b64,
    bundle::{verify_bundle, Bundle, Report},
    crypto::PublicKey,
    merkle::{leaf_hash, mth, verify_inclusion},
    Hash,
};
use serde::{Deserialize, Serialize};

pub const CHUNK_SEALED_TYPE: &str = "io.vesdb.ts.chunk-sealed";
pub const CHUNK_EXPIRED_TYPE: &str = "io.vesdb.ts.chunk-expired";
pub const POINT_PROOF_FORMAT: &str = "vesdb-point-proof/v1";
pub const CODEC: &str = "gorilla/v1";
/// Subject prefix of time-series system events: `/ts/<series>`.
pub const SUBJECT_PREFIX: &str = "/ts/";

const POINT_DOMAIN: &[u8] = b"vesdb/ts/point/v1";

/// Canonical point encoding: domain ‖ time (i64 ns, big-endian) ‖ IEEE-754 bits (big-endian).
pub fn point_enc(t: i64, v: f64) -> Vec<u8> {
    let mut b = Vec::with_capacity(POINT_DOMAIN.len() + 16);
    b.extend_from_slice(POINT_DOMAIN);
    b.extend_from_slice(&t.to_be_bytes());
    b.extend_from_slice(&v.to_bits().to_be_bytes());
    b
}

/// RFC 9162 leaf hash of a point: SHA-256(0x00 ‖ point_enc).
pub fn point_leaf(t: i64, v: f64) -> Hash {
    leaf_hash(&point_enc(t, v))
}

/// Merkle root over points in stored order.
pub fn points_root(points: &[(i64, f64)]) -> Hash {
    let leaves: Vec<Hash> = points.iter().map(|&(t, v)| point_leaf(t, v)).collect();
    mth(&leaves)
}

/// Data of a `chunk-sealed` event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChunkSummary {
    pub series: String,
    /// Start of the sealing window (ns since the Unix epoch).
    pub window: i64,
    /// First and last point time (ns), inclusive.
    pub t0: i64,
    pub t1: i64,
    /// `t0` and `t1` as RFC 3339, for people and EventQL.
    pub from: String,
    pub to: String,
    pub count: u64,
    pub min: f64,
    pub max: f64,
    pub sum: f64,
    /// Value of the first and last point in stored (time) order.
    pub first: f64,
    pub last: f64,
    /// Hex Merkle root over the points (see [`points_root`]).
    pub points_root: String,
    /// Hex SHA-256 of the chunk file.
    pub sha256: String,
    pub bytes: u64,
    pub codec: String,
    /// Highest write-ahead-log batch included; recovery skips replayed points at or below it.
    pub wal_hi: u64,
    /// The window had already been sealed when these points arrived.
    pub late: bool,
}

/// Data of a `chunk-expired` event: the chunk file was deleted under a retention policy. The
/// `chunk-sealed` event, its summary and its leaf stay in the log.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChunkExpired {
    pub series: String,
    /// Event id of the `chunk-sealed` event, as a decimal string.
    pub chunk: String,
    pub sha256: String,
    pub reason: String,
}

/// Offline evidence for one reading.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PointProof {
    pub format: String,
    pub series: String,
    pub time: i64,
    pub value: f64,
    /// Position of the point in the chunk and the chunk's point count.
    pub index: u64,
    pub count: u64,
    #[serde(with = "b64::hashes")]
    pub inclusion: Vec<Hash>,
    /// Evidence bundle holding exactly the chunk's `chunk-sealed` event.
    pub bundle: Bundle,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct PointReport {
    pub ok: bool,
    pub series: String,
    pub time: i64,
    pub value: f64,
    pub chunk_event: Option<u64>,
    pub point_inclusion_ok: bool,
    pub bundle: Report,
    pub problems: Vec<String>,
}

/// Verify a point proof against the log key and witness keys (`k` = cosignature quorum).
pub fn verify_point_proof(
    p: &PointProof,
    log_pub: &PublicKey,
    witnesses: &[PublicKey],
    k: usize,
) -> PointReport {
    let mut r = PointReport {
        series: p.series.clone(),
        time: p.time,
        value: p.value,
        bundle: verify_bundle(&p.bundle, log_pub, witnesses, k),
        ..Default::default()
    };
    if p.format != POINT_PROOF_FORMAT {
        r.problems
            .push(format!("unknown point proof format {}", p.format));
    }
    if !r.bundle.ok {
        r.problems.extend(r.bundle.problems.iter().cloned());
    }
    let [item] = p.bundle.items.as_slice() else {
        r.problems
            .push("the bundle must hold exactly the chunk-sealed event".into());
        return r;
    };
    r.chunk_event = Some(item.event.id);
    if item.event.ty != CHUNK_SEALED_TYPE {
        r.problems.push(format!(
            "event #{} is not a chunk-sealed event",
            item.event.id
        ));
    }
    if item.event.subject != format!("{SUBJECT_PREFIX}{}", p.series) {
        r.problems
            .push("the chunk event's subject does not name this series".into());
    }
    let Some(data) = &item.data else {
        r.problems
            .push("the chunk summary has been redacted".into());
        return r;
    };
    let s: ChunkSummary = match serde_json::from_str(data) {
        Ok(s) => s,
        Err(e) => {
            r.problems.push(format!("chunk summary unreadable: {e}"));
            return r;
        }
    };
    if s.series != p.series {
        r.problems
            .push("the chunk summary names another series".into());
    }
    if s.count != p.count {
        r.problems
            .push("point count differs from the chunk summary".into());
    }
    if p.time < s.t0 || p.time > s.t1 {
        r.problems
            .push("point time lies outside the chunk's range".into());
    }
    let root = match hex::decode(&s.points_root)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    {
        Some(h) => h,
        None => {
            r.problems.push("pointsRoot is not a hex hash".into());
            return r;
        }
    };
    r.point_inclusion_ok = verify_inclusion(
        p.index,
        p.count,
        &point_leaf(p.time, p.value),
        &p.inclusion,
        &root,
    );
    if !r.point_inclusion_ok {
        r.problems
            .push("the point is not in the chunk's pointsRoot".into());
    }
    r.ok = r.problems.is_empty();
    r
}
