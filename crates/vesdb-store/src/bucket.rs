//! Whole-bucket verification (`vesdb-verify bucket`), and migration of a file store into a
//! bucket (`vesdb migrate`).

use crate::{backend::Batch, Backend, ObjectBackend, Store, StoreConfig, StoreError};
use serde::Serialize;
use vesdb_core::{
    crypto::PublicKey,
    encoding::{commitment, EventMeta},
    merkle::MerkleTree,
    objects::{batch_key, data_key, parse_position, BatchObject, SnapshotObject, WRITER_KEY},
};

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketReport {
    pub ok: bool,
    pub batches: u64,
    pub events: u64,
    pub redacted: u64,
    pub checkpoints: u64,
    pub cosigned_checkpoints: u64,
    pub snapshots: u64,
    pub writer: Option<String>,
    pub problems: Vec<String>,
}

/// Check every object in the log: the batch chain has no gaps and no extra positions, every
/// receipt is signed by the log key over the rebuilt tree, every payload matches its commitment
/// (or is redacted), every checkpoint and snapshot matches the tree, and checkpoints carry valid
/// cosignatures from `witnesses` (at least `quorum` for the latest).
pub fn verify_bucket(
    b: &mut ObjectBackend,
    origin: &str,
    log_pub: &PublicKey,
    witnesses: &[PublicKey],
    quorum: usize,
) -> Result<BucketReport, StoreError> {
    let mut r = BucketReport::default();
    let mut tree = MerkleTree::new();
    let mut metas: Vec<EventMeta> = Vec::new();
    let positions: Vec<u64> = b
        .list("log", None)?
        .iter()
        .filter_map(|k| parse_position(k))
        .collect();
    let mut expected = 0u64;
    let mut chain: Vec<u64> = Vec::new();
    for &p in &positions {
        if p != expected {
            if p < expected {
                r.problems.push(format!(
                    "batch at position {p} overlaps the batch before it"
                ));
            } else {
                r.problems
                    .push(format!("gap: positions {expected}..{p} are missing"));
            }
            continue;
        }
        let Some(bytes) = b.get_raw(&batch_key(p))? else {
            continue;
        };
        let o = match BatchObject::decode(&bytes) {
            Ok(o) => o,
            Err(e) => {
                r.problems.push(format!("batch {p}: {e}"));
                break;
            }
        };
        if !o.receipt.verify(origin, log_pub) {
            r.problems
                .push(format!("batch {p}: receipt signature invalid"));
        }
        for e in &o.events {
            tree.push(e.leaf());
        }
        if tree.root_at(tree.size()) != o.receipt.root {
            r.problems.push(format!(
                "batch {p}: receipt root does not match its events (history changed)"
            ));
        }
        r.batches += 1;
        chain.push(p);
        expected = o.receipt.size;
        metas.extend(o.events);
    }
    r.events = metas.len() as u64;
    // payloads
    for m in &metas {
        match b.get_raw(&data_key(&m.commit))? {
            None => r
                .problems
                .push(format!("event {}: payload object missing", m.id)),
            Some(body) if body.len() >= 9 && body[8] == 1 => r.redacted += 1,
            Some(body) if body.len() < 41 => r
                .problems
                .push(format!("event {}: payload truncated", m.id)),
            Some(body) => {
                let salt: [u8; 32] = body[9..41].try_into().unwrap();
                if commitment(&salt, &body[41..]) != m.commit || body[..8] != m.id.to_be_bytes() {
                    r.problems.push(format!(
                        "event {}: payload does not match its commitment",
                        m.id
                    ));
                }
            }
        }
    }
    // checkpoints
    let cps = b.checkpoints_after(0)?;
    for c in &cps {
        r.checkpoints += 1;
        if !c.verify_log_sig(log_pub) {
            r.problems
                .push(format!("checkpoint {}: log signature invalid", c.size));
        } else if c.size > tree.size() || tree.root_at(c.size) != c.root {
            r.problems.push(format!(
                "checkpoint {}: root does not match the log (history changed)",
                c.size
            ));
        }
        let valid = c.valid_cosigners(witnesses).len();
        if valid < c.cosigs.len() {
            r.problems.push(format!(
                "checkpoint {}: {} invalid cosignature(s)",
                c.size,
                c.cosigs.len() - valid
            ));
        }
        if valid >= quorum {
            r.cosigned_checkpoints += 1;
        }
    }
    if quorum > 0 && r.events > 0 && r.cosigned_checkpoints == 0 {
        r.problems
            .push("no checkpoint has the witness quorum".into());
    }
    // snapshots
    for k in b.list("snap", None)? {
        let Some(bytes) = b.get_raw(&k)? else {
            continue;
        };
        r.snapshots += 1;
        match SnapshotObject::decode(&bytes) {
            Ok(s) if s.size <= tree.size() && tree.root_at(s.size) == s.root => {}
            Ok(s) => r
                .problems
                .push(format!("snapshot {}: root does not match the log", s.size)),
            Err(e) => r.problems.push(format!("{k}: {e}")),
        }
    }
    if let Some(w) = b.get_raw(WRITER_KEY)? {
        r.writer = serde_json::from_slice::<serde_json::Value>(&w)
            .ok()
            .and_then(|v| v["writer"].as_str().map(String::from));
    }
    r.ok = r.problems.is_empty();
    Ok(r)
}

/// Copy a file store into an empty bucket, batch by batch, then check the copy: same events,
/// root, receipts and checkpoints as the source, and a clean [`verify_bucket`].
pub fn migrate(
    source: &Store,
    dest: &mut ObjectBackend,
    cfg: StoreConfig,
) -> Result<String, StoreError> {
    if !dest.list("log", None)?.is_empty() {
        return Err(StoreError::Invalid(
            "destination already holds a log".into(),
        ));
    }
    let mut first = 0u64;
    let mut batches = 0u64;
    for rc in source.receipts() {
        if rc.size <= first {
            continue;
        }
        let events: Vec<EventMeta> = (first..rc.size)
            .map(|i| source.meta(i).unwrap().clone())
            .collect();
        let bodies = (first..rc.size)
            .map(|i| source.payload_body(i))
            .collect::<Result<Vec<_>, _>>()?;
        let idem = source.idem_for(first);
        dest.append(&Batch {
            first,
            events: &events,
            bodies: &bodies,
            receipt: rc,
            idem: idem.as_ref(),
            time_ns: events[0].time_ns,
        })?;
        first = rc.size;
        batches += 1;
    }
    if first != source.len() {
        return Err(StoreError::Damaged(
            "source has events after its last receipt".into(),
        ));
    }
    for cp in source.checkpoints() {
        dest.put_checkpoint(cp)?;
    }
    // reopen from the bucket and compare
    let mut copy = Store::open_with(cfg, Box::new(ObjectBackend::from_url(&dest.url())?))?;
    copy.snapshot()?;
    let n = source.len();
    let same = copy.len() == n
        && copy.tree().root_at(n) == source.tree().root_at(n)
        && copy.receipts() == source.receipts()
        && copy
            .checkpoints()
            .iter()
            .map(|c| (c.size, c.root))
            .eq(source.checkpoints().iter().map(|c| (c.size, c.root)))
        && (0..n).all(|i| {
            copy.meta(i) == source.meta(i)
                && copy.event(i).ok().map(|e| e.payload) == source.event(i).ok().map(|e| e.payload)
        });
    if !same {
        return Err(StoreError::Damaged(
            "the copy differs from the source".into(),
        ));
    }
    let findings = copy.verify()?;
    if let Some(f) = findings.first() {
        return Err(StoreError::Damaged(format!(
            "the copy does not verify: {}",
            f.description
        )));
    }
    Ok(format!(
        "migrated {n} events in {batches} batches and {} checkpoints; root {} matches the source",
        source.checkpoints().len(),
        hex::encode(source.tree().root_at(n))
    ))
}
