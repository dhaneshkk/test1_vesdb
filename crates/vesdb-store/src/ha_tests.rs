//! High-availability tests on the in-memory object store (the plan's "in-memory fake") and on a
//! local directory through `object_store`: race test, two writers, step-down, idempotency across
//! servers, snapshots, redaction, and a randomized model check of the Lean `VesdbStore`
//! theorems as runtime assertions.

use super::*;
use object_store::{memory::InMemory, ObjectStore, ObjectStoreExt};
use std::sync::Arc;
use vesdb_core::objects::{batch_key, data_key, IdemRecord};

const ORIGIN: &str = "test.example/log";

fn cfg() -> StoreConfig {
    StoreConfig {
        dir: PathBuf::from("/nonexistent"),
        origin: ORIGIN.into(),
        system_source: "https://test.example".into(),
        pii_types: Default::default(),
        key: HybridKey::from_seed(ORIGIN, &[5; 32]),
    }
}

fn c(subject: &str, data: &str) -> Candidate {
    Candidate {
        source: "https://test.example".into(),
        subject: subject.into(),
        ty: "io.example.test.e".into(),
        data: if data.starts_with('{') {
            data.into()
        } else {
            serde_json::json!({ "v": data }).to_string()
        },
        traceparent: None,
        tracestate: None,
    }
}

fn open(bucket: &Arc<InMemory>) -> Store {
    let b = ObjectBackend::new(
        bucket.clone() as Arc<dyn ObjectStore>,
        "vesdb",
        "memory:///vesdb",
    );
    Store::open_with(cfg(), Box::new(b)).unwrap()
}

fn writer(bucket: &Arc<InMemory>) -> Store {
    let mut s = open(bucket);
    s.become_writer().unwrap();
    s
}

fn key(k: &str, req: &str) -> Option<IdemRecord> {
    Some(IdemRecord {
        key: k.into(),
        request: req.into(),
    })
}

#[test]
fn race_test_on_memory_and_local_directory() {
    let mem = ObjectBackend::new(Arc::new(InMemory::new()), "", "memory:///");
    assert_eq!(backend::race_test(&mem, 2_000).unwrap(), 2_000);
    let d = tempfile::tempdir().unwrap();
    let url = format!("file://{}", d.path().display());
    let local = ObjectBackend::from_url(&url).unwrap();
    assert_eq!(backend::race_test(&local, 2_000).unwrap(), 2_000);
}

#[test]
fn objects_write_reopen_and_verify() {
    let bucket = Arc::new(InMemory::new());
    let mut a = writer(&bucket);
    assert!(!a.is_standby());
    let (m, r) = a
        .write(
            10,
            vec![c("/a", r#"{"k":1}"#), c("/a/b", r#"{"k":2}"#)],
            &[],
        )
        .unwrap();
    assert_eq!((m.len(), r.size), (2, 2));
    a.write(11, vec![c("/a", r#"{"k":3}"#)], &[]).unwrap();
    let cp = a.checkpoint(12).unwrap();
    let root = a.tree().root_at(3);
    drop(a);
    // a fresh server sees the same log, payloads and checkpoint
    let b = open(&bucket);
    assert!(b.is_standby(), "a shared store opens as standby");
    assert_eq!((b.len(), b.tree().root_at(3)), (3, root));
    assert_eq!(b.event(2).unwrap().payload.unwrap().1, r#"{"k":3}"#);
    assert_eq!(b.checkpoints().last().unwrap().size, cp.size);
    assert!(b.verify().unwrap().is_empty());
    assert!(matches!(
        open(&bucket).write(13, vec![c("/a", "{}")], &[]),
        Err(StoreError::NotWriter)
    ));
}

#[test]
fn second_writer_loses_the_race_steps_down_and_catches_up() {
    let bucket = Arc::new(InMemory::new());
    let mut a = writer(&bucket);
    a.write(1, vec![c("/x", "1")], &[]).unwrap();
    let mut b = writer(&bucket); // b saw position 1 as next
    a.write(2, vec![c("/x", "2")], &[]).unwrap(); // a takes position 1 first
                                                  // b's create at position 1 is refused: no fork, b steps down, nothing was acknowledged
    let e = b.write(3, vec![c("/x", "b")], &[]).unwrap_err();
    assert!(matches!(e, StoreError::Conflict { position: 1 }), "{e}");
    assert!(e.retryable() && b.is_standby());
    assert_eq!(b.len(), 1);
    assert_eq!(b.catch_up().unwrap(), 1);
    assert_eq!(b.tree().root_at(2), a.tree().root_at(2));
    // a pauses; b takes over and writes; a's next write is refused in turn
    b.become_writer().unwrap();
    b.write(4, vec![c("/x", "3")], &[]).unwrap();
    assert!(matches!(
        a.write(5, vec![c("/x", "a")], &[]),
        Err(StoreError::Conflict { position: 2 })
    ));
    a.catch_up().unwrap();
    assert_eq!(a.event(2).unwrap().payload.unwrap().1, r#"{"v":"3"}"#);
    // b's losing payload object from the first race is garbage, not part of the log
    assert!(open(&bucket).verify().unwrap().is_empty());
}

#[test]
fn idempotency_key_is_written_once_across_servers() {
    let bucket = Arc::new(InMemory::new());
    let mut a = writer(&bucket);
    let mut b = open(&bucket); // a standby that has not tailed since
    let first = a
        .write_ext(1, vec![c("/o", "order")], &[], key("k1", "req-1"))
        .unwrap();
    assert!(!first.replayed);
    // retried on the same server: the original answer, nothing written
    let again = a
        .write_ext(2, vec![c("/o", "order")], &[], key("k1", "req-1"))
        .unwrap();
    assert!(again.replayed);
    assert_eq!(again.receipt, first.receipt);
    assert_eq!(a.len(), 1);
    // same key, different request: refused
    assert!(matches!(
        a.write_ext(3, vec![c("/o", "other")], &[], key("k1", "req-2")),
        Err(StoreError::IdempotencyMismatch)
    ));
    // the writer dies after storing, before replying; the client retries on the standby, which
    // had not tailed yet: its create is refused, it catches up and then answers from the log
    b.standby = false; // it claimed the writer role without catching up first
    let e = b
        .write_ext(4, vec![c("/o", "order")], &[], key("k1", "req-1"))
        .unwrap_err();
    assert!(matches!(e, StoreError::Conflict { .. }));
    b.become_writer().unwrap();
    let retry = b
        .write_ext(5, vec![c("/o", "order")], &[], key("k1", "req-1"))
        .unwrap();
    assert!(retry.replayed);
    assert_eq!(retry.events[0].id, 0);
    assert_eq!(b.len(), 1, "written exactly once");
    // keys survive a restart (they are in the batch objects)
    let mut r = writer(&bucket);
    assert!(
        r.write_ext(6, vec![c("/o", "order")], &[], key("k1", "req-1"))
            .unwrap()
            .replayed
    );
}

#[test]
fn snapshots_keep_restart_reads_flat() {
    let bucket = Arc::new(InMemory::new());
    let mut a = writer(&bucket);
    a.set_snapshot_every(Some(100));
    for i in 0..1_000 {
        a.write(i, vec![c("/s", &i.to_string())], &[]).unwrap();
    }
    let root = a.tree().root_at(1_000);
    drop(a);
    let b = open(&bucket);
    assert_eq!(b.tree().root_at(1_000), root);
    // one snapshot plus at most 100 batches instead of 1,000 batches
    assert!(b.load_reads() <= 101, "{} reads", b.load_reads());
    assert!(b.verify().unwrap().is_empty());
}

#[test]
fn redaction_replaces_the_payload_object_and_keeps_every_proof() {
    let bucket = Arc::new(InMemory::new());
    let mut a = writer(&bucket);
    a.write(1, vec![c("/p/1", r#"{"name":"Ada"}"#)], &[])
        .unwrap();
    let cp = a.checkpoint(2).unwrap();
    let commit = a.meta(0).unwrap().commit;
    a.redact(3, &[0], "erasure request").unwrap();
    assert!(a.event(0).unwrap().payload.is_none());
    // the bucket keeps no copy of the old bytes (no versioning on data/)
    let raw = futures::executor::block_on(async {
        bucket
            .get(&object_store::path::Path::from(format!(
                "vesdb/{}",
                data_key(&commit)
            )))
            .await
    })
    .unwrap();
    let bytes = futures::executor::block_on(raw.bytes()).unwrap();
    assert_eq!(bytes.len(), 9, "only id and flag remain");
    // a standby learns the redaction from the log; roots, receipts and checkpoints still verify
    let b = open(&bucket);
    assert!(b.event(0).unwrap().payload.is_none());
    assert_eq!(b.tree().root_at(cp.size), cp.root);
    assert!(b.verify().unwrap().is_empty());
}

fn first_batch(bucket: &Arc<InMemory>) -> vesdb_core::objects::BatchObject {
    vesdb_core::objects::BatchObject::decode(&futures::executor::block_on(async {
        bucket
            .get(&object_store::path::Path::from(format!(
                "vesdb/{}",
                batch_key(0)
            )))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
    }))
    .unwrap()
}

#[test]
fn a_batch_with_a_forged_receipt_is_refused() {
    let bucket = Arc::new(InMemory::new());
    let mut a = writer(&bucket);
    a.write(1, vec![c("/f", "1")], &[]).unwrap();
    // someone with bucket access but not the log key writes position 1 directly, reusing
    // batch 0's signed receipt
    let mut forged = first_batch(&bucket);
    forged.first = 1;
    forged.events[0].id = 1;
    forged.receipt.size = 2;
    futures::executor::block_on(bucket.put(
        &object_store::path::Path::from(format!("vesdb/{}", batch_key(1))),
        forged.encode().into(),
    ))
    .unwrap();
    // a fresh server refuses to open on it, and a tailing server refuses to apply it
    let b = ObjectBackend::new(
        bucket.clone() as Arc<dyn ObjectStore>,
        "vesdb",
        "memory:///vesdb",
    );
    assert!(matches!(
        Store::open_with(cfg(), Box::new(b)),
        Err(StoreError::Damaged(_))
    ));
    let b = ObjectBackend::new(
        bucket.clone() as Arc<dyn ObjectStore>,
        "vesdb",
        "memory:///vesdb",
    );
    let mut s = Store::open_with(cfg(), Box::new(EmptyLoad(b))).unwrap();
    s.apply_batch(first_batch(&bucket)).unwrap();
    assert!(matches!(s.catch_up(), Err(StoreError::Damaged(_))));
    assert_eq!(s.len(), 1);
}

/// A backend wrapper that loads nothing, so a test can apply batches one at a time.
struct EmptyLoad(ObjectBackend);

impl Backend for EmptyLoad {
    fn describe(&self) -> String {
        self.0.describe()
    }
    fn load(&mut self) -> Result<backend::Loaded, StoreError> {
        Ok(Default::default())
    }
    fn append(&mut self, b: &backend::Batch) -> Result<(), StoreError> {
        self.0.append(b)
    }
    fn store_receipt(&mut self, r: &Receipt) -> Result<(), StoreError> {
        self.0.store_receipt(r)
    }
    fn read_body(&self, id: u64, m: &EventMeta) -> Result<Vec<u8>, StoreError> {
        self.0.read_body(id, m)
    }
    fn redact(&mut self, id: u64, m: &EventMeta) -> Result<(), StoreError> {
        self.0.redact(id, m)
    }
    fn sync_redactions(&mut self) -> Result<(), StoreError> {
        Ok(())
    }
    fn put_checkpoint(&mut self, cp: &Checkpoint) -> Result<(), StoreError> {
        self.0.put_checkpoint(cp)
    }
    fn tail(&mut self, from: u64) -> Result<Vec<vesdb_core::objects::BatchObject>, StoreError> {
        self.0.tail(from)
    }
    fn checkpoints_after(&mut self, after: u64) -> Result<Vec<Checkpoint>, StoreError> {
        self.0.checkpoints_after(after)
    }
    fn put_snapshot(&mut self, s: &vesdb_core::objects::SnapshotObject) -> Result<(), StoreError> {
        self.0.put_snapshot(s)
    }
    fn shared(&self) -> bool {
        true
    }
}

/// Model check: random interleavings of writes (some with idempotency keys, some retried on
/// another server), tails, restarts, pauses and redactions across three servers sharing one
/// bucket. After every step the statements of the Lean theorems are checked at runtime.
#[test]
fn model_check_lean_theorems_hold_under_random_interleavings() {
    for seed in 1..=12u64 {
        let mut rng = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut next = |n: u64| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng % n
        };
        let bucket = Arc::new(InMemory::new());
        let mut servers: Vec<Store> = (0..3).map(|_| open(&bucket)).collect();
        // acknowledged writes: position -> (count, leaf hashes)
        let mut acked: BTreeMap<u64, Vec<Hash>> = BTreeMap::new();
        let mut keys_acked: BTreeMap<String, u64> = BTreeMap::new();
        let mut t = 0u64;
        for step in 0..250 {
            t += 1;
            let i = next(3) as usize;
            match next(10) {
                0..=4 => {
                    // write, sometimes with a key reused from an earlier request (a retry)
                    let k = match next(3) {
                        0 => None,
                        1 => Some(format!("k{}", next(1000))),
                        _ => keys_acked
                            .keys()
                            .nth(next(keys_acked.len().max(1) as u64) as usize)
                            .cloned(),
                    };
                    let s = &mut servers[i];
                    if s.is_standby() && next(2) == 0 {
                        let _ = s.become_writer();
                    }
                    let n = 1 + next(3) as usize;
                    let cands = (0..n).map(|j| c("/m", &format!("{step}.{j}"))).collect();
                    let req = k.as_ref().map(|k| IdemRecord {
                        key: k.clone(),
                        request: format!("req-{k}"),
                    });
                    match s.write_ext(t, cands, &[], req) {
                        Ok(o) => {
                            let first = o.events[0].id;
                            let leaves: Vec<Hash> = o.events.iter().map(|e| e.leaf()).collect();
                            if o.replayed {
                                assert_eq!(
                                    acked.get(&first),
                                    Some(&leaves),
                                    "replay returns the original"
                                );
                            } else {
                                // no_fork: a position is acknowledged once
                                assert!(
                                    acked.insert(first, leaves).is_none(),
                                    "seed {seed}: fork at {first}"
                                );
                                if let Some(k) = &k {
                                    assert!(
                                        keys_acked.insert(k.clone(), first).is_none(),
                                        "seed {seed}: key {k} written twice"
                                    );
                                }
                            }
                        }
                        Err(StoreError::Conflict { .. } | StoreError::NotWriter) => {}
                        Err(StoreError::IdempotencyMismatch) => {
                            unreachable!("requests are deterministic per key")
                        }
                        Err(e) => panic!("seed {seed}: {e}"),
                    }
                }
                5 | 6 => {
                    servers[i].catch_up().unwrap();
                }
                7 => {
                    // restart from the bucket
                    servers[i] = open(&bucket);
                }
                8 => {
                    // pause: nothing happens on server i; others go on
                }
                _ => {
                    let s = &mut servers[i];
                    if !s.is_standby() && !s.is_empty() {
                        let id = next(s.len());
                        let _ = s.redact(t, &[id], "model check");
                    }
                }
            }
            // prefix: every pair of servers' logs agree on their common part
            let roots: Vec<(u64, Hash)> = servers
                .iter()
                .map(|s| (s.len(), s.tree().root_at(s.len())))
                .collect();
            let longest = servers.iter().max_by_key(|s| s.len()).unwrap();
            for (n, r) in &roots {
                assert_eq!(
                    longest.tree().root_at(*n),
                    *r,
                    "seed {seed} step {step}: views diverge"
                );
            }
        }
        // ack_durable + receipt_sound: a fresh server holds every acknowledged batch, and every
        // receipt verifies against the rebuilt tree
        let fresh = open(&bucket);
        for (&p, leaves) in &acked {
            for (j, l) in leaves.iter().enumerate() {
                assert_eq!(
                    fresh.tree().leaf(p + j as u64),
                    Some(*l),
                    "seed {seed}: acknowledged batch {p} lost"
                );
            }
        }
        assert!(
            fresh.verify().unwrap().is_empty(),
            "seed {seed}: {:?}",
            fresh.verify()
        );
        // idempotent: each key is in at most one batch
        let mut seen = BTreeMap::new();
        for e in fresh.idem.values() {
            assert!(seen.insert(e.key.clone(), e.first).is_none());
        }
    }
}
