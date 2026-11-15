//! Gate 5 of the high-availability plan: does vesdb's checking flag a run that has a fault in
//! it? Each run writes a random log to a fresh bucket (batches, idempotency keys, a redaction)
//! and ends with a witness-cosigned checkpoint, as the checkpointer does within a second. Half
//! the runs then get exactly one injected fault, of the kinds the plan lists:
//!
//! * a changed byte in a batch object
//! * a deleted object (a batch, or an event's payload)
//! * a forked position written straight to the bucket (a different batch at an existing position)
//! * a lost acknowledged write (the last batch removed after it was checkpointed)
//! * a wrong cosignature (a witness signature replaced by another key's)
//!
//! The detector is `verify_bucket` (what `vesdb-verify bucket` runs nightly). Positive class: a
//! fault was injected. The score is the Matthews correlation coefficient over at least 200 runs
//! of each class; the gate asks for MCC 1.0, since a missed fault or a false alarm is a bug.

use object_store::{memory::InMemory, path::Path, ObjectStore, ObjectStoreExt, PutPayload};
use std::sync::Arc;
use vesdb_core::{
    checkpoint::cosig_message,
    crypto::HybridKey,
    objects::{batch_key, cosig_key, data_key, BatchObject, CosigObject},
};
use vesdb_store::{bucket::verify_bucket, Candidate, ObjectBackend, Store, StoreConfig};

const ORIGIN: &str = "fi.example/log";
const PREFIX: &str = "vesdb";

fn backend(b: &Arc<InMemory>) -> ObjectBackend {
    ObjectBackend::new(b.clone() as Arc<dyn ObjectStore>, PREFIX, "memory:///vesdb")
}

fn key() -> HybridKey {
    HybridKey::from_seed(ORIGIN, &[9; 32])
}

fn witness() -> HybridKey {
    HybridKey::from_seed("witness.example", &[10; 32])
}

struct Rng(u64);
impl Rng {
    fn next(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n.max(1)
    }
}

fn path(k: &str) -> Path {
    Path::from(format!("{PREFIX}/{k}"))
}

fn get(b: &Arc<InMemory>, k: &str) -> Vec<u8> {
    futures::executor::block_on(async {
        b.get(&path(k))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
            .to_vec()
    })
}

fn put(b: &Arc<InMemory>, k: &str, v: Vec<u8>) {
    futures::executor::block_on(b.put(&path(k), PutPayload::from(v))).unwrap();
}

fn delete(b: &Arc<InMemory>, k: &str) {
    futures::executor::block_on(b.delete(&path(k))).unwrap();
}

/// A clean run: returns the bucket and the batch start positions.
fn clean_run(rng: &mut Rng) -> (Arc<InMemory>, Vec<u64>, u64) {
    let bucket = Arc::new(InMemory::new());
    let cfg = StoreConfig {
        dir: "/nonexistent".into(),
        origin: ORIGIN.into(),
        system_source: "https://fi.example".into(),
        pii_types: Default::default(),
        key: key(),
    };
    let mut s = Store::open_with(cfg, Box::new(backend(&bucket))).unwrap();
    s.become_writer().unwrap();
    let mut starts = Vec::new();
    let batches = 3 + rng.next(8);
    for b in 0..batches {
        starts.push(s.len());
        let n = 1 + rng.next(4);
        let cands = (0..n)
            .map(|j| Candidate {
                source: "https://fi.example".into(),
                subject: format!("/rigs/r{}", rng.next(3)),
                ty: "io.example.reading".into(),
                data: format!(r#"{{"b":{b},"j":{j},"v":{}}}"#, rng.next(1000)),
                traceparent: None,
                tracestate: None,
            })
            .collect();
        let idem = (rng.next(2) == 0).then(|| vesdb_core::objects::IdemRecord {
            key: format!("k{b}"),
            request: format!("r{b}"),
        });
        s.write_ext(b + 1, cands, &[], idem).unwrap();
    }
    if rng.next(3) == 0 {
        let id = rng.next(s.len());
        s.redact(batches + 1, &[id], "erasure").unwrap();
        // the two redaction events are batches too
        let n = s.len();
        starts.push(n - 2);
        starts.push(n - 1);
    }
    // the checkpointer's round: sign, get the witness cosignature, record it
    let mut cp = s.checkpoint(1_000).unwrap();
    let w = witness();
    cp.cosigs
        .insert(w.name().to_string(), w.sign(&cosig_message(&cp.body())));
    s.record_checkpoint(cp).unwrap();
    (bucket, starts, s.len())
}

#[derive(Clone, Copy, Debug)]
enum Fault {
    ChangedByte,
    DeletedBatch,
    DeletedPayload,
    ForkedPosition,
    LostAckedWrite,
    WrongCosignature,
}

const FAULTS: [Fault; 6] = [
    Fault::ChangedByte,
    Fault::DeletedBatch,
    Fault::DeletedPayload,
    Fault::ForkedPosition,
    Fault::LostAckedWrite,
    Fault::WrongCosignature,
];

fn inject(b: &Arc<InMemory>, starts: &[u64], size: u64, f: Fault, rng: &mut Rng) {
    let p = starts[rng.next(starts.len() as u64) as usize];
    match f {
        Fault::ChangedByte => {
            // change one character of a field inside the batch (keeps it valid JSON)
            let mut o = BatchObject::decode(&get(b, &batch_key(p))).unwrap();
            let e = &mut o.events[0];
            let mut ch: Vec<char> = e.subject.chars().collect();
            let last = ch.len() - 1;
            ch[last] = if ch[last] == 'x' { 'y' } else { 'x' };
            e.subject = ch.into_iter().collect();
            put(b, &batch_key(p), o.encode());
        }
        Fault::DeletedBatch => delete(b, &batch_key(p)),
        Fault::DeletedPayload => {
            let o = BatchObject::decode(&get(b, &batch_key(p))).unwrap();
            delete(b, &data_key(&o.events[0].commit));
        }
        Fault::ForkedPosition => {
            // another writer's batch for the same position: different event, a validly signed
            // receipt from the log key over that other history
            let mut o = BatchObject::decode(&get(b, &batch_key(p))).unwrap();
            o.events[0].time_ns += 1;
            let mut t = vesdb_core::merkle::MerkleTree::new();
            for q in starts.iter().filter(|&&q| q < p) {
                for e in BatchObject::decode(&get(b, &batch_key(*q))).unwrap().events {
                    t.push(e.leaf());
                }
            }
            for e in &o.events {
                t.push(e.leaf());
            }
            let root = t.root_at(t.size());
            o.receipt.root = root;
            o.receipt.sig = key().sign(&vesdb_core::checkpoint::receipt_message(
                ORIGIN,
                o.receipt.size,
                &root,
            ));
            put(b, &batch_key(p), o.encode());
        }
        Fault::LostAckedWrite => {
            let last = *starts.iter().max().unwrap();
            let _ = size;
            delete(b, &batch_key(last));
        }
        Fault::WrongCosignature => {
            let other = HybridKey::from_seed("witness.example", &[11; 32]);
            let k = cosig_key(size, "witness.example");
            let mut c: CosigObject = serde_json::from_slice(&get(b, &k)).unwrap();
            c.sig = other.sign(b"not the checkpoint");
            put(b, &k, serde_json::to_vec(&c).unwrap());
        }
    }
}

fn detect(b: &Arc<InMemory>) -> bool {
    let mut be = backend(b);
    let r = verify_bucket(&mut be, ORIGIN, &key().public(), &[witness().public()], 1).unwrap();
    !r.ok
}

fn mcc(tp: f64, tn: f64, fp: f64, fn_: f64) -> f64 {
    let d = ((tp + fp) * (tp + fn_) * (tn + fp) * (tn + fn_)).sqrt();
    if d == 0.0 {
        0.0
    } else {
        (tp * tn - fp * fn_) / d
    }
}

#[test]
fn fault_detection_mcc_is_one() {
    let runs_per_class = 240u64; // >= 200 per class
    let mut rng = Rng(0x5EED_1234_ABCD_EF01);
    let (mut tp, mut tn, mut fp, mut fn_) = (0u64, 0u64, 0u64, 0u64);
    let mut per_fault = [(0u64, 0u64); 6];
    for run in 0..2 * runs_per_class {
        let (bucket, starts, size) = clean_run(&mut rng);
        let faulty = run % 2 == 1;
        if faulty {
            let i = ((run / 2) % 6) as usize;
            inject(&bucket, &starts, size, FAULTS[i], &mut rng);
            let flagged = detect(&bucket);
            per_fault[i].0 += 1;
            per_fault[i].1 += flagged as u64;
            if flagged {
                tp += 1
            } else {
                fn_ += 1
            }
        } else if detect(&bucket) {
            fp += 1;
        } else {
            tn += 1;
        }
    }
    let m = mcc(tp as f64, tn as f64, fp as f64, fn_ as f64);
    eprintln!("fault injection: TP {tp} TN {tn} FP {fp} FN {fn_}  MCC {m:.4}");
    for (i, (n, d)) in per_fault.iter().enumerate() {
        eprintln!("  {:?}: detected {d}/{n}", FAULTS[i]);
    }
    assert!(tp + fn_ >= 200 && tn + fp >= 200);
    assert_eq!((fp, fn_), (0, 0));
    assert_eq!(m, 1.0);
}
