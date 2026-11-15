//! `vesdb-store`: the single-writer storage engine.
//!
//! Data directory layout (all files framed, see [`frames`]):
//!
//! | file              | contents                                                        |
//! |-------------------|-----------------------------------------------------------------|
//! | `lock.vesdb`      | exclusive lock while a server owns the directory                |
//! | `events.log`      | one JSON [`EventMeta`] per event, in id order                   |
//! | `payloads.log`    | `[u64 id][u8 flag][32 salt][data]`, flag 1 = redacted (zeroed)  |
//! | `receipts.log`    | JSON [`Receipt`] per write batch                                |
//! | `checkpoints.log` | JSON [`Checkpoint`] (re-appended when cosignatures arrive)      |
//!
//! Write order per batch: payloads → events → fsync both → sign receipt → append + fsync receipt
//! → acknowledge. Leaves never contain payload bytes, so redaction rewrites `payloads.log` in
//! place without touching any leaf, root, receipt or checkpoint.
//!
//! The same engine runs on object storage ([`backend::ObjectBackend`]): one batch object per
//! write, created only if new, so two servers can share a bucket and the bucket decides who
//! writes. A server whose create is refused steps down to standby ([`Store::is_standby`]), catches
//! up with [`Store::catch_up`] and answers with the retryable [`StoreError::Conflict`].

pub mod backend;
pub mod bucket;
pub mod frames;

pub use backend::{Backend, FileBackend, ObjectBackend};

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use vesdb_core::{
    bundle::{Bundle, BundleItem, BUNDLE_FORMAT},
    checkpoint::{receipt_message, Checkpoint, Receipt},
    crypto::{HybridKey, PublicKey},
    encoding::{commitment, compat_hash_v2, EventMeta, ZERO_HASH_HEX},
    merkle::MerkleTree,
    objects::{BatchObject, IdemEntry, IdemRecord, SnapshotObject, SNAPSHOT_FORMAT},
    random_bytes,
    validate::{self, InputError},
    Hash,
};

pub const SYSTEM_SUBJECT: &str = "/system/redactions";
pub const T_REDACTION_REQUESTED: &str = "io.vesdb.system.redaction-requested";
pub const T_REDACTION_COMPLETED: &str = "io.vesdb.system.redaction-completed";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("data directory is locked by another server")]
    Locked,
    #[error("store damaged: {0}")]
    Damaged(String),
    #[error("{err} (event {index})")]
    Input { err: InputError, index: usize },
    #[error("events-missing")]
    EventsMissing,
    #[error("precondition-violated (precondition {index})")]
    PreconditionViolated { index: usize },
    #[error("store-read-only")]
    ReadOnly,
    #[error("store-failed: {0}")]
    Failed(String),
    #[error("event-id-unknown: {0}")]
    UnknownEvent(u64),
    #[error("{0}")]
    Invalid(String),
    #[error("writer-conflict: another server wrote position {position}; this one stepped down")]
    Conflict { position: u64 },
    #[error("store-not-writer: this server is a standby")]
    NotWriter,
    #[error("idempotency-key-reused: the key was used for a different request")]
    IdempotencyMismatch,
}

impl StoreError {
    /// EventSourcingDB-style error slug.
    pub fn slug(&self) -> String {
        match self {
            StoreError::Input { err, .. } => err.slug(),
            StoreError::EventsMissing => "events-missing".into(),
            StoreError::PreconditionViolated { .. } => "precondition-violated".into(),
            StoreError::ReadOnly => "store-read-only".into(),
            StoreError::Failed(_) | StoreError::Damaged(_) => "store-failed".into(),
            StoreError::Io(_) => "file-unreadable".into(),
            StoreError::Locked => "store-locked".into(),
            StoreError::UnknownEvent(_) => "event-id-unknown".into(),
            StoreError::Invalid(_) => "request-invalid".into(),
            StoreError::Conflict { .. } => "writer-conflict".into(),
            StoreError::NotWriter => "store-not-writer".into(),
            StoreError::IdempotencyMismatch => "idempotency-key-reused".into(),
        }
    }

    /// The client may retry the same request (with its idempotency key) on another server.
    pub fn retryable(&self) -> bool {
        matches!(self, StoreError::Conflict { .. } | StoreError::NotWriter)
    }
}

/// How long idempotency keys are remembered.
pub const IDEMPOTENCY_WINDOW_NS: u64 = 24 * 3600 * 1_000_000_000;

/// Result of [`Store::write_ext`].
#[derive(Clone, Debug)]
pub struct WriteOutcome {
    pub events: Vec<EventMeta>,
    pub receipt: Receipt,
    /// The idempotency key was seen before: these are the original events, nothing was written.
    pub replayed: bool,
}

/// An event as submitted by a client.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub source: String,
    pub subject: String,
    pub ty: String,
    /// Exact JSON text of `data` (stored and hashed byte for byte).
    pub data: String,
    pub traceparent: Option<String>,
    pub tracestate: Option<String>,
}

#[derive(Clone, Debug)]
pub enum Precondition {
    IsSubjectPristine {
        subject: String,
        recursive: bool,
    },
    IsSubjectPopulated {
        subject: String,
        recursive: bool,
    },
    IsSubjectOnEventId {
        subject: String,
        event_id: u64,
        recursive: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Order {
    Chronological,
    Antichronological,
}

#[derive(Clone, Copy, Debug)]
pub struct Bound {
    pub id: u64,
    pub inclusive: bool,
}

#[derive(Clone, Debug)]
pub struct FromLatest {
    pub subject: String,
    pub ty: String,
    /// true = read everything if missing, false = read nothing
    pub read_everything_if_missing: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ReadOptions {
    pub recursive: bool,
    pub order: Option<Order>,
    pub lower: Option<Bound>,
    pub upper: Option<Bound>,
    pub from_latest: Option<FromLatest>,
}

/// A stored event with its payload (if not redacted).
#[derive(Clone, Debug)]
pub struct StoredEvent {
    pub meta: EventMeta,
    pub payload: Option<(Hash, String)>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Finding {
    pub severity: &'static str,
    pub description: String,
}

pub struct StoreConfig {
    pub dir: PathBuf,
    /// Log origin (C2SP checkpoint origin line), e.g. `rig-07.vg360.example/log`.
    pub origin: String,
    /// `source` used for system events (redactions).
    pub system_source: String,
    /// Event types that carry personal data: no unsalted compat hash is stored for them.
    pub pii_types: HashSet<String>,
    pub key: HybridKey,
}

pub struct Store {
    cfg: StoreConfig,
    backend: Box<dyn Backend>,
    events: Vec<EventMeta>,
    tree: MerkleTree,
    redacted: Vec<bool>,
    by_subject: BTreeMap<String, Vec<u64>>,
    receipts: Vec<Receipt>,
    checkpoints: Vec<Checkpoint>,
    idem: HashMap<String, IdemEntry>,
    read_only: bool,
    standby: bool,
    failed: Option<String>,
    /// bumps on every redaction (lets caches of payloads know they are stale)
    redactions: u64,
    snapshot_every: Option<u64>,
    last_snapshot: u64,
    load_reads: u64,
}

impl Store {
    /// Open the file store in `cfg.dir`.
    pub fn open(cfg: StoreConfig) -> Result<Self, StoreError> {
        let b = FileBackend::open(&cfg.dir)?;
        Self::open_with(cfg, Box::new(b))
    }

    /// Open on any backend. A shared backend (object storage) opens as a standby: call
    /// [`Store::become_writer`] once this server is the writer.
    pub fn open_with(cfg: StoreConfig, mut backend: Box<dyn Backend>) -> Result<Self, StoreError> {
        let l = backend.load()?;
        let mut tree = MerkleTree::new();
        let mut by_subject: BTreeMap<String, Vec<u64>> = BTreeMap::new();
        for e in &l.events {
            tree.push(e.leaf());
            by_subject.entry(e.subject.clone()).or_default().push(e.id);
        }
        let standby = backend.shared();
        let mut store = Store {
            cfg,
            backend,
            tree,
            redacted: l.redacted,
            by_subject,
            receipts: l.receipts,
            checkpoints: l.checkpoints,
            idem: l.idem.into_iter().map(|e| (e.key.clone(), e)).collect(),
            events: l.events,
            read_only: false,
            standby,
            failed: None,
            redactions: 0,
            snapshot_every: None,
            last_snapshot: 0,
            load_reads: l.reads,
        };
        store.last_snapshot = store.len();
        // On a shared store, refuse to serve (or extend) a log whose receipts do not match its
        // events. A file store opens anyway, so `verify-store` can report what changed.
        let shared = store.backend.shared();
        for r in store.receipts.iter().filter(|_| shared) {
            if r.size > store.len()
                || store.tree.root_at(r.size) != r.root
                || !r.verify(&store.cfg.origin, &store.cfg.key.public())
            {
                return Err(StoreError::Damaged(format!(
                    "receipt size {} does not match the log",
                    r.size
                )));
            }
        }
        // Durable but un-receipted tail (file store, crash after event fsync): issue its receipt.
        let n = store.events.len() as u64;
        if n > 0 && store.receipts.last().map(|r| r.size) != Some(n) {
            store.issue_receipt()?;
        }
        Ok(store)
    }

    /// Write a snapshot to the backend every `n` events (object stores; no-op for files).
    pub fn set_snapshot_every(&mut self, n: Option<u64>) {
        self.snapshot_every = n.filter(|&n| n > 0);
    }

    /// Objects (or files) read at open: the restart cost.
    pub fn load_reads(&self) -> u64 {
        self.load_reads
    }

    pub fn backend_description(&self) -> String {
        self.backend.describe()
    }

    // ---------------------------------------------------------------- roles

    pub fn is_standby(&self) -> bool {
        self.standby
    }

    /// Step down: stop accepting writes (another server writes now).
    pub fn step_down(&mut self) {
        self.standby = true;
    }

    /// Catch up with everything stored, then accept writes at the next position.
    pub fn become_writer(&mut self) -> Result<u64, StoreError> {
        self.catch_up()?;
        self.standby = false;
        Ok(self.len())
    }

    /// Apply batches (and checkpoints) stored since this server's last position. Returns the
    /// number of events applied. The standby never re-runs a write: it loads the bytes the
    /// writer stored and checks each receipt against its own tree.
    pub fn catch_up(&mut self) -> Result<u64, StoreError> {
        let before = self.len();
        for b in self.backend.tail(self.len())? {
            self.apply_batch(b)?;
        }
        let after = self
            .checkpoints
            .last()
            .map_or(0, |c| c.size.saturating_sub(1));
        for cp in self.backend.checkpoints_after(after)? {
            if cp.size > self.len() {
                continue;
            }
            match self.checkpoints.iter_mut().find(|c| c.size == cp.size) {
                Some(c) => c.cosigs.extend(cp.cosigs),
                None => self.checkpoints.push(cp),
            }
        }
        self.checkpoints.sort_by_key(|c| c.size);
        Ok(self.len() - before)
    }

    /// Apply one stored batch (Lean: `VesdbStore.apply`): it must start at this store's length,
    /// and its receipt must be signed by the log key over this store's new root.
    pub fn apply_batch(&mut self, b: BatchObject) -> Result<(), StoreError> {
        if b.first != self.len() {
            return Err(StoreError::Damaged(format!(
                "batch {} applied at position {}",
                b.first,
                self.len()
            )));
        }
        if !b.receipt.verify(&self.cfg.origin, &self.public_key()) {
            return Err(StoreError::Damaged(format!(
                "batch {}: receipt signature invalid",
                b.first
            )));
        }
        let base = self.len();
        for e in &b.events {
            self.tree.push(e.leaf());
        }
        if self.tree.root_at(self.len_tree()) != b.receipt.root {
            self.tree.truncate(base);
            return Err(StoreError::Damaged(format!(
                "batch {}: receipt root does not match the events",
                b.first
            )));
        }
        if let Some(r) = &b.idem {
            self.idem.insert(
                r.key.clone(),
                IdemEntry {
                    key: r.key.clone(),
                    request: r.request.clone(),
                    first: b.first,
                    count: b.events.len() as u64,
                    time_ns: b.events[0].time_ns,
                },
            );
        }
        let redaction_done: Vec<u64> = b
            .events
            .iter()
            .filter(|e| e.ty == T_REDACTION_COMPLETED)
            .map(|e| e.id)
            .collect();
        for e in b.events {
            self.by_subject
                .entry(e.subject.clone())
                .or_default()
                .push(e.id);
            self.redacted.push(false);
            self.events.push(e);
        }
        self.receipts.push(b.receipt);
        for id in redaction_done {
            if let Ok(StoredEvent {
                payload: Some((_, d)),
                ..
            }) = self.event(id)
            {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&d) {
                    for i in v["ids"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|x| x.as_u64())
                    {
                        if let Some(r) = self.redacted.get_mut(i as usize) {
                            *r = true;
                        }
                    }
                    self.redactions += 1;
                }
            }
        }
        Ok(())
    }

    /// Raw payload body `[u64 id][u8 flag][32 salt][data]` (migration).
    pub fn payload_body(&self, id: u64) -> Result<Vec<u8>, StoreError> {
        let m = self
            .events
            .get(id as usize)
            .ok_or(StoreError::UnknownEvent(id))?;
        self.backend.read_body(id, m)
    }

    /// Idempotency key of the batch starting at `first`, if any.
    pub fn idem_for(&self, first: u64) -> Option<IdemRecord> {
        self.idem
            .values()
            .find(|e| e.first == first)
            .map(|e| IdemRecord {
                key: e.key.clone(),
                request: e.request.clone(),
            })
    }

    fn len_tree(&self) -> u64 {
        self.tree.size()
    }

    /// Store a snapshot of the in-memory state (object stores read it at restart).
    pub fn snapshot(&mut self) -> Result<u64, StoreError> {
        let s = SnapshotObject {
            format: SNAPSHOT_FORMAT.into(),
            size: self.len(),
            events: self.events.clone(),
            receipts: self.receipts.clone(),
            redacted: self
                .redacted
                .iter()
                .enumerate()
                .filter(|(_, &r)| r)
                .map(|(i, _)| i as u64)
                .collect(),
            idem: self.idem.values().cloned().collect(),
            root: self.tree.root_at(self.len()),
        };
        self.backend.put_snapshot(&s)?;
        self.last_snapshot = s.size;
        Ok(s.size)
    }

    // ---------------------------------------------------------------- accessors

    /// `source` used for system events (redactions, sealed time-series chunks).
    pub fn system_source(&self) -> &str {
        &self.cfg.system_source
    }
    pub fn origin(&self) -> &str {
        &self.cfg.origin
    }
    pub fn public_key(&self) -> PublicKey {
        self.cfg.key.public()
    }
    pub fn len(&self) -> u64 {
        self.events.len() as u64
    }
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
    pub fn tree(&self) -> &MerkleTree {
        &self.tree
    }
    pub fn receipts(&self) -> &[Receipt] {
        &self.receipts
    }
    pub fn checkpoints(&self) -> &[Checkpoint] {
        &self.checkpoints
    }
    pub fn meta(&self, id: u64) -> Option<&EventMeta> {
        self.events.get(id as usize)
    }
    pub fn set_read_only(&mut self, ro: bool) {
        self.read_only = ro;
    }
    pub fn is_read_only(&self) -> bool {
        self.read_only || self.failed.is_some()
    }
    pub fn failure(&self) -> Option<&str> {
        self.failed.as_deref()
    }
    pub fn redaction_epoch(&self) -> u64 {
        self.redactions
    }
    pub fn subjects(&self) -> impl Iterator<Item = &String> {
        self.by_subject.keys()
    }

    pub fn event(&self, id: u64) -> Result<StoredEvent, StoreError> {
        let meta = self
            .events
            .get(id as usize)
            .ok_or(StoreError::UnknownEvent(id))?
            .clone();
        let payload = if self.redacted[id as usize] {
            None
        } else {
            let body = self.backend.read_body(id, &meta)?;
            if body.len() < 9 || body[8] == 1 {
                None // redacted (the body's flag is authoritative)
            } else if body.len() < 41 {
                return Err(StoreError::Damaged(format!(
                    "event {id}: payload body truncated"
                )));
            } else {
                let salt: Hash = body[9..41].try_into().unwrap();
                let data = String::from_utf8(body[41..].to_vec())
                    .map_err(|e| StoreError::Damaged(e.to_string()))?;
                Some((salt, data))
            }
        };
        Ok(StoredEvent { meta, payload })
    }

    /// Receipt covering event `id` (the first receipt whose tree contains it).
    pub fn receipt_for(&self, id: u64) -> Option<&Receipt> {
        let i = self.receipts.partition_point(|r| r.size <= id);
        self.receipts.get(i)
    }

    /// Latest checkpoint with at least `k` cosignatures from `witnesses`.
    pub fn latest_cosigned(&self, witnesses: &[PublicKey], k: usize) -> Option<&Checkpoint> {
        self.checkpoints
            .iter()
            .rev()
            .find(|c| c.valid_cosigners(witnesses).len() >= k)
    }

    // ---------------------------------------------------------------- preconditions

    fn ids_under(&self, subject: &str, recursive: bool) -> Vec<u64> {
        if !recursive {
            return self.by_subject.get(subject).cloned().unwrap_or_default();
        }
        let mut ids: Vec<u64> = self
            .by_subject
            .range(subject.to_string()..)
            .take_while(|(s, _)| subject == "/" || s.starts_with(subject))
            .filter(|(s, _)| validate::under(s, subject, true))
            .flat_map(|(_, v)| v.iter().copied())
            .collect();
        if subject == "/" {
            ids = (0..self.len()).collect();
        }
        ids.sort_unstable();
        ids
    }

    /// Index of the first precondition that does not hold, if any.
    pub fn first_failing(&self, pcs: &[Precondition]) -> Option<usize> {
        pcs.iter().position(|pc| !self.holds(pc))
    }

    fn holds(&self, pc: &Precondition) -> bool {
        match pc {
            Precondition::IsSubjectPristine { subject, recursive } => {
                self.ids_under(subject, *recursive).is_empty()
            }
            Precondition::IsSubjectPopulated { subject, recursive } => {
                !self.ids_under(subject, *recursive).is_empty()
            }
            Precondition::IsSubjectOnEventId {
                subject,
                event_id,
                recursive,
            } => self.ids_under(subject, *recursive).last() == Some(event_id),
        }
    }

    // ---------------------------------------------------------------- the sequencer

    fn ensure_writable(&self) -> Result<(), StoreError> {
        if let Some(f) = &self.failed {
            return Err(StoreError::Failed(f.clone()));
        }
        if self.standby {
            return Err(StoreError::NotWriter);
        }
        if self.read_only {
            return Err(StoreError::ReadOnly);
        }
        Ok(())
    }

    fn issue_receipt(&mut self) -> Result<Receipt, StoreError> {
        let n = self.len();
        let root = self.tree.root_at(n);
        let sig = self
            .cfg
            .key
            .sign(&receipt_message(&self.cfg.origin, n, &root));
        let r = Receipt { size: n, root, sig };
        self.backend.store_receipt(&r)?;
        self.receipts.push(r.clone());
        Ok(r)
    }

    fn sign_receipt(&self, n: u64) -> Receipt {
        let root = self.tree.root_at(n);
        let sig = self
            .cfg
            .key
            .sign(&receipt_message(&self.cfg.origin, n, &root));
        Receipt { size: n, root, sig }
    }

    /// One atomic write (Lean: `Vesdb.append`): all events or none, preconditions evaluated
    /// against the state the batch is appended to, gapless ids, monotone time, receipt issued
    /// before return.
    pub fn write(
        &mut self,
        now_ns: u64,
        cands: Vec<Candidate>,
        pcs: &[Precondition],
    ) -> Result<(Vec<EventMeta>, Receipt), StoreError> {
        let o = self.write_ext(now_ns, cands, pcs, None)?;
        Ok((o.events, o.receipt))
    }

    /// [`Store::write`] with an optional idempotency key (Lean: `VesdbStore.idempotent`): a key
    /// seen within [`IDEMPOTENCY_WINDOW_NS`] returns the original events and receipt and writes
    /// nothing; the same key with a different request is refused.
    pub fn write_ext(
        &mut self,
        now_ns: u64,
        cands: Vec<Candidate>,
        pcs: &[Precondition],
        idem: Option<IdemRecord>,
    ) -> Result<WriteOutcome, StoreError> {
        if let Some(r) = &idem {
            if let Some(e) = self.idem.get(&r.key) {
                if now_ns.saturating_sub(e.time_ns) <= IDEMPOTENCY_WINDOW_NS {
                    if e.request != r.request {
                        return Err(StoreError::IdempotencyMismatch);
                    }
                    let events =
                        self.events[e.first as usize..(e.first + e.count) as usize].to_vec();
                    let receipt = self.receipt_for(e.first).cloned().ok_or_else(|| {
                        StoreError::Damaged("receipt missing for a stored batch".into())
                    })?;
                    return Ok(WriteOutcome {
                        events,
                        receipt,
                        replayed: true,
                    });
                }
            }
        }
        self.ensure_writable()?;
        if cands.is_empty() {
            return Err(StoreError::EventsMissing);
        }
        let mut normalized = Vec::with_capacity(cands.len());
        for (index, mut c) in cands.into_iter().enumerate() {
            let err = |err| StoreError::Input { err, index };
            c.subject = validate::subject(&c.subject).map_err(err)?;
            validate::source(&c.source).map_err(err)?;
            validate::event_type(&c.ty).map_err(err)?;
            validate::data(&c.data).map_err(err)?;
            if let Some(tp) = &c.traceparent {
                validate::traceparent(tp).map_err(err)?;
            }
            match (&c.traceparent, &c.tracestate) {
                (None, Some(_)) => return Err(err(InputError::TracestateWithoutTraceparent)),
                (_, Some(ts)) => validate::tracestate(ts).map_err(err)?,
                _ => {}
            }
            if c.data.len() + c.subject.len() + c.source.len() + c.ty.len() + 400
                > validate::MAX_EVENT_BYTES
            {
                return Err(err(InputError::EventTooLarge));
            }
            normalized.push(c);
        }
        for (index, pc) in pcs.iter().enumerate() {
            if !self.holds(pc) {
                return Err(StoreError::PreconditionViolated { index });
            }
        }

        let t = now_ns.max(self.events.last().map_or(0, |e| e.time_ns));
        let base = self.len();
        let mut metas = Vec::with_capacity(normalized.len());
        let mut pay_bodies = Vec::with_capacity(normalized.len());
        let mut prev = self
            .events
            .last()
            .map_or(ZERO_HASH_HEX.to_string(), |e| e.hash.clone());
        for (j, c) in normalized.iter().enumerate() {
            let salt = random_bytes::<32>();
            let mut m = EventMeta {
                id: base + j as u64,
                time_ns: t,
                source: c.source.clone(),
                subject: c.subject.clone(),
                ty: c.ty.clone(),
                traceparent: c.traceparent.as_ref().map(|s| s.to_ascii_lowercase()),
                tracestate: c.tracestate.clone(),
                commit: commitment(&salt, c.data.as_bytes()),
                predecessorhash: prev.clone(),
                hash: String::new(),
            };
            m.hash = if self.cfg.pii_types.contains(&m.ty) {
                m.leaf_hash_string()
            } else {
                compat_hash_v2(&m, c.data.as_bytes())
            };
            prev = m.hash.clone();
            let mut body = Vec::with_capacity(41 + c.data.len());
            body.extend_from_slice(&m.id.to_be_bytes());
            body.push(0);
            body.extend_from_slice(&salt);
            body.extend_from_slice(c.data.as_bytes());
            pay_bodies.push(body);
            metas.push(m);
        }

        // the new root and its signed receipt, then one durable batch
        for m in &metas {
            self.tree.push(m.leaf());
        }
        let n = base + metas.len() as u64;
        let receipt = self.sign_receipt(n);
        let batch = backend::Batch {
            first: base,
            events: &metas,
            bodies: &pay_bodies,
            receipt: &receipt,
            idem: idem.as_ref(),
            time_ns: t,
        };
        if let Err(e) = self.backend.append(&batch) {
            self.tree.truncate(base);
            match e {
                StoreError::Conflict { .. } => self.standby = true,
                _ => self.failed = Some(format!("write failed: {e}")),
            }
            return Err(e);
        }
        for m in &metas {
            self.redacted.push(false);
            self.by_subject
                .entry(m.subject.clone())
                .or_default()
                .push(m.id);
            self.events.push(m.clone());
        }
        self.receipts.push(receipt.clone());
        if let Some(r) = idem {
            self.idem
                .retain(|_, e| t.saturating_sub(e.time_ns) <= IDEMPOTENCY_WINDOW_NS);
            self.idem.insert(
                r.key.clone(),
                IdemEntry {
                    key: r.key,
                    request: r.request,
                    first: base,
                    count: metas.len() as u64,
                    time_ns: t,
                },
            );
        }
        if let Some(k) = self.snapshot_every {
            if self.len() - self.last_snapshot >= k {
                // best effort: a missing snapshot only slows the next restart
                let _ = self.snapshot();
            }
        }
        Ok(WriteOutcome {
            events: metas,
            receipt,
            replayed: false,
        })
    }

    // ---------------------------------------------------------------- reads

    /// Event ids matching a read request (EventSourcingDB `read-events` semantics).
    pub fn read_ids(&self, subject: &str, o: &ReadOptions) -> Result<Vec<u64>, StoreError> {
        let subject =
            validate::subject(subject).map_err(|err| StoreError::Input { err, index: 0 })?;
        let mut ids = self.ids_under(&subject, o.recursive);
        if let Some(fl) = &o.from_latest {
            let fs = validate::subject(&fl.subject)
                .map_err(|err| StoreError::Input { err, index: 0 })?;
            let start = self.by_subject.get(&fs).and_then(|v| {
                v.iter()
                    .rev()
                    .find(|&&i| self.events[i as usize].ty == fl.ty)
                    .copied()
            });
            match start {
                Some(s) => ids.retain(|&i| i >= s),
                None if !fl.read_everything_if_missing => ids.clear(),
                None => {}
            }
        }
        if let Some(b) = o.lower {
            ids.retain(|&i| if b.inclusive { i >= b.id } else { i > b.id });
        }
        if let Some(b) = o.upper {
            ids.retain(|&i| if b.inclusive { i <= b.id } else { i < b.id });
        }
        if o.order == Some(Order::Antichronological) {
            ids.reverse();
        }
        Ok(ids)
    }

    // ---------------------------------------------------------------- redaction

    /// Erase payload and salt of `ids` (Lean: `redaction_preserves_root`). The act is recorded
    /// as two system events; leaves, receipts and checkpoints are untouched.
    pub fn redact(&mut self, now_ns: u64, ids: &[u64], reason: &str) -> Result<(), StoreError> {
        self.ensure_writable()?;
        for &i in ids {
            if i >= self.len() {
                return Err(StoreError::UnknownEvent(i));
            }
        }
        let src = self.cfg.system_source.clone();
        let mk = |ty: &str, data: serde_json::Value| Candidate {
            source: src.clone(),
            subject: SYSTEM_SUBJECT.into(),
            ty: ty.into(),
            data: data.to_string(),
            traceparent: None,
            tracestate: None,
        };
        self.write(
            now_ns,
            vec![mk(
                T_REDACTION_REQUESTED,
                serde_json::json!({"ids": ids, "reason": reason}),
            )],
            &[],
        )?;
        for &i in ids {
            if self.redacted[i as usize] {
                continue;
            }
            let meta = self.events[i as usize].clone();
            self.backend.redact(i, &meta)?;
            self.redacted[i as usize] = true;
        }
        self.backend.sync_redactions()?;
        self.redactions += 1;
        self.write(
            now_ns,
            vec![mk(T_REDACTION_COMPLETED, serde_json::json!({"ids": ids}))],
            &[],
        )?;
        Ok(())
    }

    // ---------------------------------------------------------------- checkpoints

    /// Sign a checkpoint of the current tree and persist it.
    pub fn checkpoint(&mut self, now_ns: u64) -> Result<Checkpoint, StoreError> {
        let n = self.len();
        let root = self.tree.root_at(n);
        let body = vesdb_core::checkpoint::checkpoint_body(&self.cfg.origin, n, &root);
        let cp = Checkpoint {
            origin: self.cfg.origin.clone(),
            size: n,
            root,
            time_ns: now_ns,
            log_sig: self.cfg.key.sign(&body),
            cosigs: Default::default(),
        };
        self.record_checkpoint(cp.clone())?;
        Ok(cp)
    }

    /// Persist a checkpoint (again) after cosignatures were added.
    pub fn record_checkpoint(&mut self, cp: Checkpoint) -> Result<(), StoreError> {
        self.backend.put_checkpoint(&cp)?;
        if let Some(last) = self.checkpoints.last_mut() {
            if last.size == cp.size && last.root == cp.root {
                *last = cp;
                return Ok(());
            }
        }
        self.checkpoints.push(cp);
        Ok(())
    }

    // ---------------------------------------------------------------- evidence

    /// Build an evidence bundle for `ids` against checkpoint `cp` (which must cover them).
    pub fn bundle(&self, ids: &[u64], cp: &Checkpoint) -> Result<Bundle, StoreError> {
        let mut items = Vec::with_capacity(ids.len());
        for &id in ids {
            if id >= cp.size {
                return Err(StoreError::Invalid(format!(
                    "event {id} is not covered by checkpoint size {}",
                    cp.size
                )));
            }
            let ev = self.event(id)?;
            let receipt = self
                .receipt_for(id)
                .ok_or(StoreError::UnknownEvent(id))?
                .clone();
            items.push(BundleItem {
                inclusion: self.tree.inclusion_proof(id, cp.size),
                receipt_inclusion: self.tree.inclusion_proof(id, receipt.size),
                receipt,
                salt: ev.payload.as_ref().map(|(s, _)| s.to_vec()),
                data: ev.payload.map(|(_, d)| d),
                event: ev.meta,
            });
        }
        Ok(Bundle {
            format: BUNDLE_FORMAT.into(),
            checkpoint: cp.clone(),
            items,
        })
    }

    // ---------------------------------------------------------------- verification

    /// Full self-check (`verify-store`): ids, time, compat chain, commitments, receipts and
    /// checkpoints against the tree rebuilt from what is on disk.
    pub fn verify(&self) -> Result<Vec<Finding>, StoreError> {
        let mut f = Vec::new();
        let mut err = |d: String| {
            if f.len() < 100 {
                f.push(Finding {
                    severity: "error",
                    description: d,
                })
            }
        };
        let pk = self.public_key();
        let mut prev = ZERO_HASH_HEX.to_string();
        let mut prev_t = 0u64;
        for (i, m) in self.events.iter().enumerate() {
            if m.id != i as u64 {
                err(format!("event at position {i} has id {}", m.id));
            }
            if m.time_ns < prev_t {
                err(format!("event {i}: time goes backwards"));
            }
            prev_t = m.time_ns;
            if m.predecessorhash != prev {
                err(format!(
                    "event {i}: compat predecessorhash does not match event {}",
                    i.saturating_sub(1)
                ));
            }
            let ev = self.event(i as u64)?;
            if let Some((salt, data)) = &ev.payload {
                if commitment(salt, data.as_bytes()) != m.commit {
                    err(format!("event {i}: payload does not match its commitment"));
                }
                if m.has_compat_hash() && compat_hash_v2(m, data.as_bytes()) != m.hash {
                    err(format!("event {i}: wrong compat hash"));
                }
            }
            if !m.has_compat_hash() && m.hash != m.leaf_hash_string() {
                err(format!("event {i}: wrong leaf hash string"));
            }
            prev = m.hash.clone();
        }
        for r in &self.receipts {
            if !r.verify(&self.cfg.origin, &pk) {
                err(format!("receipt size {}: signature invalid", r.size));
            } else if r.size > self.len() || self.tree.root_at(r.size) != r.root {
                err(format!("receipt size {}: signed root does not match the stored events (history changed)", r.size));
            }
        }
        for c in &self.checkpoints {
            if !c.verify_log_sig(&pk) {
                err(format!("checkpoint size {}: signature invalid", c.size));
            } else if c.size > self.len() || self.tree.root_at(c.size) != c.root {
                err(format!("checkpoint size {}: signed root does not match the stored events (history changed)", c.size));
            }
        }
        Ok(f)
    }

    /// Compat `audit-history`: verify the chain and that the anchor (id, hash) still matches.
    pub fn audit(&self, anchor: Option<(u64, String)>) -> Result<Option<(u64, String)>, String> {
        let findings = self.verify().map_err(|e| format!("file-unreadable: {e}"))?;
        if let Some(f) = findings.first() {
            return Err(format!("event-chain-broken: {}", f.description));
        }
        if let Some((id, h)) = anchor {
            let m = self.meta(id).ok_or("last-audited-event-unknown")?;
            if m.hash != h {
                return Err("last-audited-event-mismatched".into());
            }
        }
        Ok(self.events.last().map(|m| (m.id, m.hash.clone())))
    }
}

pub use frames::Scan;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod ha_tests;
