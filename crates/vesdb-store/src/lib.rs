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

pub mod frames;

use std::collections::{BTreeMap, HashSet};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use vesdb_core::{
    bundle::{Bundle, BundleItem, BUNDLE_FORMAT},
    checkpoint::{receipt_message, Checkpoint, Receipt},
    crypto::{HybridKey, PublicKey},
    encoding::{commitment, compat_hash_v2, EventMeta, ZERO_HASH_HEX},
    merkle::MerkleTree,
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
        }
    }
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

#[derive(Clone, Copy, Debug)]
struct PayloadSlot {
    offset: u64,
    redacted: bool,
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

struct Files {
    events: File,
    payloads: File,
    receipts: File,
    checkpoints: File,
    _lock: File,
}

pub struct Store {
    cfg: StoreConfig,
    files: Files,
    events: Vec<EventMeta>,
    tree: MerkleTree,
    slots: Vec<PayloadSlot>,
    by_subject: BTreeMap<String, Vec<u64>>,
    receipts: Vec<Receipt>,
    checkpoints: Vec<Checkpoint>,
    read_only: bool,
    failed: Option<String>,
    /// bumps on every redaction (lets caches of payloads know they are stale)
    redactions: u64,
}

/// Read/write WITHOUT `O_APPEND`: on Linux `pwrite` ignores the offset on an O_APPEND file, which
/// would turn in-place redaction into an append. [`frames::append`] seeks to the end explicitly.
fn open_rw(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

fn set_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640));
}

/// Load a framed file, truncating a torn tail; refuses damaged files.
fn load_frames(file: &mut File, name: &str) -> Result<Vec<frames::Frame>, StoreError> {
    let scan = frames::scan(file)?;
    if scan.damaged {
        return Err(StoreError::Damaged(format!(
            "{name}: bad frame at offset {} followed by more data",
            scan.good_len
        )));
    }
    if scan.trailing > 0 {
        file.set_len(scan.good_len)?;
        file.sync_all()?;
    }
    Ok(scan.frames)
}

impl Store {
    pub fn open(cfg: StoreConfig) -> Result<Self, StoreError> {
        std::fs::create_dir_all(&cfg.dir)?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&cfg.dir, std::fs::Permissions::from_mode(0o750));
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(cfg.dir.join("lock.vesdb"))?;
        if lock.try_lock().is_err() {
            return Err(StoreError::Locked);
        }
        let mut files = Files {
            events: open_rw(&cfg.dir.join("events.log"))?,
            payloads: open_rw(&cfg.dir.join("payloads.log"))?,
            receipts: open_rw(&cfg.dir.join("receipts.log"))?,
            checkpoints: open_rw(&cfg.dir.join("checkpoints.log"))?,
            _lock: lock,
        };
        for f in [
            "events.log",
            "payloads.log",
            "receipts.log",
            "checkpoints.log",
            "lock.vesdb",
        ] {
            set_mode(&cfg.dir.join(f));
        }

        // events
        let mut events = Vec::new();
        for (i, fr) in load_frames(&mut files.events, "events.log")?
            .into_iter()
            .enumerate()
        {
            let m: EventMeta = serde_json::from_slice(&fr.body)
                .map_err(|e| StoreError::Damaged(format!("events.log frame {i}: {e}")))?;
            if m.id != i as u64 {
                return Err(StoreError::Damaged(format!(
                    "events.log: frame {i} carries id {}",
                    m.id
                )));
            }
            events.push(m);
        }
        // payloads: one per event, in order; extra (unacknowledged) payloads are dropped
        let pframes = load_frames(&mut files.payloads, "payloads.log")?;
        if pframes.len() < events.len() {
            return Err(StoreError::Damaged(format!(
                "payloads.log has {} payloads for {} events",
                pframes.len(),
                events.len()
            )));
        }
        let mut slots = Vec::with_capacity(events.len());
        for (i, fr) in pframes.iter().enumerate().take(events.len()) {
            let id = u64::from_be_bytes(fr.body[..8].try_into().unwrap());
            if id != i as u64 {
                return Err(StoreError::Damaged(format!(
                    "payloads.log frame {i} carries id {id}"
                )));
            }
            slots.push(PayloadSlot {
                offset: fr.offset,
                redacted: fr.body[8] == 1,
            });
        }
        if pframes.len() > events.len() {
            files.payloads.set_len(pframes[events.len()].offset)?;
            files.payloads.sync_all()?;
        }
        let mut receipts: Vec<Receipt> = Vec::new();
        for fr in load_frames(&mut files.receipts, "receipts.log")? {
            let r: Receipt = serde_json::from_slice(&fr.body)
                .map_err(|e| StoreError::Damaged(format!("receipts.log: {e}")))?;
            if r.size <= events.len() as u64 {
                receipts.push(r);
            }
        }
        let mut checkpoints = Vec::new();
        for fr in load_frames(&mut files.checkpoints, "checkpoints.log")? {
            let c: Checkpoint = serde_json::from_slice(&fr.body)
                .map_err(|e| StoreError::Damaged(format!("checkpoints.log: {e}")))?;
            if c.size <= events.len() as u64 {
                checkpoints.push(c);
            }
        }

        let tree = MerkleTree::from_leaves(events.iter().map(|e| e.leaf()));
        let mut by_subject: BTreeMap<String, Vec<u64>> = BTreeMap::new();
        for e in &events {
            by_subject.entry(e.subject.clone()).or_default().push(e.id);
        }
        let mut store = Store {
            cfg,
            files,
            events,
            tree,
            slots,
            by_subject,
            receipts,
            checkpoints,
            read_only: false,
            failed: None,
            redactions: 0,
        };
        // Durable but un-receipted tail (crash after event fsync): issue its receipt now.
        let n = store.events.len() as u64;
        if n > 0 && store.receipts.last().map(|r| r.size) != Some(n) {
            store.issue_receipt()?;
        }
        Ok(store)
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
        let slot = self.slots[id as usize];
        let payload = if slot.redacted {
            None
        } else {
            let body = frames::read_body(&self.files.payloads, slot.offset)?;
            let salt: Hash = body[9..41].try_into().unwrap();
            let data = String::from_utf8(body[41..].to_vec())
                .map_err(|e| StoreError::Damaged(e.to_string()))?;
            Some((salt, data))
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
        frames::append(&mut self.files.receipts, &serde_json::to_vec(&r).unwrap())?;
        self.files.receipts.sync_data()?;
        self.receipts.push(r.clone());
        Ok(r)
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

        // persist: payloads, events, fsync; on any failure roll files back and fail the store
        let ev_len0 = self.files.events.metadata()?.len();
        let pay_len0 = self.files.payloads.metadata()?.len();
        let res: std::io::Result<Vec<u64>> = (|| {
            let mut offs = Vec::with_capacity(pay_bodies.len());
            for b in &pay_bodies {
                offs.push(frames::append(&mut self.files.payloads, b)?);
            }
            for m in &metas {
                frames::append(&mut self.files.events, &serde_json::to_vec(m).unwrap())?;
            }
            self.files.payloads.sync_data()?;
            self.files.events.sync_data()?;
            Ok(offs)
        })();
        let offs = match res {
            Ok(o) => o,
            Err(e) => {
                let _ = self.files.events.set_len(ev_len0);
                let _ = self.files.payloads.set_len(pay_len0);
                self.failed = Some(format!("write failed: {e}"));
                return Err(StoreError::Failed(e.to_string()));
            }
        };
        for (m, off) in metas.iter().zip(offs) {
            self.tree.push(m.leaf());
            self.slots.push(PayloadSlot {
                offset: off,
                redacted: false,
            });
            self.by_subject
                .entry(m.subject.clone())
                .or_default()
                .push(m.id);
            self.events.push(m.clone());
        }
        let receipt = self
            .issue_receipt()
            .inspect_err(|e| self.failed = Some(format!("receipt failed: {e}")))?;
        Ok((metas, receipt))
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
            let slot = self.slots[i as usize];
            if slot.redacted {
                continue;
            }
            let mut body = frames::read_body(&self.files.payloads, slot.offset)?;
            body[8] = 1;
            for b in body[9..].iter_mut() {
                *b = 0;
            }
            frames::rewrite(&self.files.payloads, slot.offset, &body)?;
            self.slots[i as usize].redacted = true;
        }
        self.files.payloads.sync_data()?;
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
        frames::append(
            &mut self.files.checkpoints,
            &serde_json::to_vec(&cp).unwrap(),
        )?;
        self.files.checkpoints.sync_data()?;
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
