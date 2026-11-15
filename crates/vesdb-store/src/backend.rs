//! Where the log lives. [`Store`](crate::Store) keeps the in-memory state (tree, indexes,
//! receipts) and calls a [`Backend`] for every durable step.
//!
//! * [`FileBackend`]: one local data directory, the files described in the crate docs, written
//!   exactly as before the split (byte for byte), guarded by a file lock.
//! * [`ObjectBackend`]: S3-style object storage (any `object_store` store: S3, GCS, Azure,
//!   RustFS, a local directory, or in memory for tests), using the layout in
//!   [`vesdb_core::objects`]. Every log object is created only if new, so the store itself
//!   decides who may write: a writer whose create is refused gets [`StoreError::Conflict`].

use crate::{frames, StoreError};
use futures::{StreamExt, TryStreamExt};
use object_store::{
    path::Path as OPath, ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload,
};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;
/// `(e_tag, version)` of a stored object, for conditional replace.
pub type ObjectVersion = (Option<String>, Option<String>);

use vesdb_core::{
    checkpoint::{Checkpoint, Receipt},
    encoding::EventMeta,
    objects::{
        batch_key, checkpoint_key, checkpoint_object, cosig_key, data_key, parse_position,
        snapshot_key, BatchObject, CosigObject, IdemEntry, IdemRecord, SnapshotObject,
        BATCH_FORMAT,
    },
};

/// Everything a store holds, as loaded at open.
#[derive(Default)]
pub struct Loaded {
    pub events: Vec<EventMeta>,
    /// Known-redacted events (payload bodies also carry the flag; that one is authoritative).
    pub redacted: Vec<bool>,
    pub receipts: Vec<Receipt>,
    pub checkpoints: Vec<Checkpoint>,
    pub idem: Vec<IdemEntry>,
    /// Number of objects/frames read, for restart-cost measurements.
    pub reads: u64,
}

/// One write batch, as handed to the backend.
pub struct Batch<'a> {
    pub first: u64,
    pub events: &'a [EventMeta],
    /// Payload bodies `[u64 id][u8 flag][32 salt][data]`, one per event.
    pub bodies: &'a [Vec<u8>],
    pub receipt: &'a Receipt,
    pub idem: Option<&'a IdemRecord>,
    pub time_ns: u64,
}

pub trait Backend: Send {
    fn describe(&self) -> String;
    fn load(&mut self) -> Result<Loaded, StoreError>;
    /// Make a batch durable. [`StoreError::Conflict`] when another writer holds the position.
    fn append(&mut self, b: &Batch) -> Result<(), StoreError>;
    /// File stores only: issue the receipt for a durable but un-receipted tail found at open.
    fn store_receipt(&mut self, r: &Receipt) -> Result<(), StoreError>;
    fn read_body(&self, id: u64, meta: &EventMeta) -> Result<Vec<u8>, StoreError>;
    /// Replace a payload body by its redacted form (flag 1, no salt, no data).
    fn redact(&mut self, id: u64, meta: &EventMeta) -> Result<(), StoreError>;
    fn sync_redactions(&mut self) -> Result<(), StoreError>;
    /// Persist a checkpoint and whatever cosignatures it carries (idempotent).
    fn put_checkpoint(&mut self, cp: &Checkpoint) -> Result<(), StoreError>;
    /// Batches stored at positions `from`, `from + len`, … until the next one is missing.
    fn tail(&mut self, from: u64) -> Result<Vec<BatchObject>, StoreError>;
    /// Checkpoints of size > `after`, with their cosignatures.
    fn checkpoints_after(&mut self, after: u64) -> Result<Vec<Checkpoint>, StoreError>;
    fn put_snapshot(&mut self, s: &SnapshotObject) -> Result<(), StoreError>;
    /// Can another server write to the same log (and so may this one lose a race)?
    fn shared(&self) -> bool;
}

// =====================================================================================
// FileBackend
// =====================================================================================

struct Files {
    events: File,
    payloads: File,
    receipts: File,
    checkpoints: File,
    idem: Option<File>,
    _lock: File,
}

pub struct FileBackend {
    dir: PathBuf,
    files: Files,
    /// payload frame offsets, by event id
    offsets: Vec<u64>,
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

impl FileBackend {
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        std::fs::create_dir_all(dir)?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750));
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join("lock.vesdb"))?;
        if lock.try_lock().is_err() {
            return Err(StoreError::Locked);
        }
        let idem_path = dir.join("idempotency.log");
        let files = Files {
            events: open_rw(&dir.join("events.log"))?,
            payloads: open_rw(&dir.join("payloads.log"))?,
            receipts: open_rw(&dir.join("receipts.log"))?,
            checkpoints: open_rw(&dir.join("checkpoints.log"))?,
            // created only when a write first carries an idempotency key
            idem: if idem_path.exists() {
                Some(open_rw(&idem_path)?)
            } else {
                None
            },
            _lock: lock,
        };
        for f in [
            "events.log",
            "payloads.log",
            "receipts.log",
            "checkpoints.log",
            "lock.vesdb",
        ] {
            set_mode(&dir.join(f));
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            files,
            offsets: Vec::new(),
        })
    }
}

impl Backend for FileBackend {
    fn describe(&self) -> String {
        format!("files in {}", self.dir.display())
    }

    fn shared(&self) -> bool {
        false
    }

    fn load(&mut self) -> Result<Loaded, StoreError> {
        let mut l = Loaded::default();
        for (i, fr) in load_frames(&mut self.files.events, "events.log")?
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
            l.events.push(m);
        }
        // payloads: one per event, in order; extra (unacknowledged) payloads are dropped
        let pframes = load_frames(&mut self.files.payloads, "payloads.log")?;
        if pframes.len() < l.events.len() {
            return Err(StoreError::Damaged(format!(
                "payloads.log has {} payloads for {} events",
                pframes.len(),
                l.events.len()
            )));
        }
        self.offsets.clear();
        for (i, fr) in pframes.iter().enumerate().take(l.events.len()) {
            let id = u64::from_be_bytes(fr.body[..8].try_into().unwrap());
            if id != i as u64 {
                return Err(StoreError::Damaged(format!(
                    "payloads.log frame {i} carries id {id}"
                )));
            }
            self.offsets.push(fr.offset);
            l.redacted.push(fr.body[8] == 1);
        }
        if pframes.len() > l.events.len() {
            self.files
                .payloads
                .set_len(pframes[l.events.len()].offset)?;
            self.files.payloads.sync_all()?;
        }
        let n = l.events.len() as u64;
        for fr in load_frames(&mut self.files.receipts, "receipts.log")? {
            let r: Receipt = serde_json::from_slice(&fr.body)
                .map_err(|e| StoreError::Damaged(format!("receipts.log: {e}")))?;
            if r.size <= n {
                l.receipts.push(r);
            }
        }
        for fr in load_frames(&mut self.files.checkpoints, "checkpoints.log")? {
            let c: Checkpoint = serde_json::from_slice(&fr.body)
                .map_err(|e| StoreError::Damaged(format!("checkpoints.log: {e}")))?;
            if c.size <= n {
                // re-appended with cosignatures: keep the latest copy of each size
                match l.checkpoints.last_mut() {
                    Some(last) if last.size == c.size && last.root == c.root => *last = c,
                    _ => l.checkpoints.push(c),
                }
            }
        }
        if let Some(f) = self.files.idem.as_mut() {
            for fr in load_frames(f, "idempotency.log")? {
                let e: IdemEntry = serde_json::from_slice(&fr.body)
                    .map_err(|e| StoreError::Damaged(format!("idempotency.log: {e}")))?;
                if e.first + e.count <= n {
                    l.idem.push(e);
                }
            }
        }
        l.reads = 4;
        Ok(l)
    }

    fn append(&mut self, b: &Batch) -> Result<(), StoreError> {
        let ev_len0 = self.files.events.metadata()?.len();
        let pay_len0 = self.files.payloads.metadata()?.len();
        let res: std::io::Result<Vec<u64>> = (|| {
            let mut offs = Vec::with_capacity(b.bodies.len());
            for body in b.bodies {
                offs.push(frames::append(&mut self.files.payloads, body)?);
            }
            for m in b.events {
                frames::append(&mut self.files.events, &serde_json::to_vec(m).unwrap())?;
            }
            if let Some(r) = b.idem {
                if self.files.idem.is_none() {
                    let p = self.dir.join("idempotency.log");
                    self.files.idem = Some(open_rw(&p)?);
                    set_mode(&p);
                }
                let e = IdemEntry {
                    key: r.key.clone(),
                    request: r.request.clone(),
                    first: b.first,
                    count: b.events.len() as u64,
                    time_ns: b.time_ns,
                };
                let f = self.files.idem.as_mut().unwrap();
                frames::append(f, &serde_json::to_vec(&e).unwrap())?;
                f.sync_data()?;
            }
            self.files.payloads.sync_data()?;
            self.files.events.sync_data()?;
            Ok(offs)
        })();
        match res {
            Ok(offs) => {
                self.offsets.extend(offs);
                self.store_receipt(b.receipt)
            }
            Err(e) => {
                let _ = self.files.events.set_len(ev_len0);
                let _ = self.files.payloads.set_len(pay_len0);
                Err(StoreError::Failed(format!("write failed: {e}")))
            }
        }
    }

    fn store_receipt(&mut self, r: &Receipt) -> Result<(), StoreError> {
        frames::append(&mut self.files.receipts, &serde_json::to_vec(r).unwrap())?;
        self.files.receipts.sync_data()?;
        Ok(())
    }

    fn read_body(&self, id: u64, _meta: &EventMeta) -> Result<Vec<u8>, StoreError> {
        let off = *self
            .offsets
            .get(id as usize)
            .ok_or(StoreError::UnknownEvent(id))?;
        Ok(frames::read_body(&self.files.payloads, off)?)
    }

    fn redact(&mut self, id: u64, meta: &EventMeta) -> Result<(), StoreError> {
        let off = self.offsets[id as usize];
        let mut body = self.read_body(id, meta)?;
        body[8] = 1;
        for b in body[9..].iter_mut() {
            *b = 0;
        }
        frames::rewrite(&self.files.payloads, off, &body)?;
        Ok(())
    }

    fn sync_redactions(&mut self) -> Result<(), StoreError> {
        self.files.payloads.sync_data()?;
        Ok(())
    }

    fn put_checkpoint(&mut self, cp: &Checkpoint) -> Result<(), StoreError> {
        frames::append(
            &mut self.files.checkpoints,
            &serde_json::to_vec(cp).unwrap(),
        )?;
        self.files.checkpoints.sync_data()?;
        Ok(())
    }

    fn tail(&mut self, _from: u64) -> Result<Vec<BatchObject>, StoreError> {
        Ok(vec![]) // a file store has exactly one writer: this process
    }

    fn checkpoints_after(&mut self, _after: u64) -> Result<Vec<Checkpoint>, StoreError> {
        Ok(vec![])
    }

    fn put_snapshot(&mut self, _s: &SnapshotObject) -> Result<(), StoreError> {
        Ok(()) // the files are their own snapshot
    }
}

// =====================================================================================
// ObjectBackend
// =====================================================================================

/// Runs object-store futures on one process-wide runtime and waits for them from any thread,
/// including a tokio worker or a test's current-thread runtime. The runtime is never dropped
/// (dropping a runtime inside async code panics).
#[derive(Clone, Copy)]
struct Rt;

impl Rt {
    fn new() -> Self {
        Rt
    }
    fn runtime() -> &'static tokio::runtime::Runtime {
        static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
        RT.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_name("vesdb-objects")
                .enable_all()
                .build()
                .expect("object-store runtime")
        })
    }
    fn run<T: Send + 'static>(
        &self,
        f: impl std::future::Future<Output = T> + Send + 'static,
    ) -> T {
        // Wait on a plain channel, not on the JoinHandle: polling a tokio JoinHandle from a tokio
        // worker (with futures' block_on) spins forever once that worker's coop budget is spent.
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        Self::runtime().spawn(async move {
            let _ = tx.send(f.await);
        });
        rx.recv().expect("object-store task panicked")
    }
}

pub struct ObjectBackend {
    store: Arc<dyn ObjectStore>,
    prefix: OPath,
    url: String,
    rt: Rt,
}

fn obj_err(what: &str, e: object_store::Error) -> StoreError {
    StoreError::Failed(format!("{what}: {e}"))
}

impl ObjectBackend {
    pub fn new(store: Arc<dyn ObjectStore>, prefix: &str, url: &str) -> Self {
        Self {
            store,
            prefix: OPath::from(prefix),
            url: url.to_string(),
            rt: Rt::new(),
        }
    }

    /// `s3://bucket/prefix`, `gs://…`, `az://…`, `file:///dir`, `memory:///` (credentials and
    /// endpoint from the environment: `AWS_*`, `GOOGLE_*`, `AZURE_*`).
    pub fn from_url(url: &str) -> Result<Self, StoreError> {
        let u =
            url::Url::parse(url).map_err(|e| StoreError::Invalid(format!("storage url: {e}")))?;
        let opts: Vec<(String, String)> = std::env::vars()
            .filter(|(k, _)| {
                k.starts_with("AWS_") || k.starts_with("GOOGLE_") || k.starts_with("AZURE_")
            })
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
        let (store, path) = if u.scheme() == "file" {
            let dir = u
                .to_file_path()
                .map_err(|_| StoreError::Invalid("bad file url".into()))?;
            std::fs::create_dir_all(&dir)?;
            let s = object_store::local::LocalFileSystem::new_with_prefix(&dir)
                .map_err(|e| obj_err("local store", e))?;
            (Arc::new(s) as Arc<dyn ObjectStore>, OPath::from(""))
        } else {
            let (s, p) =
                object_store::parse_url_opts(&u, opts).map_err(|e| obj_err("storage url", e))?;
            (Arc::from(s), p)
        };
        Ok(Self {
            store,
            prefix: path,
            url: url.to_string(),
            rt: Rt::new(),
        })
    }

    pub fn url(&self) -> String {
        self.url.clone()
    }

    pub fn object_store(&self) -> Arc<dyn ObjectStore> {
        self.store.clone()
    }
    pub fn prefix(&self) -> &OPath {
        &self.prefix
    }

    fn key(&self, k: &str) -> OPath {
        if self.prefix.as_ref().is_empty() {
            OPath::from(k)
        } else {
            OPath::from(format!("{}/{k}", self.prefix))
        }
    }

    fn create(&self, k: &str, bytes: Vec<u8>) -> Result<bool, StoreError> {
        let (s, p) = (self.store.clone(), self.key(k));
        let opts = PutOptions {
            mode: PutMode::Create,
            ..Default::default()
        };
        match self
            .rt
            .run(async move { s.put_opts(&p, PutPayload::from(bytes), opts).await })
        {
            Ok(_) => Ok(true),
            Err(object_store::Error::AlreadyExists { .. }) => Ok(false),
            Err(e) => Err(obj_err(&format!("create {k}"), e)),
        }
    }

    fn get(&self, k: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let (s, p) = (self.store.clone(), self.key(k));
        match self.rt.run(async move {
            match s.get(&p).await {
                Ok(r) => r.bytes().await.map(Some),
                Err(e) => Err(e),
            }
        }) {
            Ok(b) => Ok(b.map(|b| b.to_vec())),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(obj_err(&format!("get {k}"), e)),
        }
    }

    /// Keys (relative to the prefix) under `dir`, after `offset` (also relative), sorted.
    pub fn list(&self, dir: &str, offset: Option<&str>) -> Result<Vec<String>, StoreError> {
        let (s, p) = (self.store.clone(), self.key(dir));
        let off = offset.map(|o| self.key(o));
        let strip = if self.prefix.as_ref().is_empty() {
            0
        } else {
            self.prefix.as_ref().len() + 1
        };
        let mut keys: Vec<String> = self
            .rt
            .run(async move {
                let st = match &off {
                    Some(o) => s.list_with_offset(Some(&p), o),
                    None => s.list(Some(&p)),
                };
                st.map_ok(|m| m.location.to_string())
                    .try_collect::<Vec<_>>()
                    .await
            })
            .map_err(|e| obj_err(&format!("list {dir}"), e))?
            .into_iter()
            .map(|k| k[strip..].to_string())
            .collect();
        keys.sort();
        Ok(keys)
    }

    pub fn get_raw(&self, k: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.get(k)
    }
    pub fn put_raw(&self, k: &str, bytes: Vec<u8>) -> Result<(), StoreError> {
        let (s, p) = (self.store.clone(), self.key(k));
        self.rt
            .run(async move { s.put(&p, PutPayload::from(bytes)).await })
            .map(|_| ())
            .map_err(|e| obj_err(&format!("put {k}"), e))
    }
    pub fn create_raw(&self, k: &str, bytes: Vec<u8>) -> Result<bool, StoreError> {
        self.create(k, bytes)
    }
    pub fn delete_raw(&self, k: &str) -> Result<(), StoreError> {
        let (s, p) = (self.store.clone(), self.key(k));
        match self.rt.run(async move { s.delete(&p).await }) {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(obj_err(&format!("delete {k}"), e)),
        }
    }

    /// Conditional replace of `writer.json`-style objects: `Ok(Some(etag))` on success,
    /// `Ok(None)` when someone else changed it first. Stores without conditional updates
    /// (local directories) fall back to a plain replace: the object is advisory only.
    pub fn replace_if(
        &self,
        k: &str,
        bytes: Vec<u8>,
        expect: Option<ObjectVersion>,
    ) -> Result<Option<ObjectVersion>, StoreError> {
        let (s, p) = (self.store.clone(), self.key(k));
        let mode = match expect {
            None => PutMode::Create,
            Some((e_tag, version)) => {
                PutMode::Update(object_store::UpdateVersion { e_tag, version })
            }
        };
        let fallback = bytes.clone();
        let r = self.rt.run({
            let (s, p) = (s.clone(), p.clone());
            async move {
                s.put_opts(
                    &p,
                    PutPayload::from(bytes),
                    PutOptions {
                        mode,
                        ..Default::default()
                    },
                )
                .await
            }
        });
        match r {
            Ok(pr) => Ok(Some((pr.e_tag, pr.version))),
            Err(
                object_store::Error::AlreadyExists { .. }
                | object_store::Error::Precondition { .. },
            ) => Ok(None),
            Err(object_store::Error::NotImplemented { .. }) => self
                .rt
                .run(async move { s.put(&p, PutPayload::from(fallback)).await })
                .map(|pr| Some((pr.e_tag, pr.version)))
                .map_err(|e| obj_err(&format!("put {k}"), e)),
            Err(e) => Err(obj_err(&format!("replace {k}"), e)),
        }
    }

    /// `(bytes, (etag, version))` of an object, if present.
    pub fn get_versioned(&self, k: &str) -> Result<Option<(Vec<u8>, ObjectVersion)>, StoreError> {
        let (s, p) = (self.store.clone(), self.key(k));
        match self.rt.run(async move {
            let r = s.get(&p).await?;
            let v = (r.meta.e_tag.clone(), r.meta.version.clone());
            Ok::<_, object_store::Error>((r.bytes().await?.to_vec(), v))
        }) {
            Ok(x) => Ok(Some(x)),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(obj_err(&format!("get {k}"), e)),
        }
    }

    fn load_batches(&self, from: u64, l: &mut Loaded) -> Result<(), StoreError> {
        let mut next = from;
        while let Some(b) = self.get(&batch_key(next))? {
            l.reads += 1;
            let o = BatchObject::decode(&b)
                .map_err(|e| StoreError::Damaged(format!("batch {next}: {e}")))?;
            if o.first != next {
                return Err(StoreError::Damaged(format!(
                    "{} holds batch {}",
                    batch_key(next),
                    o.first
                )));
            }
            next = o.receipt.size;
            if let Some(r) = &o.idem {
                l.idem.push(IdemEntry {
                    key: r.key.clone(),
                    request: r.request.clone(),
                    first: o.first,
                    count: o.events.len() as u64,
                    time_ns: o.events[0].time_ns,
                });
            }
            l.redacted
                .extend(std::iter::repeat_n(false, o.events.len()));
            l.events.extend(o.events);
            l.receipts.push(o.receipt);
        }
        Ok(())
    }
}

impl Backend for ObjectBackend {
    fn describe(&self) -> String {
        format!("objects in {}", self.url)
    }

    fn shared(&self) -> bool {
        true
    }

    fn load(&mut self) -> Result<Loaded, StoreError> {
        let mut l = Loaded::default();
        let mut from = 0;
        if let Some(k) = self.list("snap", None)?.last() {
            if let Some(b) = self.get(k)? {
                l.reads += 1;
                let s = SnapshotObject::decode(&b)
                    .map_err(|e| StoreError::Damaged(format!("{k}: {e}")))?;
                from = s.size;
                l.redacted = vec![false; s.events.len()];
                for &i in &s.redacted {
                    if let Some(r) = l.redacted.get_mut(i as usize) {
                        *r = true;
                    }
                }
                l.events = s.events;
                l.receipts = s.receipts;
                l.idem = s.idem;
            }
        }
        self.load_batches(from, &mut l)?;
        l.checkpoints = self.checkpoints_after(0)?;
        l.checkpoints.retain(|c| c.size <= l.events.len() as u64);
        Ok(l)
    }

    fn append(&mut self, b: &Batch) -> Result<(), StoreError> {
        // 1. payloads, in parallel, named by their (salted, so unique) commitments
        let puts: Vec<_> = b
            .events
            .iter()
            .zip(b.bodies)
            .map(|(m, body)| {
                let (s, p) = (self.store.clone(), self.key(&data_key(&m.commit)));
                let body = body.clone();
                async move {
                    let opts = PutOptions {
                        mode: PutMode::Create,
                        ..Default::default()
                    };
                    s.put_opts(&p, PutPayload::from(body), opts)
                        .await
                        .map(|_| ())
                }
            })
            .collect();
        let res = self.rt.run(async move {
            futures::stream::iter(puts)
                .buffer_unordered(16)
                .try_collect::<Vec<()>>()
                .await
        });
        match res {
            Ok(_) | Err(object_store::Error::AlreadyExists { .. }) => {}
            Err(e) => return Err(obj_err("store payload", e)),
        }
        // 2. the batch, create only if new: this is the decision
        let o = BatchObject {
            format: BATCH_FORMAT.into(),
            first: b.first,
            events: b.events.to_vec(),
            receipt: b.receipt.clone(),
            idem: b.idem.cloned(),
        };
        if self.create(&batch_key(b.first), o.encode())? {
            Ok(())
        } else {
            Err(StoreError::Conflict { position: b.first })
        }
    }

    fn store_receipt(&mut self, _r: &Receipt) -> Result<(), StoreError> {
        Err(StoreError::Failed(
            "object stores keep each receipt inside its batch".into(),
        ))
    }

    fn read_body(&self, id: u64, meta: &EventMeta) -> Result<Vec<u8>, StoreError> {
        self.get(&data_key(&meta.commit))?
            .ok_or_else(|| StoreError::Damaged(format!("event {id}: payload object missing")))
    }

    fn redact(&mut self, id: u64, meta: &EventMeta) -> Result<(), StoreError> {
        // replaced, not versioned: the bucket prefix `data/` has neither Object Lock nor
        // versioning, so the old bytes are really gone
        let mut body = id.to_be_bytes().to_vec();
        body.push(1);
        self.put_raw(&data_key(&meta.commit), body)
    }

    fn sync_redactions(&mut self) -> Result<(), StoreError> {
        Ok(())
    }

    fn put_checkpoint(&mut self, cp: &Checkpoint) -> Result<(), StoreError> {
        self.create(&checkpoint_key(cp.size), checkpoint_object(cp))?;
        for (w, sig) in &cp.cosigs {
            let o = CosigObject {
                witness: w.clone(),
                size: cp.size,
                sig: sig.clone(),
            };
            self.create(&cosig_key(cp.size, w), serde_json::to_vec(&o).unwrap())?;
        }
        Ok(())
    }

    fn tail(&mut self, from: u64) -> Result<Vec<BatchObject>, StoreError> {
        let mut out = Vec::new();
        let mut next = from;
        while let Some(b) = self.get(&batch_key(next))? {
            let o = BatchObject::decode(&b)
                .map_err(|e| StoreError::Damaged(format!("batch {next}: {e}")))?;
            next = o.receipt.size;
            out.push(o);
        }
        Ok(out)
    }

    fn checkpoints_after(&mut self, after: u64) -> Result<Vec<Checkpoint>, StoreError> {
        let offset = format!("cp/{}", vesdb_core::objects::position(after));
        let keys = self.list("cp", Some(&offset))?;
        let mut cps: BTreeMap<u64, Checkpoint> = BTreeMap::new();
        let mut sigs: Vec<CosigObject> = Vec::new();
        for k in keys {
            let Some(b) = self.get(&k)? else { continue };
            if k.ends_with(".json") {
                let c: Checkpoint = serde_json::from_slice(&b)
                    .map_err(|e| StoreError::Damaged(format!("{k}: {e}")))?;
                if c.size > after {
                    cps.insert(c.size, c);
                }
            } else if k.ends_with(".sig") {
                let s: CosigObject = serde_json::from_slice(&b)
                    .map_err(|e| StoreError::Damaged(format!("{k}: {e}")))?;
                sigs.push(s);
            }
        }
        for s in sigs {
            if let Some(c) = cps.get_mut(&s.size) {
                c.cosigs.insert(s.witness, s.sig);
            }
        }
        Ok(cps.into_values().collect())
    }

    fn put_snapshot(&mut self, s: &SnapshotObject) -> Result<(), StoreError> {
        self.create(&snapshot_key(s.size), s.encode()).map(|_| ())
    }
}

/// Position of every `log/` object, in order (for gap checks).
pub fn batch_positions(b: &ObjectBackend) -> Result<Vec<u64>, StoreError> {
    Ok(b.list("log", None)?
        .iter()
        .filter_map(|k| parse_position(k))
        .collect())
}

/// Race test (plan, section 6): two writers create the same key `rounds` times, concurrently.
/// Returns the number of rounds in which exactly one create succeeded; a store fit for vesdb
/// returns `rounds`. Keys go under `race/<run>/`, which is removed afterwards.
pub fn race_test(b: &ObjectBackend, rounds: u64) -> Result<u64, StoreError> {
    let run = hex::encode(vesdb_core::random_bytes::<8>());
    let store = b.store.clone();
    let base = b.key(&format!("race/{run}"));
    let ok = b.rt.run(async move {
        let mut ok = 0u64;
        for i in 0..rounds {
            let p = OPath::from(format!("{base}/{i:020}"));
            let put = |who: u8| {
                let (s, p) = (store.clone(), p.clone());
                tokio::spawn(async move {
                    let opts = PutOptions {
                        mode: PutMode::Create,
                        ..Default::default()
                    };
                    s.put_opts(&p, PutPayload::from(vec![who]), opts).await
                })
            };
            let (a, c) = (put(1), put(2));
            let (a, c) = (a.await.expect("join"), c.await.expect("join"));
            let won = [&a, &c].iter().filter(|r| r.is_ok()).count();
            let refused = [&a, &c]
                .iter()
                .filter(|r| matches!(r, Err(object_store::Error::AlreadyExists { .. })))
                .count();
            if won == 1 && refused == 1 {
                // the stored object must be the winner's
                let who = if a.is_ok() { 1u8 } else { 2 };
                let got = store.get(&p).await?.bytes().await?;
                if got.as_ref() == [who] {
                    ok += 1;
                }
            }
        }
        let keys: Vec<OPath> = store
            .list(Some(&base))
            .map_ok(|m| m.location)
            .try_collect()
            .await?;
        for k in keys {
            store.delete(&k).await?;
        }
        Ok::<u64, object_store::Error>(ok)
    });
    ok.map_err(|e| obj_err("race test", e))
}
