//! `vesdb-ts`: high-rate time series next to the event log.
//!
//! Points never become log entries. They go to a write-ahead log and an in-memory buffer per
//! `(series, window)`. When a window closes (window end + grace), its points are sorted,
//! Gorilla-compressed into a chunk file, and the chunk is committed to the log as one
//! `io.vesdb.ts.chunk-sealed` event carrying a summary: time range, count, min/max/sum/first/last,
//! the file's SHA-256 and the Merkle root over the points. One log leaf per series per window buys
//! write-time receipts, witness cosigning and per-reading proofs for everything in the chunk.
//!
//! Retention deletes chunk files but keeps their `chunk-sealed` events. Each deletion is itself
//! logged (`io.vesdb.ts.chunk-expired`), so an auditor can tell policy deletion from tampering,
//! and the summaries keep answering coarse aggregate queries.
//!
//! The engine does not touch the log itself: [`TsEngine::prepare_seals`] returns what to append,
//! the caller appends it atomically, then hands the event ids back to
//! [`TsEngine::commit_seals`]. Recovery rebuilds the chunk index from those events and replays the
//! write-ahead log, skipping points that a committed chunk already holds (`walHi`), so a crash at
//! any step neither loses an acknowledged point nor seals one twice.

pub mod chunk;
pub mod gorilla;

use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use vesdb_core::{
    merkle::MerkleTree,
    sha256,
    ts::{
        point_leaf, ChunkExpired, ChunkSummary, CHUNK_EXPIRED_TYPE, CHUNK_SEALED_TYPE,
        SUBJECT_PREFIX,
    },
    validate, Hash,
};
use vesdb_store::frames;

#[derive(Debug, thiserror::Error)]
pub enum TsError {
    #[error("{0}")]
    Invalid(String),
    #[error("chunk #{chunk} of {series} failed its integrity check: {why}")]
    Tampered {
        series: String,
        chunk: u64,
        why: String,
    },
    #[error("time-series buffer is full ({0} points waiting to be sealed)")]
    Busy(usize),
    #[error("{0}")]
    NotFound(String),
    #[error("the point is not sealed yet; flush or wait for its window to close")]
    NotSealed,
    #[error("the query would return more than {0} points; use a step to downsample")]
    TooMany(usize),
    #[error("write-ahead log is damaged: {0}")]
    Damaged(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl TsError {
    pub fn slug(&self) -> &'static str {
        match self {
            TsError::Invalid(_) => "invalid-argument",
            TsError::Tampered { .. } => "integrity-violation",
            TsError::Busy(_) => "resource-exhausted",
            TsError::NotFound(_) => "not-found",
            TsError::NotSealed => "failed-precondition",
            TsError::TooMany(_) => "resource-exhausted",
            TsError::Damaged(_) => "data-loss",
            TsError::Io(_) => "internal",
        }
    }
}

#[derive(Clone, Debug)]
pub struct TsConfig {
    pub dir: PathBuf,
    /// Sealing window length (ns). Default 60 s.
    pub window_ns: i64,
    /// How long after a window's end late points are still waited for (ns). Default 5 s.
    pub grace_ns: i64,
    /// fsync the write-ahead log before acknowledging a write, and chunk files before their
    /// events are appended.
    pub fsync: bool,
    pub max_buffered_points: usize,
    pub max_query_points: usize,
    pub max_points_per_write: usize,
    /// Delete chunk files whose last point is older than this (ns), logging each deletion.
    pub retention_ns: Option<i64>,
}

impl TsConfig {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            window_ns: 60_000_000_000,
            grace_ns: 5_000_000_000,
            fsync: true,
            max_buffered_points: 20_000_000,
            max_query_points: 1_000_000,
            max_points_per_write: 1_000_000,
            retention_ns: None,
        }
    }
}

/// A sealed chunk as known from the log.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChunkRef {
    /// Event id of the chunk's `chunk-sealed` event.
    pub event_id: u64,
    pub summary: ChunkSummary,
    /// Event id of the `chunk-expired` event, once the file has been deleted.
    pub expired_by: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
struct Buffered {
    t: i64,
    v: f64,
    batch: u64,
}

/// A chunk file written to disk whose `chunk-sealed` event has not been appended yet.
#[derive(Debug)]
pub struct PendingSeal {
    pub summary: ChunkSummary,
    path: PathBuf,
}

impl PendingSeal {
    pub fn subject(&self) -> String {
        format!("{SUBJECT_PREFIX}{}", self.summary.series)
    }
    pub fn event_type(&self) -> &'static str {
        CHUNK_SEALED_TYPE
    }
    /// Exact JSON text for the event's data.
    pub fn data(&self) -> String {
        serde_json::to_string(&self.summary).expect("summary serializes")
    }
}

/// A chunk whose deletion has to be logged before the file is removed.
#[derive(Debug)]
pub struct PendingExpiry {
    pub chunk_event: u64,
    pub info: ChunkExpired,
}

impl PendingExpiry {
    pub fn subject(&self) -> String {
        format!("{SUBJECT_PREFIX}{}", self.info.series)
    }
    pub fn event_type(&self) -> &'static str {
        CHUNK_EXPIRED_TYPE
    }
    pub fn data(&self) -> String {
        serde_json::to_string(&self.info).expect("expiry serializes")
    }
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Bucket {
    pub start: i64,
    pub count: u64,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub sum: f64,
    pub avg: Option<f64>,
    pub first: Option<f64>,
    pub last: Option<f64>,
    /// Some points in this bucket were deleted by retention and could not be counted
    /// (their chunk spans more than this bucket).
    pub partial: bool,
    /// Part of this bucket was answered from expired chunks' summaries.
    pub from_summaries: bool,
    #[serde(skip)]
    first_t: i64,
    #[serde(skip)]
    last_t: i64,
}

impl Bucket {
    fn new(start: i64) -> Self {
        Self {
            start,
            first_t: i64::MAX,
            last_t: i64::MIN,
            ..Default::default()
        }
    }
    fn add(&mut self, t: i64, v: f64) {
        self.count += 1;
        self.sum += v;
        self.min = Some(self.min.map_or(v, |m| m.min(v)));
        self.max = Some(self.max.map_or(v, |m| m.max(v)));
        if t < self.first_t {
            (self.first_t, self.first) = (t, Some(v));
        }
        if t >= self.last_t {
            (self.last_t, self.last) = (t, Some(v));
        }
    }
    fn add_summary(&mut self, s: &ChunkSummary) {
        self.count += s.count;
        self.sum += s.sum;
        self.min = Some(self.min.map_or(s.min, |m| m.min(s.min)));
        self.max = Some(self.max.map_or(s.max, |m| m.max(s.max)));
        if s.t0 < self.first_t {
            (self.first_t, self.first) = (s.t0, Some(s.first));
        }
        if s.t1 >= self.last_t {
            (self.last_t, self.last) = (s.t1, Some(s.last));
        }
        self.from_summaries = true;
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawResult {
    pub points: Vec<(i64, f64)>,
    /// Chunks in the range whose points were deleted by retention.
    pub expired: Vec<ChunkRef>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SeriesInfo {
    pub series: String,
    pub chunks: usize,
    pub expired_chunks: usize,
    pub sealed_points: u64,
    pub open_points: usize,
    pub first: Option<i64>,
    pub last: Option<i64>,
    pub stored_bytes: u64,
}

/// Material for a point proof; the caller adds the evidence bundle for `chunk_event`.
#[derive(Clone, Debug)]
pub struct PointProofParts {
    pub chunk_event: u64,
    pub index: u64,
    pub count: u64,
    pub value: f64,
    pub inclusion: Vec<Hash>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub severity: &'static str,
    pub description: String,
}

pub struct TsEngine {
    cfg: TsConfig,
    wal: File,
    next_batch: u64,
    open: BTreeMap<String, BTreeMap<i64, Vec<Buffered>>>,
    buffered: usize,
    chunks: BTreeMap<String, Vec<ChunkRef>>,
    sealed_hi: HashMap<(String, i64), u64>,
}

fn invalid(s: impl Into<String>) -> TsError {
    TsError::Invalid(s.into())
}

/// Series names are subject paths below `/ts/`: segments of `[A-Za-z0-9_-]`, separated by `/`.
pub fn validate_series(series: &str) -> Result<(), TsError> {
    let subject = format!("{SUBJECT_PREFIX}{series}");
    match validate::subject(&subject) {
        Ok(norm) if norm == subject && !series.is_empty() => Ok(()),
        _ => Err(invalid(format!(
            "series {series:?} must be one or more `/`-separated segments of [A-Za-z0-9_-]"
        ))),
    }
}

fn wal_body(batch: u64, groups: &[(&str, &[(i64, f64)])]) -> Vec<u8> {
    let n: usize = groups.iter().map(|g| g.1.len()).sum();
    let mut b = Vec::with_capacity(12 + n * 16 + groups.len() * 40);
    b.extend_from_slice(&batch.to_be_bytes());
    b.extend_from_slice(&(groups.len() as u32).to_be_bytes());
    for (s, pts) in groups {
        b.extend_from_slice(&(s.len() as u16).to_be_bytes());
        b.extend_from_slice(s.as_bytes());
        b.extend_from_slice(&(pts.len() as u32).to_be_bytes());
        for &(t, v) in pts.iter() {
            b.extend_from_slice(&t.to_be_bytes());
            b.extend_from_slice(&v.to_bits().to_be_bytes());
        }
    }
    b
}

type WalBatch = (u64, Vec<(String, Vec<(i64, f64)>)>);
/// batch -> series -> points, for rewriting the write-ahead log
type ByBatch<'a> = BTreeMap<u64, BTreeMap<&'a str, Vec<(i64, f64)>>>;

fn parse_wal_body(b: &[u8]) -> Option<WalBatch> {
    let mut p = 0usize;
    let mut take = |n: usize| -> Option<&[u8]> {
        let r = b.get(p..p + n)?;
        p += n;
        Some(r)
    };
    let batch = u64::from_be_bytes(take(8)?.try_into().ok()?);
    let ng = u32::from_be_bytes(take(4)?.try_into().ok()?);
    let mut groups = Vec::new();
    for _ in 0..ng {
        let sl = u16::from_be_bytes(take(2)?.try_into().ok()?) as usize;
        let s = String::from_utf8(take(sl)?.to_vec()).ok()?;
        let n = u32::from_be_bytes(take(4)?.try_into().ok()?) as usize;
        let mut pts = Vec::with_capacity(n.min(1 << 20));
        for _ in 0..n {
            let t = i64::from_be_bytes(take(8)?.try_into().ok()?);
            let v = f64::from_bits(u64::from_be_bytes(take(8)?.try_into().ok()?));
            pts.push((t, v));
        }
        groups.push((s, pts));
    }
    Some((batch, groups))
}

fn sync_dir(p: &Path) -> std::io::Result<()> {
    File::open(p)?.sync_all()
}

impl TsEngine {
    /// Open (or create) the engine. `log` yields every `/ts/…` event in log order as
    /// `(event id, type, data)`; `data` is `None` for a redacted payload.
    pub fn open<'a>(
        cfg: TsConfig,
        log: impl IntoIterator<Item = (u64, &'a str, Option<&'a str>)>,
    ) -> Result<(Self, Vec<Finding>), TsError> {
        if cfg.window_ns <= 0 || cfg.grace_ns < 0 {
            return Err(invalid("window must be positive and grace non-negative"));
        }
        let mut findings = Vec::new();
        fs::create_dir_all(cfg.dir.join("chunks"))?;
        let mut chunks: BTreeMap<String, Vec<ChunkRef>> = BTreeMap::new();
        let mut sealed_hi: HashMap<(String, i64), u64> = HashMap::new();
        let mut where_is: HashMap<u64, (String, usize)> = HashMap::new();
        let mut max_batch = 0u64;
        for (id, ty, data) in log {
            match (ty, data) {
                (CHUNK_SEALED_TYPE, Some(d)) => match serde_json::from_str::<ChunkSummary>(d) {
                    Ok(s) => {
                        let hi = sealed_hi.entry((s.series.clone(), s.window)).or_default();
                        *hi = (*hi).max(s.wal_hi);
                        max_batch = max_batch.max(s.wal_hi);
                        let v = chunks.entry(s.series.clone()).or_default();
                        where_is.insert(id, (s.series.clone(), v.len()));
                        v.push(ChunkRef {
                            event_id: id,
                            summary: s,
                            expired_by: None,
                        });
                    }
                    Err(e) => findings.push(Finding {
                        severity: "error",
                        description: format!("event #{id}: unreadable chunk summary: {e}"),
                    }),
                },
                (CHUNK_EXPIRED_TYPE, Some(d)) => match serde_json::from_str::<ChunkExpired>(d) {
                    Ok(x) => {
                        let target = x.chunk.parse::<u64>().ok().and_then(|c| where_is.get(&c));
                        match target {
                            Some((s, i)) => chunks.get_mut(s).unwrap()[*i].expired_by = Some(id),
                            None => findings.push(Finding {
                                severity: "error",
                                description: format!(
                                    "event #{id} expires unknown chunk {}",
                                    x.chunk
                                ),
                            }),
                        }
                    }
                    Err(e) => findings.push(Finding {
                        severity: "error",
                        description: format!("event #{id}: unreadable expiry: {e}"),
                    }),
                },
                (CHUNK_SEALED_TYPE | CHUNK_EXPIRED_TYPE, None) => findings.push(Finding {
                    severity: "warning",
                    description: format!("event #{id}: time-series event payload was redacted"),
                }),
                _ => {}
            }
        }
        for v in chunks.values_mut() {
            v.sort_by_key(|c| (c.summary.t0, c.event_id));
        }
        let mut e = TsEngine {
            wal: OpenOptions::new()
                .create(true)
                .read(true)
                .append(true)
                .open(cfg.dir.join("wal"))?,
            cfg,
            next_batch: 0,
            open: BTreeMap::new(),
            buffered: 0,
            chunks,
            sealed_hi,
        };
        e.cleanup_files()?;
        // replay the write-ahead log
        let scan = frames::scan(&mut e.wal)?;
        if scan.damaged {
            return Err(TsError::Damaged(format!(
                "bad frame followed by {} more bytes",
                scan.trailing
            )));
        }
        if scan.trailing > 0 {
            e.wal.set_len(scan.good_len)?;
            findings.push(Finding {
                severity: "info",
                description: format!(
                    "time-series WAL: dropped a torn final write ({} bytes, never acknowledged)",
                    scan.trailing
                ),
            });
        }
        let mut replayed = 0usize;
        for f in &scan.frames {
            let (batch, groups) = parse_wal_body(&f.body)
                .ok_or_else(|| TsError::Damaged("unreadable batch".into()))?;
            max_batch = max_batch.max(batch);
            for (s, pts) in groups {
                for (t, v) in pts {
                    let w = t.div_euclid(e.cfg.window_ns) * e.cfg.window_ns;
                    if e.sealed_hi
                        .get(&(s.clone(), w))
                        .is_some_and(|&hi| batch <= hi)
                    {
                        continue; // already in a committed chunk
                    }
                    e.open
                        .entry(s.clone())
                        .or_default()
                        .entry(w)
                        .or_default()
                        .push(Buffered { t, v, batch });
                    e.buffered += 1;
                    replayed += 1;
                }
            }
        }
        if replayed > 0 {
            findings.push(Finding {
                severity: "info",
                description: format!("time-series WAL: {replayed} unsealed points recovered"),
            });
        }
        e.next_batch = max_batch + 1;
        Ok((e, findings))
    }

    fn chunk_path(&self, s: &ChunkSummary) -> PathBuf {
        let dir = hex::encode(&sha256(&[s.series.as_bytes()])[..8]);
        self.cfg
            .dir
            .join("chunks")
            .join(dir)
            .join(format!("{}-{}.vtsc", s.window, &s.sha256[..16]))
    }

    /// Delete chunk files of expired chunks and files no committed chunk refers to (a crash
    /// between writing a chunk file and appending its event).
    fn cleanup_files(&self) -> Result<(), TsError> {
        let mut live = HashSet::new();
        for c in self.chunks.values().flatten() {
            let p = self.chunk_path(&c.summary);
            if c.expired_by.is_some() {
                let _ = fs::remove_file(&p);
            } else {
                live.insert(p);
            }
        }
        for d in fs::read_dir(self.cfg.dir.join("chunks"))? {
            let d = d?.path();
            if !d.is_dir() {
                continue;
            }
            for f in fs::read_dir(&d)? {
                let f = f?.path();
                if !live.contains(&f) {
                    fs::remove_file(&f)?;
                }
            }
        }
        Ok(())
    }

    pub fn config(&self) -> &TsConfig {
        &self.cfg
    }

    pub fn buffered(&self) -> usize {
        self.buffered
    }

    // ------------------------------------------------------------------ writes

    /// Durably accept points (WAL first, then the buffer). Returns the number accepted.
    pub fn write(&mut self, batches: &[(String, Vec<(i64, f64)>)]) -> Result<usize, TsError> {
        let n: usize = batches.iter().map(|b| b.1.len()).sum();
        if n == 0 {
            return Ok(0);
        }
        if n > self.cfg.max_points_per_write {
            return Err(invalid(format!(
                "at most {} points per write",
                self.cfg.max_points_per_write
            )));
        }
        if self.buffered + n > self.cfg.max_buffered_points {
            return Err(TsError::Busy(self.buffered));
        }
        for (s, pts) in batches {
            validate_series(s)?;
            for &(t, v) in pts {
                if t < 0 {
                    return Err(invalid("point times must be at or after the Unix epoch"));
                }
                if !v.is_finite() {
                    return Err(invalid(format!("{s}: values must be finite numbers")));
                }
            }
        }
        let batch = self.next_batch;
        let groups: Vec<(&str, &[(i64, f64)])> = batches
            .iter()
            .map(|(s, p)| (s.as_str(), p.as_slice()))
            .collect();
        frames::append(&mut self.wal, &wal_body(batch, &groups))?;
        if self.cfg.fsync {
            self.wal.sync_data()?;
        }
        self.next_batch += 1;
        for (s, pts) in batches {
            let windows = self.open.entry(s.clone()).or_default();
            for &(t, v) in pts {
                let w = t.div_euclid(self.cfg.window_ns) * self.cfg.window_ns;
                windows.entry(w).or_default().push(Buffered { t, v, batch });
            }
        }
        self.buffered += n;
        Ok(n)
    }

    // ------------------------------------------------------------------ sealing

    /// Write chunk files for every window that has closed by `now` (all windows if `force`).
    /// Nothing changes in the engine until [`commit_seals`](Self::commit_seals).
    pub fn prepare_seals(&mut self, now: i64, force: bool) -> Result<Vec<PendingSeal>, TsError> {
        let mut out = Vec::new();
        for (s, windows) in &self.open {
            for (&w, pts) in windows {
                if pts.is_empty()
                    || !(force
                        || w.saturating_add(self.cfg.window_ns)
                            .saturating_add(self.cfg.grace_ns)
                            <= now)
                {
                    continue;
                }
                let mut sorted: Vec<Buffered> = pts.clone();
                sorted.sort_by_key(|p| p.t); // stable: ties keep arrival order
                let wal_hi = sorted.iter().map(|p| p.batch).max().unwrap();
                let late = self.sealed_hi.contains_key(&(s.clone(), w));
                let pv: Vec<(i64, f64)> = sorted.iter().map(|p| (p.t, p.v)).collect();
                let (bytes, summary) = chunk::build(s, w, &pv, wal_hi, late);
                let path = self.chunk_path(&summary);
                fs::create_dir_all(path.parent().unwrap())?;
                let tmp = path.with_extension("tmp");
                {
                    let mut f = File::create(&tmp)?;
                    f.write_all(&bytes)?;
                    if self.cfg.fsync {
                        f.sync_all()?; // durable before its event can name it
                    }
                }
                fs::rename(&tmp, &path)?;
                if self.cfg.fsync {
                    sync_dir(path.parent().unwrap())?;
                }
                out.push(PendingSeal { summary, path });
            }
        }
        Ok(out)
    }

    /// The log could not take the events: forget the chunk files (the points stay buffered).
    pub fn abort_seals(&mut self, pending: Vec<PendingSeal>) {
        for p in pending {
            let _ = fs::remove_file(p.path);
        }
    }

    /// Record appended `chunk-sealed` events (`(seal, event id)`), drop sealed points from the
    /// buffer and compact the write-ahead log.
    pub fn commit_seals(&mut self, sealed: Vec<(PendingSeal, u64)>) -> Result<(), TsError> {
        if sealed.is_empty() {
            return Ok(());
        }
        for (p, id) in sealed {
            let s = p.summary;
            let key = (s.series.clone(), s.window);
            let hi = self.sealed_hi.entry(key).or_default();
            *hi = (*hi).max(s.wal_hi);
            if let Some(windows) = self.open.get_mut(&s.series) {
                if let Some(v) = windows.get_mut(&s.window) {
                    let before = v.len();
                    v.retain(|b| b.batch > s.wal_hi);
                    self.buffered -= before - v.len();
                    if v.is_empty() {
                        windows.remove(&s.window);
                    }
                }
                if windows.is_empty() {
                    self.open.remove(&s.series);
                }
            }
            let v = self.chunks.entry(s.series.clone()).or_default();
            v.push(ChunkRef {
                event_id: id,
                summary: s,
                expired_by: None,
            });
            v.sort_by_key(|c| (c.summary.t0, c.event_id));
        }
        self.compact_wal()
    }

    /// Rewrite the WAL with only the points still buffered (atomic rename).
    fn compact_wal(&mut self) -> Result<(), TsError> {
        let mut by_batch: ByBatch = BTreeMap::new();
        for (s, windows) in &self.open {
            for pts in windows.values() {
                for p in pts {
                    by_batch
                        .entry(p.batch)
                        .or_default()
                        .entry(s.as_str())
                        .or_default()
                        .push((p.t, p.v));
                }
            }
        }
        let tmp = self.cfg.dir.join("wal.tmp");
        {
            let mut f = File::create(&tmp)?;
            for (batch, groups) in &by_batch {
                let g: Vec<(&str, &[(i64, f64)])> =
                    groups.iter().map(|(s, p)| (*s, p.as_slice())).collect();
                f.write_all(&frames::encode(&wal_body(*batch, &g)))?;
            }
            f.sync_all()?;
        }
        fs::rename(&tmp, self.cfg.dir.join("wal"))?;
        sync_dir(&self.cfg.dir)?;
        self.wal = OpenOptions::new()
            .read(true)
            .append(true)
            .open(self.cfg.dir.join("wal"))?;
        Ok(())
    }

    // ------------------------------------------------------------------ retention

    /// Chunks whose last point is before `before` and whose file still exists.
    pub fn prepare_expiry(&self, before: i64, reason: &str) -> Vec<PendingExpiry> {
        self.chunks
            .values()
            .flatten()
            .filter(|c| c.expired_by.is_none() && c.summary.t1 < before)
            .map(|c| PendingExpiry {
                chunk_event: c.event_id,
                info: ChunkExpired {
                    series: c.summary.series.clone(),
                    chunk: c.event_id.to_string(),
                    sha256: c.summary.sha256.clone(),
                    reason: reason.to_string(),
                },
            })
            .collect()
    }

    /// The `chunk-expired` events are in the log: delete the files.
    pub fn commit_expiry(&mut self, done: Vec<(PendingExpiry, u64)>) -> Result<(), TsError> {
        for (x, id) in done {
            if let Some(c) = self
                .chunks
                .get_mut(&x.info.series)
                .and_then(|v| v.iter_mut().find(|c| c.event_id == x.chunk_event))
            {
                c.expired_by = Some(id);
                let summary = c.summary.clone();
                let p = self.chunk_path(&summary);
                match fs::remove_file(&p) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------ reads

    fn load(&self, c: &ChunkRef) -> Result<Vec<(i64, f64)>, TsError> {
        let tampered = |why: String| TsError::Tampered {
            series: c.summary.series.clone(),
            chunk: c.event_id,
            why,
        };
        let bytes = fs::read(self.chunk_path(&c.summary))
            .map_err(|e| tampered(format!("chunk file unreadable: {e}")))?;
        chunk::read(&bytes, &c.summary).map_err(tampered)
    }

    fn series_chunks(&self, series: &str) -> &[ChunkRef] {
        self.chunks.get(series).map_or(&[], |v| v.as_slice())
    }

    /// Raw points in `[from, to]`, sorted by time (ties: chunks in log order, then unsealed).
    /// Every chunk read is checked against its sealed summary.
    pub fn query(&self, series: &str, from: i64, to: i64) -> Result<RawResult, TsError> {
        validate_series(series)?;
        if from > to {
            return Err(invalid("from must not be after to"));
        }
        let mut points = Vec::new();
        let mut expired = Vec::new();
        for c in self.series_chunks(series) {
            if c.summary.t1 < from || c.summary.t0 > to {
                continue;
            }
            if c.expired_by.is_some() {
                expired.push(c.clone());
                continue;
            }
            let pts = self.load(c)?;
            points.extend(pts.into_iter().filter(|p| p.0 >= from && p.0 <= to));
            if points.len() > self.cfg.max_query_points {
                return Err(TsError::TooMany(self.cfg.max_query_points));
            }
        }
        if let Some(windows) = self.open.get(series) {
            for pts in windows.values() {
                let mut v: Vec<&Buffered> =
                    pts.iter().filter(|p| p.t >= from && p.t <= to).collect();
                v.sort_by_key(|p| p.t);
                points.extend(v.into_iter().map(|p| (p.t, p.v)));
            }
        }
        if points.len() > self.cfg.max_query_points {
            return Err(TsError::TooMany(self.cfg.max_query_points));
        }
        points.sort_by_key(|p| p.0);
        Ok(RawResult { points, expired })
    }

    /// Aggregates per `step`-aligned bucket in `[from, to]`. Expired chunks that fall inside a
    /// single bucket are answered exactly from their sealed summaries; others mark the bucket
    /// `partial`.
    pub fn downsample(
        &self,
        series: &str,
        from: i64,
        to: i64,
        step: i64,
    ) -> Result<Vec<Bucket>, TsError> {
        validate_series(series)?;
        if step <= 0 || from > to {
            return Err(invalid("step must be positive and from not after to"));
        }
        let span = (to.div_euclid(step) - from.div_euclid(step)) as u128 + 1;
        if span > self.cfg.max_query_points as u128 {
            return Err(TsError::TooMany(self.cfg.max_query_points));
        }
        let mut b: BTreeMap<i64, Bucket> = BTreeMap::new();
        let key = |t: i64| t.div_euclid(step) * step;
        let add = |b: &mut BTreeMap<i64, Bucket>, t: i64, v: f64| {
            b.entry(key(t))
                .or_insert_with(|| Bucket::new(key(t)))
                .add(t, v);
        };
        for c in self.series_chunks(series) {
            let s = &c.summary;
            if s.t1 < from || s.t0 > to {
                continue;
            }
            if c.expired_by.is_some() {
                let k = key(s.t0);
                let e = b.entry(k).or_insert_with(|| Bucket::new(k));
                if key(s.t1) == k && s.t0 >= from && s.t1 <= to {
                    e.add_summary(s);
                } else {
                    e.partial = true;
                }
                continue;
            }
            for (t, v) in self.load(c)? {
                if t >= from && t <= to {
                    add(&mut b, t, v);
                }
            }
        }
        if let Some(windows) = self.open.get(series) {
            for pts in windows.values() {
                for p in pts.iter().filter(|p| p.t >= from && p.t <= to) {
                    add(&mut b, p.t, p.v);
                }
            }
        }
        Ok(b.into_values()
            .map(|mut x| {
                x.avg = (x.count > 0).then(|| x.sum / x.count as f64);
                x
            })
            .collect())
    }

    /// Inclusion of the first point at time `t` in its chunk's `pointsRoot`.
    pub fn point_proof(&self, series: &str, t: i64) -> Result<PointProofParts, TsError> {
        validate_series(series)?;
        for c in self.series_chunks(series) {
            if t < c.summary.t0 || t > c.summary.t1 {
                continue;
            }
            if c.expired_by.is_some() {
                continue;
            }
            let pts = self.load(c)?;
            if let Some(i) = pts.iter().position(|p| p.0 == t) {
                let tree = MerkleTree::from_leaves(pts.iter().map(|&(t, v)| point_leaf(t, v)));
                let n = pts.len() as u64;
                return Ok(PointProofParts {
                    chunk_event: c.event_id,
                    index: i as u64,
                    count: n,
                    value: pts[i].1,
                    inclusion: tree.inclusion_proof(i as u64, n),
                });
            }
        }
        let unsealed = self
            .open
            .get(series)
            .is_some_and(|w| w.values().flatten().any(|p| p.t == t));
        if unsealed {
            return Err(TsError::NotSealed);
        }
        let expired = self
            .series_chunks(series)
            .iter()
            .any(|c| c.expired_by.is_some() && t >= c.summary.t0 && t <= c.summary.t1);
        Err(TsError::NotFound(if expired {
            format!("{series}: the chunk holding that time was deleted by retention")
        } else {
            format!("{series}: no point at that time")
        }))
    }

    pub fn chunks(&self, series: &str) -> &[ChunkRef] {
        self.series_chunks(series)
    }

    pub fn series(&self) -> Vec<SeriesInfo> {
        let names: std::collections::BTreeSet<&String> =
            self.chunks.keys().chain(self.open.keys()).collect();
        names
            .into_iter()
            .map(|s| {
                let cs = self.series_chunks(s);
                let open: Vec<&Buffered> = self
                    .open
                    .get(s)
                    .map(|w| w.values().flatten().collect())
                    .unwrap_or_default();
                let ts = cs
                    .iter()
                    .flat_map(|c| [c.summary.t0, c.summary.t1])
                    .chain(open.iter().map(|p| p.t));
                let (first, last) =
                    ts.fold((None, None), |(a, b): (Option<i64>, Option<i64>), t| {
                        (
                            Some(a.map_or(t, |a| a.min(t))),
                            Some(b.map_or(t, |b| b.max(t))),
                        )
                    });
                SeriesInfo {
                    series: s.clone(),
                    chunks: cs.len(),
                    expired_chunks: cs.iter().filter(|c| c.expired_by.is_some()).count(),
                    sealed_points: cs.iter().map(|c| c.summary.count).sum(),
                    open_points: open.len(),
                    first,
                    last,
                    stored_bytes: cs
                        .iter()
                        .filter(|c| c.expired_by.is_none())
                        .map(|c| c.summary.bytes)
                        .sum(),
                }
            })
            .collect()
    }

    /// Check every live chunk file against its sealed summary, and that expired files are gone.
    pub fn verify(&self) -> Vec<Finding> {
        let mut f = Vec::new();
        for c in self.chunks.values().flatten() {
            let p = self.chunk_path(&c.summary);
            if c.expired_by.is_some() {
                if p.exists() {
                    f.push(Finding {
                        severity: "warning",
                        description: format!(
                            "chunk #{} of {} was logged as expired but its file still exists",
                            c.event_id, c.summary.series
                        ),
                    });
                }
                continue;
            }
            if let Err(e) = self.load(c) {
                f.push(Finding {
                    severity: "error",
                    description: e.to_string(),
                });
            }
        }
        f
    }
}

#[cfg(test)]
mod tests;
