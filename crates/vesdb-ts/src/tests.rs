use super::*;
use vesdb_core::ts::{points_root, POINT_PROOF_FORMAT};

const S: i64 = 1_000_000_000;
const T0: i64 = 1_762_000_020 * S; // a window boundary for 60 s windows
const H2S: &str = "rig-07/gas/h2s";

/// Stand-in for the event log: `(id, type, data)`.
#[derive(Default)]
struct Log(Vec<(u64, String, String)>);

impl Log {
    fn append(&mut self, ty: &str, data: String) -> u64 {
        let id = self.0.len() as u64;
        self.0.push((id, ty.into(), data));
        id
    }
    fn view(&self) -> impl Iterator<Item = (u64, &str, Option<&str>)> {
        self.0
            .iter()
            .map(|(i, t, d)| (*i, t.as_str(), Some(d.as_str())))
    }
}

fn cfg(dir: &Path) -> TsConfig {
    TsConfig {
        fsync: false,
        ..TsConfig::new(dir)
    }
}

fn seal(e: &mut TsEngine, log: &mut Log, now: i64, force: bool) -> Vec<u64> {
    let pending = e.prepare_seals(now, force).unwrap();
    let done: Vec<(PendingSeal, u64)> = pending
        .into_iter()
        .map(|p| {
            let id = log.append(p.event_type(), p.data());
            (p, id)
        })
        .collect();
    let ids = done.iter().map(|d| d.1).collect();
    e.commit_seals(done).unwrap();
    ids
}

fn ramp(series: &str, from_s: i64, n: i64) -> (String, Vec<(i64, f64)>) {
    (
        series.into(),
        (0..n)
            .map(|i| (T0 + (from_s + i) * S, i as f64 * 0.5))
            .collect(),
    )
}

#[test]
fn seal_query_and_point_proof() {
    let d = tempfile::tempdir().unwrap();
    let mut log = Log::default();
    let (mut e, _) = TsEngine::open(cfg(d.path()), log.view()).unwrap();
    e.write(&[ramp(H2S, 0, 150)]).unwrap(); // windows 0, 60, 120 s
                                            // only windows closed by now+grace are sealed
    let ids = seal(&mut e, &mut log, T0 + 125 * S, false);
    assert_eq!(ids.len(), 2);
    assert_eq!(e.buffered(), 30);
    let r = e.query(H2S, T0, T0 + 200 * S).unwrap();
    assert_eq!(r.points.len(), 150, "sealed and open points merge");
    assert!(r.points.windows(2).all(|w| w[0].0 <= w[1].0));
    let s: ChunkSummary = serde_json::from_str(&log.0[0].2).unwrap();
    assert_eq!((s.count, s.t0, s.t1, s.window), (60, T0, T0 + 59 * S, T0));
    assert_eq!((s.min, s.max, s.first, s.last), (0.0, 29.5, 0.0, 29.5));
    assert!(!s.late);

    let p = e.point_proof(H2S, T0 + 75 * S).unwrap();
    assert_eq!(
        (p.chunk_event, p.index, p.count, p.value),
        (ids[1], 15, 60, 37.5)
    );
    let s1: ChunkSummary = serde_json::from_str(&log.0[1].2).unwrap();
    let root: Hash = hex::decode(&s1.points_root).unwrap().try_into().unwrap();
    assert!(vesdb_core::merkle::verify_inclusion(
        p.index,
        p.count,
        &point_leaf(T0 + 75 * S, 37.5),
        &p.inclusion,
        &root
    ));
    assert!(!vesdb_core::merkle::verify_inclusion(
        p.index,
        p.count,
        &point_leaf(T0 + 75 * S, 37.6),
        &p.inclusion,
        &root
    ));
    assert!(matches!(
        e.point_proof(H2S, T0 + 130 * S),
        Err(TsError::NotSealed)
    ));
    let _ = POINT_PROOF_FORMAT;
}

#[test]
fn out_of_order_and_late_points() {
    let d = tempfile::tempdir().unwrap();
    let mut log = Log::default();
    let (mut e, _) = TsEngine::open(cfg(d.path()), log.view()).unwrap();
    // out of order inside one window: sealed sorted
    e.write(&[(
        H2S.into(),
        vec![(T0 + 30 * S, 3.0), (T0 + 10 * S, 1.0), (T0 + 20 * S, 2.0)],
    )])
    .unwrap();
    seal(&mut e, &mut log, T0 + 65 * S, false);
    // a late point for the sealed window becomes a second, late chunk
    e.write(&[(H2S.into(), vec![(T0 + 15 * S, 1.5)])]).unwrap();
    seal(&mut e, &mut log, T0 + 200 * S, false);
    let late: ChunkSummary = serde_json::from_str(&log.0[1].2).unwrap();
    assert!(late.late);
    let r = e.query(H2S, T0, T0 + 60 * S).unwrap();
    let ts: Vec<i64> = r.points.iter().map(|p| (p.0 - T0) / S).collect();
    assert_eq!(ts, vec![10, 15, 20, 30]);
    let b = e.downsample(H2S, T0, T0 + 59 * S, 60 * S).unwrap();
    assert_eq!(b.len(), 1);
    assert_eq!(
        (b[0].count, b[0].first, b[0].last),
        (4, Some(1.0), Some(3.0))
    );
    assert_eq!(b[0].avg, Some(7.5 / 4.0));
}

#[test]
fn input_validation() {
    let d = tempfile::tempdir().unwrap();
    let (mut e, _) = TsEngine::open(cfg(d.path()), Log::default().view()).unwrap();
    for bad in ["", "/x", "x/", "a//b", "a b", "a.b", "ü"] {
        assert!(
            e.write(&[(bad.into(), vec![(T0, 1.0)])]).is_err(),
            "{bad:?}"
        );
    }
    assert!(e.write(&[(H2S.into(), vec![(T0, f64::NAN)])]).is_err());
    assert!(e.write(&[(H2S.into(), vec![(-1, 1.0)])]).is_err());
    assert_eq!(e.buffered(), 0, "a rejected write leaves nothing behind");
}

#[test]
fn crash_before_the_event_is_appended_keeps_points_and_drops_the_file() {
    let d = tempfile::tempdir().unwrap();
    let log = Log::default();
    {
        let (mut e, _) = TsEngine::open(cfg(d.path()), log.view()).unwrap();
        e.write(&[ramp(H2S, 0, 60)]).unwrap();
        let p = e.prepare_seals(T0 + 70 * S, false).unwrap();
        assert_eq!(p.len(), 1);
        // crash: chunk file on disk, no event in the log
    }
    let (e, f) = TsEngine::open(cfg(d.path()), log.view()).unwrap();
    assert_eq!(e.buffered(), 60);
    assert!(f
        .iter()
        .any(|x| x.description.contains("60 unsealed points recovered")));
    let files = walk(&d.path().join("chunks"));
    assert!(files.is_empty(), "orphan chunk file removed: {files:?}");
}

#[test]
fn crash_after_the_event_but_before_wal_compaction_does_not_duplicate() {
    let d = tempfile::tempdir().unwrap();
    let mut log = Log::default();
    {
        let (mut e, _) = TsEngine::open(cfg(d.path()), log.view()).unwrap();
        e.write(&[ramp(H2S, 0, 60)]).unwrap();
        e.write(&[ramp(H2S, 60, 10)]).unwrap();
        for p in e.prepare_seals(T0 + 70 * S, false).unwrap() {
            log.append(p.event_type(), p.data());
        }
        // crash: event appended, engine never told, WAL still holds every point
    }
    let (mut e, _) = TsEngine::open(cfg(d.path()), log.view()).unwrap();
    assert_eq!(e.buffered(), 10, "only the open window is replayed");
    assert_eq!(e.query(H2S, T0, T0 + 3600 * S).unwrap().points.len(), 70);
    // and new writes get batch numbers above everything sealed
    e.write(&[(H2S.into(), vec![(T0 + 5 * S, 9.0)])]).unwrap();
    seal(&mut e, &mut log, T0 + 1000 * S, false);
    assert_eq!(e.query(H2S, T0, T0 + 3600 * S).unwrap().points.len(), 71);
}

#[test]
fn torn_wal_tail_is_dropped_and_damage_refused() {
    let d = tempfile::tempdir().unwrap();
    {
        let (mut e, _) = TsEngine::open(cfg(d.path()), Log::default().view()).unwrap();
        e.write(&[ramp(H2S, 0, 5)]).unwrap();
        e.write(&[ramp(H2S, 5, 5)]).unwrap();
    }
    let wal = d.path().join("wal");
    let len = fs::metadata(&wal).unwrap().len();
    OpenOptions::new()
        .write(true)
        .open(&wal)
        .unwrap()
        .set_len(len - 3)
        .unwrap();
    let (e, _) = TsEngine::open(cfg(d.path()), Log::default().view()).unwrap();
    assert_eq!(
        e.buffered(),
        5,
        "acknowledged first batch kept, torn second dropped"
    );
    drop(e);
    let mut b = fs::read(&wal).unwrap();
    b[10] ^= 0xff; // damage inside the first frame, followed by nothing more: torn
    b.extend_from_slice(&[0; 40]); // ...now followed by more data: damage
    fs::write(&wal, b).unwrap();
    assert!(matches!(
        TsEngine::open(cfg(d.path()), Log::default().view()),
        Err(TsError::Damaged(_))
    ));
}

#[test]
fn tampered_chunk_is_detected_on_read_and_by_verify() {
    let d = tempfile::tempdir().unwrap();
    let mut log = Log::default();
    let (mut e, _) = TsEngine::open(cfg(d.path()), log.view()).unwrap();
    e.write(&[ramp(H2S, 0, 60)]).unwrap();
    seal(&mut e, &mut log, 0, true);
    assert!(e.verify().is_empty());
    let f = walk(&d.path().join("chunks")).pop().unwrap();
    // rewrite the file with a "corrected" reading, as an insider would
    let pts: Vec<(i64, f64)> = (0..60)
        .map(|i| (T0 + i * S, if i == 42 { 0.0 } else { i as f64 * 0.5 }))
        .collect();
    let (forged, _) = chunk::build(H2S, T0, &pts, 1, false);
    fs::write(&f, forged).unwrap();
    assert!(matches!(
        e.query(H2S, T0, T0 + 60 * S),
        Err(TsError::Tampered { .. })
    ));
    assert!(matches!(
        e.point_proof(H2S, T0 + 42 * S),
        Err(TsError::Tampered { .. })
    ));
    let v = e.verify();
    assert_eq!(v.len(), 1);
    assert!(v[0].description.contains("file hash differs"), "{v:?}");
}

#[test]
fn retention_deletes_files_keeps_summaries_and_survives_restart() {
    let d = tempfile::tempdir().unwrap();
    let mut log = Log::default();
    let (mut e, _) = TsEngine::open(cfg(d.path()), log.view()).unwrap();
    e.write(&[ramp(H2S, 0, 180)]).unwrap();
    seal(&mut e, &mut log, 0, true);
    let x = e.prepare_expiry(T0 + 120 * S, "90-day retention");
    assert_eq!(x.len(), 2);
    let done: Vec<_> = x
        .into_iter()
        .map(|p| {
            let id = log.append(p.event_type(), p.data());
            (p, id)
        })
        .collect();
    e.commit_expiry(done).unwrap();
    assert_eq!(walk(&d.path().join("chunks")).len(), 1);
    let r = e.query(H2S, T0, T0 + 200 * S).unwrap();
    assert_eq!((r.points.len(), r.expired.len()), (60, 2));
    // per-minute aggregates are still exact from the sealed summaries
    let b = e.downsample(H2S, T0, T0 + 179 * S, 60 * S).unwrap();
    assert_eq!(
        b.iter().map(|b| b.count).collect::<Vec<_>>(),
        vec![60, 60, 60]
    );
    assert!(b[0].from_summaries && !b[0].partial && !b[2].from_summaries);
    assert_eq!(b[1].max, Some(59.5));
    // 30 s buckets cannot be answered from 60 s summaries
    let b = e.downsample(H2S, T0, T0 + 179 * S, 30 * S).unwrap();
    assert!(b[0].partial);
    assert!(matches!(
        e.point_proof(H2S, T0 + 5 * S),
        Err(TsError::NotFound(_))
    ));
    drop(e);
    let (e, _) = TsEngine::open(cfg(d.path()), log.view()).unwrap();
    assert!(e.verify().is_empty());
    assert_eq!(e.series()[0].expired_chunks, 2);
    assert_eq!(e.series()[0].sealed_points, 180);
}

#[test]
fn compression_and_throughput() {
    let d = tempfile::tempdir().unwrap();
    let mut log = Log::default();
    let (mut e, _) = TsEngine::open(cfg(d.path()), log.view()).unwrap();
    // 100 sensors x 1 Hz x 1 hour, 0.01 resolution
    let n_series = 100;
    let secs = 3600;
    let t = std::time::Instant::now();
    for chunk in 0..(secs / 60) {
        let batches: Vec<(String, Vec<(i64, f64)>)> = (0..n_series)
            .map(|k| {
                (
                    format!("rig-07/sensor-{k:03}"),
                    (0..60)
                        .map(|i| {
                            let s = chunk * 60 + i;
                            let v = (20.0 + (s as f64 / 600.0 + k as f64).sin() * 5.0) * 100.0;
                            (T0 + s * S, v.round() / 100.0)
                        })
                        .collect(),
                )
            })
            .collect();
        e.write(&batches).unwrap();
    }
    let write = t.elapsed();
    let t = std::time::Instant::now();
    seal(&mut e, &mut log, 0, true);
    let sealing = t.elapsed();
    let points = (n_series * secs) as f64;
    let bytes: u64 = e.series().iter().map(|s| s.stored_bytes).sum();
    let t = std::time::Instant::now();
    let q = e.query("rig-07/sensor-007", T0, T0 + secs * S).unwrap();
    let query = t.elapsed();
    assert_eq!(q.points.len(), secs as usize);
    eprintln!(
        "{points} points: write {:.0} pts/s, seal {:.0} pts/s, {:.2} bytes/pt on disk (vs 16 raw), \
         {} chunks = {} log events, 1 h raw query {:?}",
        points / write.as_secs_f64(),
        points / sealing.as_secs_f64(),
        bytes as f64 / points,
        log.0.len(),
        log.0.len(),
        query
    );
    assert_eq!(
        log.0.len(),
        n_series as usize * 60,
        "one event per series per minute"
    );
    assert!((bytes as f64 / points) < 6.0);
    let s: ChunkSummary = serde_json::from_str(&log.0[0].2).unwrap();
    let pts = e.query(&s.series, s.t0, s.t1).unwrap().points;
    assert_eq!(hex::encode(points_root(&pts)), s.points_root);
}

fn walk(p: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    for d in fs::read_dir(p).unwrap() {
        let d = d.unwrap().path();
        if d.is_dir() {
            v.extend(walk(&d));
        } else {
            v.push(d);
        }
    }
    v
}
