//! Chunk files: `"VTSC" ‖ 0x01 ‖ u16 series length ‖ series ‖ i64 window ‖ u32 count ‖ gorilla`.
//! All integers are big-endian. The file's SHA-256 and the Merkle root over its points are recorded
//! in the `chunk-sealed` event, so a chunk is checked against the log on every read.

use crate::gorilla;
use vesdb_core::{
    sha256,
    time::rfc3339_ns,
    ts::{points_root, ChunkSummary, CODEC},
};

const MAGIC: &[u8; 5] = b"VTSC\x01";

/// Build a chunk from points sorted by time.
pub fn build(
    series: &str,
    window: i64,
    points: &[(i64, f64)],
    wal_hi: u64,
    late: bool,
) -> (Vec<u8>, ChunkSummary) {
    assert!(!points.is_empty(), "a chunk holds at least one point");
    let mut b = Vec::with_capacity(32 + series.len() + points.len() * 2);
    b.extend_from_slice(MAGIC);
    b.extend_from_slice(&(series.len() as u16).to_be_bytes());
    b.extend_from_slice(series.as_bytes());
    b.extend_from_slice(&window.to_be_bytes());
    b.extend_from_slice(&(points.len() as u32).to_be_bytes());
    b.extend_from_slice(&gorilla::encode(points));
    let (mut min, mut max, mut sum) = (f64::INFINITY, f64::NEG_INFINITY, 0.0);
    for &(_, v) in points {
        min = min.min(v);
        max = max.max(v);
        sum += v;
    }
    let (t0, t1) = (points[0].0, points[points.len() - 1].0);
    let s = ChunkSummary {
        series: series.to_string(),
        window,
        t0,
        t1,
        from: rfc3339_ns(t0 as u64),
        to: rfc3339_ns(t1 as u64),
        count: points.len() as u64,
        min,
        max,
        sum,
        first: points[0].1,
        last: points[points.len() - 1].1,
        points_root: hex::encode(points_root(points)),
        sha256: hex::encode(sha256(&[&b])),
        bytes: b.len() as u64,
        codec: CODEC.into(),
        wal_hi,
        late,
    };
    (b, s)
}

/// Decode a chunk file and check it against its sealed summary: file hash, header, point count,
/// Merkle root and the recorded aggregates.
pub fn read(bytes: &[u8], s: &ChunkSummary) -> Result<Vec<(i64, f64)>, String> {
    if hex::encode(sha256(&[bytes])) != s.sha256 {
        return Err("file hash differs from the sealed chunk-sealed event".into());
    }
    if bytes.len() < MAGIC.len() + 2 || &bytes[..MAGIC.len()] != MAGIC {
        return Err("not a vesdb chunk file".into());
    }
    let mut p = MAGIC.len();
    let take = |p: &mut usize, n: usize| -> Result<&[u8], String> {
        let r = bytes.get(*p..*p + n).ok_or("chunk header truncated")?;
        *p += n;
        Ok(r)
    };
    let sl = u16::from_be_bytes(take(&mut p, 2)?.try_into().unwrap()) as usize;
    let series = take(&mut p, sl)?;
    let window = i64::from_be_bytes(take(&mut p, 8)?.try_into().unwrap());
    let count = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
    if series != s.series.as_bytes() || window != s.window || count as u64 != s.count {
        return Err("chunk header differs from its summary".into());
    }
    let pts = gorilla::decode(&bytes[p..], count).ok_or("chunk payload does not decode")?;
    if hex::encode(points_root(&pts)) != s.points_root {
        return Err("points do not match pointsRoot".into());
    }
    if pts.first().map(|x| x.0) != Some(s.t0) || pts.last().map(|x| x.0) != Some(s.t1) {
        return Err("time range differs from the summary".into());
    }
    Ok(pts)
}
