//! Gorilla compression (Pelkonen et al., VLDB 2015) for `(i64 ns, f64)` points.
//!
//! * Timestamps: first raw (64 bits), then delta-of-delta in buckets
//!   `0` | `10`+7 | `110`+9 | `1110`+12 | `11110`+32 | `11111`+64 bits, each a two's-complement
//!   range (the paper's ranges are shifted by one; this keeps decoding a plain sign extension). Arithmetic wraps, so every
//!   i64 sequence round-trips (the 64-bit escape covers any difference).
//! * Values: first raw (64 bits), then the XOR with the previous value: `0` for an identical value,
//!   `10` + meaningful bits when they fit the previous leading/trailing window, otherwise `11` +
//!   5 bits leading zeros + 6 bits length + meaningful bits.
//!
//! Decoding is bit-exact (NaN payloads, signed zeros), and it never panics on malformed input.

pub struct BitWriter {
    buf: Vec<u8>,
    /// bits used in the last byte (0 = no partial byte)
    used: u8,
}

impl Default for BitWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl BitWriter {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            used: 0,
        }
    }

    #[inline]
    pub fn bit(&mut self, b: bool) {
        if self.used == 0 {
            self.buf.push(0);
        }
        if b {
            *self.buf.last_mut().unwrap() |= 0x80 >> self.used;
        }
        self.used = (self.used + 1) % 8;
    }

    /// Write the low `n` bits of `v`, most significant first.
    #[inline]
    pub fn bits(&mut self, v: u64, n: u32) {
        debug_assert!(n <= 64);
        let mut left = n;
        while left > 0 {
            if self.used == 0 {
                self.buf.push(0);
            }
            let room = 8 - self.used as u32;
            let take = room.min(left);
            let chunk = ((v >> (left - take)) & ((1u64 << take) - 1)) as u8;
            *self.buf.last_mut().unwrap() |= chunk << (room - take);
            self.used = ((self.used as u32 + take) % 8) as u8;
            left -= take;
        }
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

pub struct BitReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[inline]
    pub fn bit(&mut self) -> Option<bool> {
        let byte = *self.buf.get(self.pos / 8)?;
        let b = byte & (0x80 >> (self.pos % 8)) != 0;
        self.pos += 1;
        Some(b)
    }

    #[inline]
    pub fn bits(&mut self, n: u32) -> Option<u64> {
        if n == 0 {
            return Some(0);
        }
        if self.pos + n as usize > self.buf.len() * 8 {
            return None;
        }
        let mut v = 0u64;
        let mut left = n;
        while left > 0 {
            let byte = self.buf[self.pos / 8];
            let off = (self.pos % 8) as u32;
            let avail = 8 - off;
            let take = avail.min(left);
            let chunk = (byte >> (avail - take)) as u64 & ((1u64 << take) - 1);
            v = (v << take) | chunk;
            self.pos += take as usize;
            left -= take;
        }
        Some(v)
    }
}

fn sign_extend(v: u64, n: u32) -> i64 {
    let shift = 64 - n;
    ((v << shift) as i64) >> shift
}

/// Encode points (times need not be sorted; any i64 works).
pub fn encode(points: &[(i64, f64)]) -> Vec<u8> {
    let mut w = BitWriter::new();
    let Some(&(t0, v0)) = points.first() else {
        return w.finish();
    };
    w.bits(t0 as u64, 64);
    w.bits(v0.to_bits(), 64);
    let (mut pt, mut pd) = (t0, 0i64);
    let (mut pv, mut lead, mut trail) = (v0.to_bits(), u32::MAX, 0u32);
    for &(t, v) in &points[1..] {
        let d = t.wrapping_sub(pt);
        let dod = d.wrapping_sub(pd);
        match dod {
            0 => w.bit(false),
            -64..=63 => {
                w.bits(0b10, 2);
                w.bits(dod as u64, 7);
            }
            -256..=255 => {
                w.bits(0b110, 3);
                w.bits(dod as u64, 9);
            }
            -2048..=2047 => {
                w.bits(0b1110, 4);
                w.bits(dod as u64, 12);
            }
            -2_147_483_648..=2_147_483_647 => {
                w.bits(0b11110, 5);
                w.bits(dod as u64, 32);
            }
            _ => {
                w.bits(0b11111, 5);
                w.bits(dod as u64, 64);
            }
        }
        (pt, pd) = (t, d);

        let bits = v.to_bits();
        let x = bits ^ pv;
        if x == 0 {
            w.bit(false);
        } else {
            let l = x.leading_zeros().min(31);
            let tr = x.trailing_zeros();
            if lead != u32::MAX && l >= lead && tr >= trail {
                w.bits(0b10, 2);
                w.bits(x >> trail, 64 - lead - trail);
            } else {
                let len = 64 - l - tr; // 1..=64
                w.bits(0b11, 2);
                w.bits(l as u64, 5);
                w.bits((len % 64) as u64, 6); // 64 is stored as 0
                w.bits(x >> tr, len);
                (lead, trail) = (l, tr);
            }
        }
        pv = bits;
    }
    w.finish()
}

/// Decode `count` points. `None` on truncated or malformed input.
pub fn decode(buf: &[u8], count: usize) -> Option<Vec<(i64, f64)>> {
    let mut out = Vec::with_capacity(count.min(1 << 20));
    if count == 0 {
        return Some(out);
    }
    let mut r = BitReader::new(buf);
    let t0 = r.bits(64)? as i64;
    let v0 = r.bits(64)?;
    out.push((t0, f64::from_bits(v0)));
    let (mut pt, mut pd) = (t0, 0i64);
    let (mut pv, mut lead, mut trail) = (v0, 0u32, 0u32);
    let mut have_window = false;
    for _ in 1..count {
        let dod = if !r.bit()? {
            0
        } else if !r.bit()? {
            sign_extend(r.bits(7)?, 7)
        } else if !r.bit()? {
            sign_extend(r.bits(9)?, 9)
        } else if !r.bit()? {
            sign_extend(r.bits(12)?, 12)
        } else if !r.bit()? {
            sign_extend(r.bits(32)?, 32)
        } else {
            r.bits(64)? as i64
        };
        let d = pd.wrapping_add(dod);
        let t = pt.wrapping_add(d);
        (pt, pd) = (t, d);

        let bits = if !r.bit()? {
            pv
        } else if !r.bit()? {
            if !have_window {
                return None;
            }
            let m = r.bits(64 - lead - trail)?;
            pv ^ (m << trail)
        } else {
            let l = r.bits(5)? as u32;
            let len = match r.bits(6)? as u32 {
                0 => 64,
                n => n,
            };
            if l + len > 64 {
                return None;
            }
            let tr = 64 - l - len;
            let m = r.bits(len)?;
            (lead, trail, have_window) = (l, tr, true);
            pv ^ (m << tr)
        };
        pv = bits;
        out.push((t, f64::from_bits(bits)));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn same(a: &[(i64, f64)], b: &[(i64, f64)]) -> bool {
        a.len() == b.len()
            && a.iter()
                .zip(b)
                .all(|(x, y)| x.0 == y.0 && x.1.to_bits() == y.1.to_bits())
    }

    #[test]
    fn special_values_round_trip() {
        let pts = vec![
            (0, 0.0),
            (1, -0.0),
            (2, f64::NAN),
            (3, f64::from_bits(0x7ff8_dead_beef_0001)),
            (i64::MAX, f64::INFINITY),
            (i64::MIN, f64::NEG_INFINITY),
            (5, f64::MIN_POSITIVE),
            (5, f64::MAX),
            (-7, 1.0),
            (-7, 1.0),
        ];
        assert!(same(&decode(&encode(&pts), pts.len()).unwrap(), &pts));
    }

    #[test]
    fn regular_sensor_data_compresses() {
        // 1 Hz H2S readings, slowly varying with 0.1 ppm resolution
        let t0 = 1_762_000_000_000_000_000i64;
        let pts: Vec<(i64, f64)> = (0..3600)
            .map(|i| {
                let v = ((i as f64 / 300.0).sin() * 20.0).round() / 10.0 + 2.0;
                (t0 + i * 1_000_000_000, v)
            })
            .collect();
        let enc = encode(&pts);
        let bpp = enc.len() as f64 / pts.len() as f64;
        assert!(same(&decode(&enc, pts.len()).unwrap(), &pts));
        assert!(bpp < 4.0, "{bpp} bytes/point");
        // constant series at a fixed interval: ~2 bits/point
        let flat: Vec<(i64, f64)> = (0..10_000).map(|i| (t0 + i * 10, 5.0)).collect();
        assert!(encode(&flat).len() < 10_000 / 4 + 32);
    }

    #[test]
    fn malformed_input_is_rejected_not_panicking() {
        let pts: Vec<(i64, f64)> = (0..100).map(|i| (i * 7, i as f64 * 0.37)).collect();
        let enc = encode(&pts);
        for cut in 0..enc.len() {
            let _ = decode(&enc[..cut], pts.len());
        }
        assert!(decode(&enc[..enc.len() / 2], pts.len()).is_none());
        let junk: Vec<u8> = (0..64u8).map(|i| i.wrapping_mul(37)).collect();
        let _ = decode(&junk, 1000);
    }

    proptest! {
        #[test]
        fn any_points_round_trip(pts in proptest::collection::vec((any::<i64>(), any::<u64>()), 0..300)) {
            let pts: Vec<(i64, f64)> = pts.into_iter().map(|(t, b)| (t, f64::from_bits(b))).collect();
            let back = decode(&encode(&pts), pts.len()).unwrap();
            prop_assert!(same(&back, &pts));
        }

        #[test]
        fn near_regular_points_round_trip(start in any::<i64>(), steps in proptest::collection::vec((-3000i64..3000, -50i32..50), 1..500)) {
            let mut t = start;
            let mut v = 100.0f64;
            let mut pts = Vec::new();
            for (dt, dv) in steps {
                t = t.wrapping_add(1_000_000_000 + dt);
                v += dv as f64 * 0.01;
                pts.push((t, v));
            }
            let back = decode(&encode(&pts), pts.len()).unwrap();
            prop_assert!(same(&back, &pts));
        }
    }
}
