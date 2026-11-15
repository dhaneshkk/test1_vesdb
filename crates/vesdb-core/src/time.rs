//! RFC 3339 timestamps with nanosecond precision, UTC (what EventSourcingDB returns).

use std::time::{SystemTime, UNIX_EPOCH};

/// Nanoseconds since 1970-01-01T00:00:00Z.
pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Days since epoch -> (year, month, day). Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// `2026-11-11T10:42:07.310000000Z`
pub fn rfc3339_ns(t_ns: u64) -> String {
    let secs = (t_ns / 1_000_000_000) as i64;
    let ns = t_ns % 1_000_000_000;
    let (y, mo, d) = civil_from_days(secs.div_euclid(86_400));
    let sod = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}.{ns:09}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.fraction]Z` (UTC only).
pub fn parse_rfc3339_ns(s: &str) -> Option<u64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut dp = date.split('-');
    let y: i64 = dp.next()?.parse().ok()?;
    let mo: u32 = dp.next()?.parse().ok()?;
    let d: u32 = dp.next()?.parse().ok()?;
    let (hms, frac) = match time.split_once('.') {
        Some((a, b)) => (a, b),
        None => (time, ""),
    };
    let mut tp = hms.split(':');
    let h: u64 = tp.next()?.parse().ok()?;
    let mi: u64 = tp.next()?.parse().ok()?;
    let se: u64 = tp.next()?.parse().ok()?;
    if frac.len() > 9 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let ns: u64 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<9}").parse().ok()?
    };
    let days = days_from_civil(y, mo, d);
    if days < 0 {
        return None;
    }
    Some((days as u64 * 86_400 + h * 3600 + mi * 60 + se) * 1_000_000_000 + ns)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let t = 1_794_393_727_310_000_000u64; // 2026-11-11T10:42:07.31Z
        let s = rfc3339_ns(t);
        assert_eq!(s, "2026-11-11T10:42:07.310000000Z");
        assert_eq!(parse_rfc3339_ns(&s), Some(t));
        assert_eq!(rfc3339_ns(0), "1970-01-01T00:00:00.000000000Z");
    }
}
