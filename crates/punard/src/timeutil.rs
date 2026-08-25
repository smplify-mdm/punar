//! RFC 3339 UTC timestamps without a time crate.
//!
//! INTERFACE NOTE (for the M3 integrate agent): the plan of record
//! (docs/development/milestone-3.md section 3) places `utc_now_rfc3339()` in
//! `punar-common`, which is being written concurrently. This module is the
//! same function living temporarily in `punard`; when
//! `punar_common::utc_now_rfc3339` (or equivalent) lands, delete this file
//! and re-point the two call sites (`server.rs`, `audit.rs`) — the signature
//! here (`fn utc_now_rfc3339() -> String`) is the planned one.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current UTC time as an RFC 3339 string with second precision, e.g.
/// `2026-08-25T07:00:12Z`. Matches the audit schema's timestamp pattern.
pub fn utc_now_rfc3339() -> String {
    rfc3339_from_unix(unix_now_secs())
}

/// Seconds since the Unix epoch (0 if the clock is before the epoch).
pub fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Milliseconds since the Unix epoch (0 if the clock is before the epoch).
pub fn unix_now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Format a non-negative Unix timestamp as RFC 3339 UTC (`...Z`).
///
/// Uses Howard Hinnant's civil-from-days algorithm; unit-tested against
/// known calendar values including leap days.
pub fn rfc3339_from_unix(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Days since 1970-01-01 to (year, month, day) in the proleptic Gregorian
/// calendar. Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_timestamps_format_correctly() {
        assert_eq!(rfc3339_from_unix(0), "1970-01-01T00:00:00Z");
        // Leap day of a century leap year.
        assert_eq!(rfc3339_from_unix(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339_from_unix(1_609_459_199), "2020-12-31T23:59:59Z");
        assert_eq!(rfc3339_from_unix(1_609_459_200), "2021-01-01T00:00:00Z");
        // The M3 era, cross-checked with `date -j -f ... +%s`.
        assert_eq!(rfc3339_from_unix(1_787_616_000), "2026-08-25T00:00:00Z");
    }

    #[test]
    fn now_matches_schema_timestamp_pattern() {
        let now = utc_now_rfc3339();
        // ^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$ without a regex dependency.
        let b = now.as_bytes();
        assert_eq!(b.len(), 20, "{now}");
        for (i, c) in b.iter().enumerate() {
            match i {
                4 | 7 => assert_eq!(*c, b'-'),
                10 => assert_eq!(*c, b'T'),
                13 | 16 => assert_eq!(*c, b':'),
                19 => assert_eq!(*c, b'Z'),
                _ => assert!(c.is_ascii_digit(), "{now}"),
            }
        }
    }
}
