//! Minimal UTC time helpers — RFC 3339 formatting without a time crate.
//!
//! Milestone 3 decision (docs/development/milestone-3.md section 3): audit
//! events and IPC results need RFC 3339 UTC timestamps, and nothing else.
//! One formatting function does not justify the dependency tree of `chrono`,
//! `time`, or `jiff` (budget + supply chain, PERFORMANCE_BUDGETS.md section
//! 6.2), so the civil-from-days conversion is hand-rolled here and unit
//! tested against known values.
//!
//! Scope limits, stated honestly:
//!
//! - Output is always UTC with a trailing `Z`, second precision (the
//!   `schemas/common/defs.json` timestamp pattern allows but does not
//!   require fractional seconds and offsets).
//! - Valid for the Unix-epoch range through year 9999 (four-digit years,
//!   matching the schema pattern). Punar does not schedule the year 10000
//!   problem into Milestone 3.
//! - [`is_rfc3339_timestamp`] mirrors the *schema pattern* (shape check),
//!   not calendar validity: `2026-13-40T99:99:99Z` matches the pattern and
//!   is accepted, exactly as the JSON Schema would accept it. It exists so
//!   Rust tests and validators agree with the shipped schema contract.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds per day.
const SECS_PER_DAY: u64 = 86_400;

/// Current time as an RFC 3339 UTC string, e.g. `2026-08-25T07:00:12Z`.
///
/// A system clock before the Unix epoch (broken RTC) clamps to
/// `1970-01-01T00:00:00Z` rather than panicking: a daemon must keep running
/// and auditing even with a bad clock.
pub fn utc_now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    rfc3339_utc_from_unix_seconds(secs)
}

/// Milliseconds since the Unix epoch (0 if the clock is before the epoch).
///
/// Used for audit event ids (`evt_<millis>x<counter>`, see
/// [`crate::audit::next_event_id`]).
pub fn unix_now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Format `secs` (seconds since the Unix epoch) as RFC 3339 UTC.
pub fn rfc3339_utc_from_unix_seconds(secs: u64) -> String {
    let days = (secs / SECS_PER_DAY) as i64;
    let second_of_day = secs % SECS_PER_DAY;
    let (year, month, day) = civil_from_days(days);
    let hour = second_of_day / 3_600;
    let minute = (second_of_day % 3_600) / 60;
    let second = second_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Convert days since 1970-01-01 to a (year, month, day) civil date.
///
/// Howard Hinnant's `civil_from_days` algorithm (public domain,
/// <https://howardhinnant.github.io/date_algorithms.html>), exact for the
/// proleptic Gregorian calendar.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // day of era, [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year, [0, 365]
    let mp = (5 * doy + 2) / 153; // month index March=0, [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (year + i64::from(month <= 2), month, day)
}

/// Shape-check a string against the `schemas/common/defs.json` timestamp
/// pattern: `^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$`.
///
/// Pattern parity with the shipped schema — not calendar validation (see
/// module docs).
pub fn is_rfc3339_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    // Fixed head: YYYY-MM-DDTHH:MM:SS (19 bytes) + at least "Z" (1 byte).
    if b.len() < 20 {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| b[range].iter().all(u8::is_ascii_digit);
    if !(digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && (b[10] == b'T' || b[10] == b't')
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19))
    {
        return false;
    }
    let mut pos = 19;
    // Optional fractional seconds: '.' then one or more digits.
    if b[pos] == b'.' {
        pos += 1;
        let start = pos;
        while pos < b.len() && b[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == start {
            return false;
        }
    }
    // Offset: 'Z'/'z' or +HH:MM / -HH:MM, then end of string.
    match b.get(pos) {
        Some(b'Z' | b'z') => pos + 1 == b.len(),
        Some(b'+' | b'-') => {
            pos + 6 == b.len()
                && digits(pos + 1..pos + 3)
                && b[pos + 3] == b':'
                && digits(pos + 4..pos + 6)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verified externally with `date -u -r <secs> +%Y-%m-%dT%H:%M:%SZ`.
    const KNOWN: [(u64, &str); 9] = [
        (0, "1970-01-01T00:00:00Z"),
        (86_399, "1970-01-01T23:59:59Z"),
        (68_169_600, "1972-02-29T00:00:00Z"), // first post-epoch leap day
        (951_782_400, "2000-02-29T00:00:00Z"), // 400-year-rule leap day
        (951_868_799, "2000-02-29T23:59:59Z"),
        (2_147_483_648, "2038-01-19T03:14:08Z"), // past the i32 rollover
        (4_102_444_800, "2100-01-01T00:00:00Z"), // 2100 is not a leap year
        (1_767_225_600, "2026-01-01T00:00:00Z"),
        (1_787_616_000, "2026-08-25T00:00:00Z"),
    ];

    #[test]
    fn formats_known_timestamps() {
        for (secs, expected) in KNOWN {
            assert_eq!(rfc3339_utc_from_unix_seconds(secs), expected, "secs={secs}");
        }
    }

    #[test]
    fn formatted_output_matches_the_schema_pattern() {
        for (secs, _) in KNOWN {
            let formatted = rfc3339_utc_from_unix_seconds(secs);
            assert!(is_rfc3339_timestamp(&formatted), "{formatted}");
        }
    }

    #[test]
    fn now_is_schema_valid_and_after_2026() {
        let now = utc_now_rfc3339();
        assert!(is_rfc3339_timestamp(&now), "{now}");
        assert!(now.as_str() >= "2026", "clock reports {now}");
    }

    #[test]
    fn day_boundaries_are_exact() {
        assert_eq!(
            rfc3339_utc_from_unix_seconds(86_400),
            "1970-01-02T00:00:00Z"
        );
        assert_eq!(
            rfc3339_utc_from_unix_seconds(951_868_800),
            "2000-03-01T00:00:00Z"
        );
    }

    #[test]
    fn pattern_accepts_schema_valid_shapes() {
        for ts in [
            "2026-08-24T12:00:00Z",
            "2026-08-24t12:00:00z",
            "2026-08-24T12:00:00.5Z",
            "2026-08-24T12:00:00.123456Z",
            "2026-08-24T12:00:00+02:00",
            "2026-08-24T12:00:00.5-07:30",
            // Pattern parity: shape-valid but calendar-nonsense values pass,
            // exactly as they pass the JSON Schema pattern.
            "2026-13-40T99:99:99Z",
        ] {
            assert!(is_rfc3339_timestamp(ts), "{ts} should match");
        }
    }

    #[test]
    fn pattern_rejects_invalid_shapes() {
        for ts in [
            "",
            "2026-08-24",
            "2026-08-24T12:00:00",      // no offset
            "2026-08-24 12:00:00Z",     // space separator
            "2026-08-24T12:00:00.Z",    // empty fraction
            "2026-08-24T12:00:00+0200", // offset without colon
            "2026-08-24T12:00:00+02",   // short offset
            "2026-08-24T12:00:00Zz",    // trailing garbage
            "26-08-24T12:00:00Z",       // two-digit year
            "2026-08-24T12:00:00Z ",    // trailing space
            "x026-08-24T12:00:00Z",
        ] {
            assert!(!is_rfc3339_timestamp(ts), "{ts} should not match");
        }
    }

    #[test]
    fn unix_now_millis_is_sane() {
        // 2026-01-01T00:00:00Z in millis; the clock must be past it.
        assert!(unix_now_millis() > 1_767_225_600_000);
    }
}
