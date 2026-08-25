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

/// Parse an RFC 3339 timestamp back to seconds since the Unix epoch.
///
/// Milestone 9 needs the inverse of [`rfc3339_utc_from_unix_seconds`]: an
/// approval carries `expires_at` as a schema-conformant string, and the
/// lazy expiry sweep (docs/api/ipc.md section 14.4) has to compare it with
/// the wall clock. Keeping the inverse here — hand-rolled, exact, tested
/// against the same table as the forward direction — keeps the "no time
/// crate" decision intact (module docs).
///
/// Accepts exactly what [`is_rfc3339_timestamp`] accepts: `Z`/`z` or a
/// `±HH:MM` offset, with optional fractional seconds (truncated, never
/// rounded — an expiry must not be reachable a millisecond early). Returns
/// `None` for anything that is not a well-formed timestamp, including
/// pattern-valid but calendar-invalid input such as `2026-13-40T…`, and for
/// pre-epoch instants. Callers treat `None` as "cannot be reasoned about",
/// which for an approval means **expired** — fail closed, never open.
pub fn unix_seconds_from_rfc3339(s: &str) -> Option<u64> {
    if !is_rfc3339_timestamp(s) {
        return None;
    }
    let b = s.as_bytes();
    let num = |range: std::ops::Range<usize>| -> i64 {
        s[range]
            .parse::<i64>()
            .expect("digits checked by the pattern")
    };
    let (year, month, day) = (num(0..4), num(5..7) as u32, num(8..10) as u32);
    let (hour, minute, second) = (num(11..13), num(14..16), num(17..19));
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 {
        return None; // 60 = leap second; clamped below, never rejected
    }
    let days = days_from_civil(year, month, day);
    let mut total = days * SECS_PER_DAY as i64 + hour * 3_600 + minute * 60 + second.min(59);

    // Offset suffix: skip optional fractional seconds first.
    let mut pos = 19;
    if b[pos] == b'.' {
        pos += 1;
        while pos < b.len() && b[pos].is_ascii_digit() {
            pos += 1;
        }
    }
    match b[pos] {
        b'Z' | b'z' => {}
        sign => {
            let offset = num(pos + 1..pos + 3) * 3_600 + num(pos + 4..pos + 6) * 60;
            // A local-time stamp is ahead of UTC by its offset, so subtract.
            total += if sign == b'+' { -offset } else { offset };
        }
    }
    u64::try_from(total).ok()
}

/// Days in `month` of `year` (proleptic Gregorian).
fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        _ => 0,
    }
}

/// Inverse of [`civil_from_days`] — Howard Hinnant's `days_from_civil`
/// (public domain, <https://howardhinnant.github.io/date_algorithms.html>).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = year - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64; // [0, 399]
    let m = month as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day as u64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe as i64 - 719_468
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

    /// The M9 inverse must round-trip every value the forward direction is
    /// pinned against — an approval's expiry is only as trustworthy as this.
    #[test]
    fn rfc3339_round_trips_through_unix_seconds() {
        for (secs, text) in KNOWN {
            assert_eq!(unix_seconds_from_rfc3339(text), Some(secs), "{text}");
            assert_eq!(rfc3339_utc_from_unix_seconds(secs), text);
        }
    }

    #[test]
    fn offsets_and_fractions_normalize_to_utc() {
        // 12:00:00+02:00 is 10:00:00Z; -07:30 is 19:30:00Z.
        let noon_utc = unix_seconds_from_rfc3339("2026-08-24T10:00:00Z").unwrap();
        assert_eq!(
            unix_seconds_from_rfc3339("2026-08-24T12:00:00+02:00"),
            Some(noon_utc)
        );
        assert_eq!(
            unix_seconds_from_rfc3339("2026-08-24T02:30:00-07:30"),
            Some(noon_utc)
        );
        // Fractional seconds truncate: an expiry never arrives early.
        assert_eq!(
            unix_seconds_from_rfc3339("2026-08-24T10:00:00.999Z"),
            Some(noon_utc)
        );
        assert_eq!(
            unix_seconds_from_rfc3339("2026-08-24t10:00:00z"),
            Some(noon_utc)
        );
    }

    /// Pattern parity is deliberate in [`is_rfc3339_timestamp`]; the parser
    /// is stricter, because arithmetic on `2026-13-40` is not a number an
    /// expiry decision may rest on. `None` means "fail closed".
    #[test]
    fn unparsable_and_calendar_invalid_input_is_none() {
        for ts in [
            "",
            "2026-13-40T99:99:99Z",
            "2026-02-30T00:00:00Z",
            "2025-02-29T00:00:00Z", // 2025 is not a leap year
            "2026-00-10T00:00:00Z",
            "2026-08-24T24:00:00Z",
            "2026-08-24T12:60:00Z",
            "2026-08-24T12:00:00", // no offset
            "not a timestamp",
        ] {
            assert_eq!(unix_seconds_from_rfc3339(ts), None, "{ts}");
        }
        // 2024 is a leap year, so this one parses.
        assert!(unix_seconds_from_rfc3339("2024-02-29T00:00:00Z").is_some());
    }
}
