//! Trusted time, phase P0a: expiry measured on the boot clock, never on the
//! wall clock (SMP-1405; the trusted-time model's migration table).
//!
//! # Why the wall clock decides nothing here
//!
//! A JIT privilege grant, a pending approval, a re-authentication ticket and
//! a brokered credential each promise "this lasts N seconds". Judged against
//! `CLOCK_REALTIME`, that promise is only as good as whoever last set the
//! clock: a DHCP-supplied NTP server, an SNTP man in the middle, or a person
//! with `timedated` could roll it back and keep every grant alive. The code
//! this replaces went further and read a clock it could not read as the far
//! past, which made everything live.
//!
//! So a window opens at a [`BootStamp`] and is judged against a later one:
//!
//! - **`boot_id`** is `/proc/sys/kernel/random/boot_id`, fresh at every boot.
//!   A stamp from another boot is not comparable, so the window is **closed**.
//!   Grants, pending approvals and tickets therefore lapse at reboot, which is
//!   the settled owner decision for this phase.
//! - **`raw_bt_ms`** is `CLOCK_MONOTONIC_RAW + (CLOCK_BOOTTIME −
//!   CLOCK_MONOTONIC)` in whole milliseconds: the raw oscillator, which NTP
//!   neither slews nor steps, plus the time the machine spent suspended, which
//!   the kernel measures itself. Nothing in user space can move it.
//!
//! Phase P0a is **monotonic-only**: no server anchor, no persisted floor, no
//! network. Those arrive with P1, and none of the consumers here need them,
//! because each of their windows is short and lives inside one boot.
//!
//! # The rule, in exact integers
//!
//! A window of `duration_ms` opened at `start` is live at `now` iff
//!
//! ```text
//! now.boot_id == start.boot_id
//!   and 0 <= now.raw_bt_ms - start.raw_bt_ms
//!   and now.raw_bt_ms - start.raw_bt_ms < duration_ms - ceil(duration_ms * 200 / 10^6)
//! ```
//!
//! Every rounding goes the safe way, so a window is judged closed **early**,
//! never late:
//!
//! - The oscillator may run up to [`DRIFT_PPM`] slow. Taking the ceiling of
//!   `duration_ms · δ` off the budget means a raw clock running that slow
//!   still closes the window before `duration_ms` of true time: if raw time
//!   `E` is below `D − ⌈D·δ⌉ ≤ D·(1 − δ)`, true time `E / (1 − δ)` is below
//!   `D`.
//! - Both stamps are floored to whole milliseconds, so the measured elapsed
//!   `e` can be up to one millisecond short of the true `E`. The comparison is
//!   strict: `e < B` between integers means `e + 1 ≤ B`, and `E < e + 1`, so
//!   `E < B`. The truncation is absorbed exactly, not approximately.
//! - Anything that cannot be measured is closed: an unreadable clock, an
//!   unreadable or malformed boot id, a stamp from another boot, a clock that
//!   went backwards, a negative stamp, a non-positive duration, and every
//!   overflow.
//!
//! Records carry their display `expires_at` on the wall clock as before, for
//! people to read. It is never compared with anything.

use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// Where the kernel publishes this boot's random identifier.
pub const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// The oscillator error every window is shortened by, in parts per million.
/// Commodity crystals stay well inside it; the allowance is what lets the
/// rule above say "never late" rather than "rarely late".
pub const DRIFT_PPM: i64 = 200;

const PPM: i64 = 1_000_000;
const NANOS_PER_MILLI: i128 = 1_000_000;
const NANOS_PER_SEC: i128 = 1_000_000_000;

/// A boot id is 36 bytes plus a newline; anything longer is not one.
const BOOT_ID_READ_LIMIT: u64 = 64;

/// How far the suspend offset may move across one reading before the reading
/// is retried. A suspend during the read moves it by the whole sleep; a
/// reading that straddled one is refused rather than guessed at.
const SUSPEND_TOLERANCE_NS: i128 = NANOS_PER_MILLI;
/// Readings attempted before the clock is reported unreadable.
const READ_ATTEMPTS: usize = 5;

/// One instant on this boot's raw clock.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootStamp {
    /// `/proc/sys/kernel/random/boot_id`, verbatim (lowercase UUID).
    pub boot_id: String,
    /// `CLOCK_MONOTONIC_RAW + (CLOCK_BOOTTIME − CLOCK_MONOTONIC)`, floored to
    /// whole milliseconds.
    pub raw_bt_ms: i64,
}

impl BootStamp {
    /// A stamp the rule can reason about: a UUID-shaped boot id and a
    /// non-negative raw time. Anything else closes every window it touches.
    pub fn is_well_formed(&self) -> bool {
        is_boot_id(&self.boot_id) && self.raw_bt_ms >= 0
    }
}

/// A window of `duration_ms` raw milliseconds that opened at `start`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootWindow {
    pub start: BootStamp,
    pub duration_ms: i64,
}

impl BootWindow {
    /// A window opening at `start`.
    pub fn new(start: BootStamp, duration_ms: i64) -> Self {
        BootWindow { start, duration_ms }
    }

    /// A window of `secs` seconds opening at `start`. A duration too large to
    /// count in milliseconds saturates; every caller clamps its duration to
    /// minutes or hours long before that could matter.
    pub fn of_secs(start: BootStamp, secs: u64) -> Self {
        BootWindow::new(start, secs_to_ms(secs))
    }

    /// A window of `secs` seconds opening now, or `None` when `clock` cannot
    /// be read — a window that cannot be dated must not be created at all.
    pub fn opening_now(clock: &dyn TrustedClock, secs: u64) -> Option<Self> {
        clock.now().map(|start| BootWindow::of_secs(start, secs))
    }

    /// Whether the window is still open at `now` (see the module rule).
    pub fn is_open(&self, now: Option<&BootStamp>) -> bool {
        is_within(&self.start, now, self.duration_ms)
    }

    /// Milliseconds the window stays open after `now`, or `None` once it is
    /// closed or cannot be judged. Measured against the drift-shortened
    /// budget, so it never promises more than [`BootWindow::is_open`] keeps.
    pub fn remaining_ms(&self, now: Option<&BootStamp>) -> Option<i64> {
        let elapsed = elapsed_ms(&self.start, now?)?;
        let left = live_budget_ms(self.duration_ms).checked_sub(elapsed)?;
        (left > 0).then_some(left)
    }
}

/// Raw milliseconds from `since` to `now`, or `None` when the two cannot be
/// compared: different boots, a malformed stamp, or a clock that went
/// backwards.
pub fn elapsed_ms(since: &BootStamp, now: &BootStamp) -> Option<i64> {
    if !since.is_well_formed() || !now.is_well_formed() || since.boot_id != now.boot_id {
        return None;
    }
    now.raw_bt_ms
        .checked_sub(since.raw_bt_ms)
        .filter(|elapsed| *elapsed >= 0)
}

/// `ceil(duration_ms · DRIFT_PPM / 10^6)`, the part of a window the drift
/// allowance takes back. Zero for a non-positive duration. Computed in `i128`
/// so no duration can overflow it.
pub fn drift_allowance_ms(duration_ms: i64) -> i64 {
    if duration_ms <= 0 {
        return 0;
    }
    let scaled = i128::from(duration_ms) * i128::from(DRIFT_PPM);
    let ceiling = (scaled + i128::from(PPM) - 1) / i128::from(PPM);
    // DRIFT_PPM < PPM, so the allowance is at most `duration_ms` and fits.
    i64::try_from(ceiling).unwrap_or(duration_ms)
}

/// Raw milliseconds a window of `duration_ms` is live for: the duration less
/// its drift allowance. Zero for a non-positive duration, which is therefore
/// never live.
pub fn live_budget_ms(duration_ms: i64) -> i64 {
    if duration_ms <= 0 {
        return 0;
    }
    duration_ms - drift_allowance_ms(duration_ms)
}

/// The module rule: live iff same boot and `elapsed < duration − drift`.
/// `now == None` (the clock could not be read) is never live.
pub fn is_within(since: &BootStamp, now: Option<&BootStamp>, duration_ms: i64) -> bool {
    let Some(now) = now else {
        return false;
    };
    elapsed_ms(since, now).is_some_and(|elapsed| elapsed < live_budget_ms(duration_ms))
}

/// Seconds to milliseconds, saturating at `i64::MAX`.
pub fn secs_to_ms(secs: u64) -> i64 {
    i64::try_from(secs.saturating_mul(1_000)).unwrap_or(i64::MAX)
}

/// `8-4-4-4-12` lowercase hexadecimal, exactly as the kernel prints it.
pub fn is_boot_id(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(b),
        })
}

/// Where "now" comes from. Injected so every consumer can be tested against a
/// clock the test moves, and so no consumer can reach the wall clock by
/// accident.
pub trait TrustedClock: Send + Sync + fmt::Debug {
    /// This boot's id and raw time, or `None` when either cannot be read.
    fn now(&self) -> Option<BootStamp>;
}

/// The machine's own clock: `boot_id` from procfs, raw time from
/// `clock_gettime(2)` through rustix's safe wrapper.
#[derive(Debug, Clone)]
pub struct SystemClock {
    boot_id_path: PathBuf,
}

impl Default for SystemClock {
    fn default() -> Self {
        SystemClock {
            boot_id_path: PathBuf::from(BOOT_ID_PATH),
        }
    }
}

impl SystemClock {
    /// The production clock.
    pub fn new() -> Self {
        SystemClock::default()
    }

    /// The production clock reading its boot id from somewhere else — for
    /// tests of the parse, never for a daemon.
    pub fn with_boot_id_path(path: impl Into<PathBuf>) -> Self {
        SystemClock {
            boot_id_path: path.into(),
        }
    }
}

impl TrustedClock for SystemClock {
    fn now(&self) -> Option<BootStamp> {
        let boot_id = read_boot_id(&self.boot_id_path)?;
        let raw_bt_ms = read_raw_bt_ms()?;
        Some(BootStamp { boot_id, raw_bt_ms })
    }
}

/// Read and validate a boot id file. Unreadable, oversized or malformed is
/// `None`, and `None` closes every window.
pub fn read_boot_id(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut text = String::new();
    file.take(BOOT_ID_READ_LIMIT)
        .read_to_string(&mut text)
        .ok()?;
    let id = text.strip_suffix('\n').unwrap_or(&text);
    is_boot_id(id).then(|| id.to_string())
}

/// `CLOCK_MONOTONIC_RAW + (CLOCK_BOOTTIME − CLOCK_MONOTONIC)`, floored to
/// milliseconds.
///
/// The suspend offset is read on both sides of the raw clock and must agree
/// to within a millisecond; a reading that a suspend (or a long preemption)
/// split is retried, and after [`READ_ATTEMPTS`] refusals the clock is
/// reported unreadable rather than guessed.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_raw_bt_ms() -> Option<i64> {
    use rustix::time::{ClockId, DynamicClockId, clock_gettime_dynamic};

    fn nanos(id: ClockId) -> Option<i128> {
        let ts = clock_gettime_dynamic(DynamicClockId::Known(id)).ok()?;
        let secs = i128::from(ts.tv_sec);
        let nsec = i128::from(ts.tv_nsec);
        if secs < 0 || !(0..NANOS_PER_SEC).contains(&nsec) {
            return None;
        }
        Some(secs * NANOS_PER_SEC + nsec)
    }
    fn suspended() -> Option<i128> {
        let boot = nanos(ClockId::Boottime)?;
        let mono = nanos(ClockId::Monotonic)?;
        // BOOTTIME never runs behind MONOTONIC; the read order can only make
        // the difference a hair small, never negative in truth.
        Some((boot - mono).max(0))
    }

    for _ in 0..READ_ATTEMPTS {
        let before = suspended()?;
        let raw = nanos(ClockId::MonotonicRaw)?;
        let after = suspended()?;
        if (after - before).abs() <= SUSPEND_TOLERANCE_NS {
            let total = raw.checked_add(before)?;
            return i64::try_from(total.div_euclid(NANOS_PER_MILLI)).ok();
        }
    }
    None
}

/// No boot clock outside Linux: every window is closed.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn read_raw_bt_ms() -> Option<i64> {
    None
}

/// A clock a test moves by hand. Production never constructs one: no daemon
/// reads it from a flag, a file or the environment, exactly like the test
/// clocks the daemons already carry.
#[derive(Debug)]
pub struct ManualClock {
    state: Mutex<Option<BootStamp>>,
}

impl ManualClock {
    /// A clock reading `boot_id` at `raw_bt_ms`.
    pub fn new(boot_id: &str, raw_bt_ms: i64) -> Self {
        ManualClock {
            state: Mutex::new(Some(BootStamp {
                boot_id: boot_id.to_string(),
                raw_bt_ms,
            })),
        }
    }

    fn with_state<R>(&self, f: impl FnOnce(&mut Option<BootStamp>) -> R) -> R {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }

    /// Move the raw clock by `ms` (negative moves it back, which the rule
    /// treats as unmeasurable). Saturates rather than wrapping.
    pub fn advance_ms(&self, ms: i64) {
        self.with_state(|state| {
            if let Some(stamp) = state {
                stamp.raw_bt_ms = stamp.raw_bt_ms.saturating_add(ms);
            }
        });
    }

    /// Move the raw clock by `secs` seconds.
    pub fn advance_secs(&self, secs: u64) {
        self.advance_ms(secs_to_ms(secs));
    }

    /// Simulate a reboot: a new boot id and a raw clock starting again.
    pub fn reboot(&self, boot_id: &str, raw_bt_ms: i64) {
        self.set(Some(BootStamp {
            boot_id: boot_id.to_string(),
            raw_bt_ms,
        }));
    }

    /// Make the clock unreadable (`None`), or readable again.
    pub fn set(&self, stamp: Option<BootStamp>) {
        self.with_state(|state| *state = stamp);
    }
}

impl TrustedClock for ManualClock {
    fn now(&self) -> Option<BootStamp> {
        self.with_state(|state| state.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT_A: &str = "0f2a6c1e-7d3b-4a59-9c8e-1b2d3e4f5a6b";
    const BOOT_B: &str = "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b";

    fn at(boot_id: &str, raw_bt_ms: i64) -> BootStamp {
        BootStamp {
            boot_id: boot_id.to_string(),
            raw_bt_ms,
        }
    }

    #[test]
    fn the_drift_allowance_is_a_ceiling_and_never_zero_for_a_real_window() {
        assert_eq!(drift_allowance_ms(0), 0);
        assert_eq!(drift_allowance_ms(-5), 0);
        // Any positive window loses at least one millisecond.
        assert_eq!(drift_allowance_ms(1), 1);
        assert_eq!(drift_allowance_ms(4_999), 1);
        assert_eq!(drift_allowance_ms(5_000), 1);
        assert_eq!(drift_allowance_ms(5_001), 2);
        // The windows this phase migrates.
        assert_eq!(drift_allowance_ms(15_000), 3); // shortest approval TTL
        assert_eq!(drift_allowance_ms(120_000), 24); // re-auth ticket
        assert_eq!(drift_allowance_ms(300_000), 60); // default approval TTL
        assert_eq!(drift_allowance_ms(3_600_000), 720); // grant ceiling, credential
        assert_eq!(live_budget_ms(300_000), 299_940);
        assert_eq!(live_budget_ms(0), 0);
        assert_eq!(live_budget_ms(i64::MIN), 0);
    }

    /// The boundary is exact: live at `budget − 1`, closed at `budget`.
    #[test]
    fn the_boundary_is_exactly_duration_minus_drift() {
        for duration in [2_i64, 999, 15_000, 60_000, 120_000, 300_000, 3_600_000] {
            let budget = duration - drift_allowance_ms(duration);
            let start = at(BOOT_A, 1_000);
            let window = BootWindow::new(start.clone(), duration);
            assert!(
                window.is_open(Some(&at(BOOT_A, 1_000 + budget - 1))),
                "{duration}: one millisecond before the budget is live"
            );
            assert!(
                !window.is_open(Some(&at(BOOT_A, 1_000 + budget))),
                "{duration}: the budget itself is closed"
            );
            assert!(
                !window.is_open(Some(&at(BOOT_A, 1_000 + duration - 1))),
                "{duration}: judged closed early, never at the wall duration"
            );
            assert_eq!(
                window.remaining_ms(Some(&at(BOOT_A, 1_000 + budget - 1))),
                Some(1)
            );
            assert_eq!(window.remaining_ms(Some(&at(BOOT_A, 1_000 + budget))), None);
        }
        // Opened this instant: live, for a positive duration.
        let window = BootWindow::of_secs(at(BOOT_A, 0), 1);
        assert!(window.is_open(Some(&at(BOOT_A, 0))));
    }

    #[test]
    fn another_boot_closes_the_window() {
        let window = BootWindow::of_secs(at(BOOT_A, 5_000), 3_600);
        assert!(window.is_open(Some(&at(BOOT_A, 5_001))));
        // After a reboot the raw clock starts again near zero — a naive
        // comparison would call that "no time has passed".
        assert!(!window.is_open(Some(&at(BOOT_B, 5_001))));
        assert!(!window.is_open(Some(&at(BOOT_B, 0))));
        assert_eq!(elapsed_ms(&at(BOOT_A, 0), &at(BOOT_B, 10)), None);
    }

    #[test]
    fn a_clock_that_went_backwards_closes_the_window() {
        let window = BootWindow::of_secs(at(BOOT_A, 10_000), 300);
        assert!(!window.is_open(Some(&at(BOOT_A, 9_999))));
        assert_eq!(elapsed_ms(&at(BOOT_A, 10_000), &at(BOOT_A, 9_999)), None);
        assert_eq!(window.remaining_ms(Some(&at(BOOT_A, 9_999))), None);
    }

    #[test]
    fn a_clock_that_cannot_be_read_closes_every_window() {
        let window = BootWindow::of_secs(at(BOOT_A, 0), 3_600);
        assert!(!window.is_open(None));
        assert_eq!(window.remaining_ms(None), None);

        let clock = ManualClock::new(BOOT_A, 0);
        clock.set(None);
        assert_eq!(BootWindow::opening_now(&clock, 60), None);
        assert!(!window.is_open(clock.now().as_ref()));
    }

    #[test]
    fn malformed_stamps_and_durations_close_the_window() {
        let now = at(BOOT_A, 100);
        for start in [
            at("", 0),
            at("not-a-boot-id", 0),
            at(&BOOT_A.to_uppercase(), 0),
            at(&format!("{BOOT_A}\n"), 0),
            at(BOOT_A, -1),
        ] {
            assert!(!is_within(&start, Some(&now), 60_000), "{start:?}");
        }
        // A malformed *now* is no better.
        assert!(!is_within(&at(BOOT_A, 0), Some(&at("", 100)), 60_000));
        // A window with no length is never open, not even at its start.
        for duration in [0, -1, i64::MIN] {
            assert!(!is_within(&at(BOOT_A, 0), Some(&at(BOOT_A, 0)), duration));
        }
    }

    #[test]
    fn the_extremes_of_i64_neither_overflow_nor_open_a_window() {
        // Largest duration: the allowance is computed in i128.
        assert_eq!(drift_allowance_ms(i64::MAX), 1_844_674_407_370_956);
        assert_eq!(live_budget_ms(i64::MAX), i64::MAX - 1_844_674_407_370_956);
        // The whole raw range elapsed: measurable, and beyond any budget.
        let start = at(BOOT_A, 0);
        assert_eq!(elapsed_ms(&start, &at(BOOT_A, i64::MAX)), Some(i64::MAX));
        assert!(!is_within(&start, Some(&at(BOOT_A, i64::MAX)), i64::MAX));
        assert!(is_within(
            &start,
            Some(&at(BOOT_A, i64::MAX - 1_844_674_407_370_957)),
            i64::MAX
        ));
        // A start at the top of the range, a now at the bottom: backwards.
        assert_eq!(elapsed_ms(&at(BOOT_A, i64::MAX), &at(BOOT_A, 0)), None);
        // Negative stamps are refused before any subtraction could wrap.
        assert_eq!(
            elapsed_ms(&at(BOOT_A, i64::MIN), &at(BOOT_A, i64::MAX)),
            None
        );
        assert_eq!(secs_to_ms(u64::MAX), i64::MAX);
        assert_eq!(secs_to_ms(300), 300_000);

        let clock = ManualClock::new(BOOT_A, i64::MAX - 1);
        clock.advance_ms(10);
        assert_eq!(clock.now().unwrap().raw_bt_ms, i64::MAX);
    }

    #[test]
    fn the_manual_clock_moves_reboots_and_fails_on_request() {
        let clock = ManualClock::new(BOOT_A, 1_000);
        let window = BootWindow::opening_now(&clock, 60).unwrap();
        assert_eq!(window.start, at(BOOT_A, 1_000));
        assert_eq!(window.duration_ms, 60_000);
        clock.advance_secs(59);
        assert!(window.is_open(clock.now().as_ref()));
        clock.advance_secs(1);
        assert!(!window.is_open(clock.now().as_ref()));
        clock.reboot(BOOT_B, 0);
        assert_eq!(clock.now(), Some(at(BOOT_B, 0)));
        clock.set(None);
        assert_eq!(clock.now(), None);
        clock.advance_ms(5); // advancing an unreadable clock leaves it unreadable
        assert_eq!(clock.now(), None);
    }

    #[test]
    fn boot_ids_are_read_exactly_and_refused_otherwise() {
        let dir = std::env::temp_dir().join(format!(
            "punar-trusted-time-{}-{}",
            std::process::id(),
            crate::time::unix_now_millis()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("boot_id");

        std::fs::write(&path, format!("{BOOT_A}\n")).unwrap();
        assert_eq!(read_boot_id(&path).as_deref(), Some(BOOT_A));
        std::fs::write(&path, BOOT_A).unwrap();
        assert_eq!(read_boot_id(&path).as_deref(), Some(BOOT_A));
        for bad in [
            String::new(),
            "\n".to_string(),
            format!("{BOOT_A}\n\n"),
            format!(" {BOOT_A}\n"),
            BOOT_A.to_uppercase(),
            BOOT_A.replace('-', "_"),
            format!("{BOOT_A}{BOOT_A}"),
        ] {
            std::fs::write(&path, &bad).unwrap();
            assert_eq!(read_boot_id(&path), None, "{bad:?}");
        }
        assert_eq!(read_boot_id(&dir.join("absent")), None);
        // A clock with no readable boot id cannot say what time it is.
        assert_eq!(
            SystemClock::with_boot_id_path(dir.join("absent")).now(),
            None
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// On the machine running the test: a readable, well-formed, monotone
    /// clock, and the real boot id.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_system_clock_reads_this_boot_and_never_runs_backwards() {
        let clock = SystemClock::new();
        let Some(first) = clock.now() else {
            // A sandbox without /proc/sys: the clock must then say so, which
            // it just did. Nothing else to check.
            return;
        };
        assert!(first.is_well_formed(), "{first:?}");
        std::thread::sleep(std::time::Duration::from_millis(20));
        let second = clock.now().unwrap();
        assert_eq!(second.boot_id, first.boot_id);
        let elapsed = elapsed_ms(&first, &second).unwrap();
        assert!(elapsed >= 19, "slept 20 ms, measured {elapsed}");
        assert!(elapsed < 60_000, "measured {elapsed}");
    }

    #[test]
    fn stamps_and_windows_round_trip_and_refuse_extra_fields() {
        let window = BootWindow::of_secs(at(BOOT_A, 42), 300);
        let text = serde_json::to_string(&window).unwrap();
        assert_eq!(
            text,
            format!(r#"{{"start":{{"boot_id":"{BOOT_A}","raw_bt_ms":42}},"duration_ms":300000}}"#)
        );
        assert_eq!(serde_json::from_str::<BootWindow>(&text).unwrap(), window);
        let smuggled = format!(r#"{{"boot_id":"{BOOT_A}","raw_bt_ms":42,"wall":1}}"#);
        assert!(serde_json::from_str::<BootStamp>(&smuggled).is_err());
    }
}
