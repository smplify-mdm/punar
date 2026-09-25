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
//!   CLOCK_MONOTONIC)` in milliseconds (each part floored, so it never reads
//!   above the exact sum): the raw oscillator, which NTP neither slews nor
//!   steps, plus the time the kernel counted as suspended. Nothing in user
//!   space can move it.
//! - **`sleep_ms`** is that suspended part on its own, and **`suspends`** is
//!   the kernel's count of suspend attempts this boot
//!   (`/sys/power/suspend_stats/{success,fail}`). Together they say which
//!   *waking span* of the boot a stamp was taken in.
//!
//! Phase P0a is **monotonic-only**: no server anchor, no persisted floor, no
//! network. Those arrive with P1, and none of the consumers here need them,
//! because each of their windows is short and lives inside one boot.
//!
//! # A suspend closes every window that spans it
//!
//! The kernel measures a suspend exactly only where a clocksource keeps
//! running through it. On most x86 machines it does not, and the kernel then
//! takes the time asleep from the RTC in whole seconds: up to about a second
//! short on every resume, and nothing at all when the RTC did not move
//! forward (a sub-second sleep, or an RTC set back while the machine slept).
//! A window judged across such a resume would close late — by a second, or by
//! the whole sleep. P0a does not guess at that error: a window is live only
//! inside the waking span it opened in, so **a suspend closes it**, exactly as
//! a reboot does. Two independent signs mark a suspend, so one missing sign
//! is not enough to hide it: the kernel's suspend count moved, or the
//! suspended time moved by more than [`SLEEP_TOLERANCE_MS`]. (The count is
//! bumped a moment after user space thaws, which is why the suspended time is
//! checked as well.) Inside one waking span the suspended time is constant,
//! so elapsed time is measured on `CLOCK_MONOTONIC_RAW` alone, exactly.
//! P1's per-suspend allowance and sleep hook are what may later let a grant
//! survive a suspend; Punar has no hibernation (installer.md §4.6).
//!
//! # The rule, in exact integers
//!
//! Write `raw(s) = s.raw_bt_ms − s.sleep_ms`, the raw oscillator's reading. A
//! window of `duration_ms` opened at `start` is live at `now` iff
//!
//! ```text
//! now.boot_id == start.boot_id
//!   and now.suspends == start.suspends
//!   and |now.sleep_ms − start.sleep_ms| <= 1
//!   and 0 <= raw(now) − raw(start)
//!   and raw(now) − raw(start) < duration_ms − ceil(duration_ms * 200 / 10^6)
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
//! - `raw` is one clock read, floored to whole milliseconds, so the measured
//!   elapsed `e` can be up to one millisecond short of the true `E`. The
//!   comparison is strict: `e < B` between integers means `e + 1 ≤ B`, and
//!   `E < e + 1`, so `E < B`. The truncation is absorbed exactly, not
//!   approximately. The suspended time, which cannot be read in one call, is
//!   used only to tell waking spans apart and never enters the elapsed time.
//! - Anything that cannot be measured is closed: an unreadable clock, an
//!   unreadable or malformed boot id or suspend count, a stamp from another
//!   boot or another waking span, a clock that went backwards, a negative
//!   stamp, a non-positive duration, and every overflow.
//!
//! Records carry their display `expires_at` on the wall clock as before, for
//! people to read. It is never compared with anything.

use std::fmt;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// Where the kernel publishes this boot's random identifier.
pub const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// Where the kernel counts this boot's suspend attempts
/// (`success` and `fail`, Linux 5.4 and later with `CONFIG_PM_SLEEP`).
pub const SUSPEND_STATS_DIR: &str = "/sys/power/suspend_stats";

/// The oscillator error every window is shortened by, in parts per million.
/// Commodity crystals stay well inside it; the allowance is what lets the
/// rule above say "never late" rather than "rarely late".
pub const DRIFT_PPM: i64 = 200;

/// How far two readings of the suspended time may differ and still be the
/// same waking span. A reading pins it to within a quarter of a millisecond, and each
/// is floored, so two readings of one span differ by at most a millisecond.
pub const SLEEP_TOLERANCE_MS: i64 = 1;

const PPM: i64 = 1_000_000;
const NANOS_PER_MILLI: i128 = 1_000_000;
const NANOS_PER_SEC: i128 = 1_000_000_000;

/// A boot id is 36 bytes plus a newline; anything longer is not one.
const BOOT_ID_READ_LIMIT: u64 = 64;
/// A kernel counter is a decimal `int` plus a newline.
const COUNTER_READ_LIMIT: u64 = 32;

/// The widest `CLOCK_MONOTONIC` bracket around a `CLOCK_BOOTTIME` read that
/// is accepted. The suspended time is `BOOTTIME − MONOTONIC`, read in two
/// calls; bracketing the BOOTTIME read between two MONOTONIC reads pins it to
/// within the bracket's width. A preemption inside the bracket widens it, and
/// the reading is taken again rather than trusted.
const BRACKET_NS: i128 = 250_000;
/// Readings attempted before the clock is reported unreadable.
const READ_ATTEMPTS: usize = 5;

/// One instant on this boot's raw clock.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootStamp {
    /// `/proc/sys/kernel/random/boot_id`, verbatim (lowercase UUID).
    pub boot_id: String,
    /// `CLOCK_MONOTONIC_RAW + (CLOCK_BOOTTIME − CLOCK_MONOTONIC)` in whole
    /// milliseconds: the raw clock and [`sleep_ms`](Self::sleep_ms), each
    /// floored.
    pub raw_bt_ms: i64,
    /// `CLOCK_BOOTTIME − CLOCK_MONOTONIC` in whole milliseconds, floored: the
    /// time the kernel counted as suspended this boot.
    pub sleep_ms: i64,
    /// The kernel's count of suspend attempts this boot, successful or not.
    pub suspends: u64,
}

impl BootStamp {
    /// A stamp the rule can reason about: a UUID-shaped boot id, and
    /// `0 ≤ sleep_ms ≤ raw_bt_ms` (the raw part is never negative). Anything
    /// else closes every window it touches.
    pub fn is_well_formed(&self) -> bool {
        is_boot_id(&self.boot_id) && self.sleep_ms >= 0 && self.sleep_ms <= self.raw_bt_ms
    }

    /// The raw oscillator's reading, `CLOCK_MONOTONIC_RAW` in whole
    /// milliseconds. `None` for a malformed stamp.
    pub fn raw_ms(&self) -> Option<i64> {
        self.raw_bt_ms
            .checked_sub(self.sleep_ms)
            .filter(|raw| *raw >= 0 && self.sleep_ms >= 0)
    }

    /// Whether `self` and `other` were taken in the same waking span of the
    /// same boot: no reboot, and no suspend, between them.
    pub fn same_waking_span(&self, other: &BootStamp) -> bool {
        self.boot_id == other.boot_id
            && self.suspends == other.suspends
            && self
                .sleep_ms
                .checked_sub(other.sleep_ms)
                .is_some_and(|moved| (-SLEEP_TOLERANCE_MS..=SLEEP_TOLERANCE_MS).contains(&moved))
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
/// compared: different boots, a suspend between them, a malformed stamp, or
/// a clock that went backwards.
pub fn elapsed_ms(since: &BootStamp, now: &BootStamp) -> Option<i64> {
    if !since.is_well_formed() || !now.is_well_formed() || !since.same_waking_span(now) {
        return None;
    }
    now.raw_ms()?
        .checked_sub(since.raw_ms()?)
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

/// The module rule: live iff same boot, same waking span, and
/// `elapsed < duration − drift`. `now == None` (the clock could not be read)
/// is never live.
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
    /// This boot's id, raw time and waking span, or `None` when any of them
    /// cannot be read.
    fn now(&self) -> Option<BootStamp>;
}

/// The machine's own clock: `boot_id` from procfs, the suspend count from
/// sysfs, raw time from `clock_gettime(2)` through rustix's safe wrapper.
#[derive(Debug, Clone)]
pub struct SystemClock {
    boot_id_path: PathBuf,
    suspend_stats_dir: PathBuf,
}

impl Default for SystemClock {
    fn default() -> Self {
        SystemClock {
            boot_id_path: PathBuf::from(BOOT_ID_PATH),
            suspend_stats_dir: PathBuf::from(SUSPEND_STATS_DIR),
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
            ..SystemClock::default()
        }
    }

    /// The production clock reading its boot id and suspend counters from
    /// somewhere else — for tests of the parse, never for a daemon.
    pub fn with_paths(boot_id: impl Into<PathBuf>, suspend_stats_dir: impl Into<PathBuf>) -> Self {
        SystemClock {
            boot_id_path: boot_id.into(),
            suspend_stats_dir: suspend_stats_dir.into(),
        }
    }
}

impl TrustedClock for SystemClock {
    fn now(&self) -> Option<BootStamp> {
        let boot_id = read_boot_id(&self.boot_id_path)?;
        let reading = read_system_clocks(&self.suspend_stats_dir)?;
        Some(BootStamp {
            boot_id,
            raw_bt_ms: reading.raw_bt_ms,
            sleep_ms: reading.sleep_ms,
            suspends: reading.suspends,
        })
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

/// The kernel's count of suspend attempts this boot: `success + fail` under
/// `dir` (normally [`SUSPEND_STATS_DIR`]). A failed attempt counts too — the
/// machine may still have slept — so it also closes every open window.
///
/// A `dir` that does not exist is a kernel built without sleep support,
/// which cannot suspend: zero. (Hiding the directory from a daemon takes
/// root, and the suspended time in each stamp still closes a window across
/// every suspend the kernel measured.) Anything else unreadable, oversized
/// or not a plain decimal is `None`, and `None` closes every window.
pub fn read_suspend_count(dir: &Path) -> Option<u64> {
    match std::fs::metadata(dir) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Some(0),
        Err(_) => return None,
        Ok(meta) if !meta.is_dir() => return None,
        Ok(_) => {}
    }
    let success = read_counter(&dir.join("success"))?;
    let fail = read_counter(&dir.join("fail"))?;
    success.checked_add(fail)
}

fn read_counter(path: &Path) -> Option<u64> {
    let file = std::fs::File::open(path).ok()?;
    let mut text = String::new();
    file.take(COUNTER_READ_LIMIT)
        .read_to_string(&mut text)
        .ok()?;
    let digits = text.strip_suffix('\n').unwrap_or(&text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The three kernel clocks a reading takes.
#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Clock {
    Monotonic,
    Boottime,
    MonotonicRaw,
}

/// The clock part of a [`BootStamp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClockReading {
    raw_bt_ms: i64,
    sleep_ms: i64,
    suspends: u64,
}

/// A `timespec` as nanoseconds. A negative second or a nanosecond field
/// outside `[0, 10^9)` is not a reading of these clocks: `None`.
#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
fn timespec_nanos(secs: i128, nanos: i128) -> Option<i128> {
    if secs < 0 || !(0..NANOS_PER_SEC).contains(&nanos) {
        return None;
    }
    secs.checked_mul(NANOS_PER_SEC)?.checked_add(nanos)
}

/// `BOOTTIME − MONOTONIC`, with the BOOTTIME read bracketed between two
/// MONOTONIC reads. The outer `None` is a clock that could not be read (or
/// a MONOTONIC that ran backwards); `Some(None)` is a bracket wider than
/// [`BRACKET_NS`] — a preemption — to be read again. The value returned is
/// never above the true suspended time and at most the bracket below it.
#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
fn bracketed_sleep_ns(read: &mut dyn FnMut(Clock) -> Option<i128>) -> Option<Option<i128>> {
    let before = read(Clock::Monotonic)?;
    let boot = read(Clock::Boottime)?;
    let after = read(Clock::Monotonic)?;
    let width = after.checked_sub(before)?;
    if width < 0 {
        return None;
    }
    if width > BRACKET_NS {
        return Some(None);
    }
    // BOOTTIME never runs behind MONOTONIC; reading MONOTONIC after BOOTTIME
    // can only make the difference a hair small, which the floor of zero
    // corrects toward the truth, never past it.
    Some(Some(boot.checked_sub(after)?.max(0)))
}

/// One consistent reading of the three clocks and the suspend count, from
/// injected sources so every branch is testable.
///
/// The suspend count and the suspended time are each read on both sides of
/// the raw clock and must agree: a reading that a suspend split (or a
/// preemption widened) is taken again, and after [`READ_ATTEMPTS`] refusals
/// the clock is reported unreadable rather than guessed. The raw clock is a
/// single read, floored, so it is exact to the millisecond; the suspended
/// time only labels the waking span.
#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
fn read_clocks(
    read: &mut dyn FnMut(Clock) -> Option<i128>,
    suspends: &mut dyn FnMut() -> Option<u64>,
) -> Option<ClockReading> {
    for _ in 0..READ_ATTEMPTS {
        let count_before = suspends()?;
        let Some(first) = bracketed_sleep_ns(read)? else {
            continue;
        };
        let raw = read(Clock::MonotonicRaw)?;
        let Some(second) = bracketed_sleep_ns(read)? else {
            continue;
        };
        let count_after = suspends()?;
        if count_before != count_after || (second - first).abs() > BRACKET_NS {
            continue;
        }
        if raw < 0 {
            return None;
        }
        let raw_ms = i64::try_from(raw.div_euclid(NANOS_PER_MILLI)).ok()?;
        let sleep_ms = i64::try_from(first.min(second).div_euclid(NANOS_PER_MILLI)).ok()?;
        return Some(ClockReading {
            raw_bt_ms: raw_ms.checked_add(sleep_ms)?,
            sleep_ms,
            suspends: count_after,
        });
    }
    None
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_system_clocks(suspend_stats_dir: &Path) -> Option<ClockReading> {
    use rustix::time::{ClockId, DynamicClockId, clock_gettime_dynamic};

    let mut read = |clock: Clock| {
        let id = match clock {
            Clock::Monotonic => ClockId::Monotonic,
            Clock::Boottime => ClockId::Boottime,
            Clock::MonotonicRaw => ClockId::MonotonicRaw,
        };
        let ts = clock_gettime_dynamic(DynamicClockId::Known(id)).ok()?;
        timespec_nanos(i128::from(ts.tv_sec), i128::from(ts.tv_nsec))
    };
    let mut suspends = || read_suspend_count(suspend_stats_dir);
    read_clocks(&mut read, &mut suspends)
}

/// No boot clock outside Linux: every window is closed.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn read_system_clocks(_suspend_stats_dir: &Path) -> Option<ClockReading> {
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
    /// A clock reading `boot_id` at `raw_bt_ms`, never yet suspended.
    pub fn new(boot_id: &str, raw_bt_ms: i64) -> Self {
        ManualClock {
            state: Mutex::new(Some(BootStamp {
                boot_id: boot_id.to_string(),
                raw_bt_ms,
                sleep_ms: 0,
                suspends: 0,
            })),
        }
    }

    fn with_state<R>(&self, f: impl FnOnce(&mut Option<BootStamp>) -> R) -> R {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }

    /// Move the raw clock by `ms` while awake (negative moves it back, which
    /// the rule treats as unmeasurable). Saturates rather than wrapping.
    pub fn advance_ms(&self, ms: i64) {
        self.with_state(|state| {
            if let Some(stamp) = state {
                stamp.raw_bt_ms = stamp.raw_bt_ms.saturating_add(ms);
            }
        });
    }

    /// Move the raw clock by `secs` seconds while awake.
    pub fn advance_secs(&self, secs: u64) {
        self.advance_ms(secs_to_ms(secs));
    }

    /// Simulate one suspend the kernel measured as `slept_ms`: the suspend
    /// count, the suspended time and the boot time all move.
    pub fn suspend(&self, slept_ms: i64) {
        self.with_state(|state| {
            if let Some(stamp) = state {
                let slept = slept_ms.max(0);
                stamp.suspends = stamp.suspends.saturating_add(1);
                stamp.sleep_ms = stamp.sleep_ms.saturating_add(slept);
                stamp.raw_bt_ms = stamp.raw_bt_ms.saturating_add(slept);
            }
        });
    }

    /// Simulate a reboot: a new boot id, and a raw clock and suspend count
    /// starting again.
    pub fn reboot(&self, boot_id: &str, raw_bt_ms: i64) {
        self.set(Some(BootStamp {
            boot_id: boot_id.to_string(),
            raw_bt_ms,
            sleep_ms: 0,
            suspends: 0,
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
    use std::collections::VecDeque;

    use super::*;

    const BOOT_A: &str = "0f2a6c1e-7d3b-4a59-9c8e-1b2d3e4f5a6b";
    const BOOT_B: &str = "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b";

    /// A stamp in the first waking span of a boot: never suspended.
    fn at(boot_id: &str, raw_bt_ms: i64) -> BootStamp {
        BootStamp {
            boot_id: boot_id.to_string(),
            raw_bt_ms,
            sleep_ms: 0,
            suspends: 0,
        }
    }

    /// A stamp after `suspends` suspends that slept `sleep_ms` in all.
    fn after_sleep(raw_bt_ms: i64, sleep_ms: i64, suspends: u64) -> BootStamp {
        BootStamp {
            boot_id: BOOT_A.to_string(),
            raw_bt_ms,
            sleep_ms,
            suspends,
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "punar-trusted-time-{tag}-{}-{}",
            std::process::id(),
            crate::time::unix_now_millis()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
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

    /// A suspend closes every window that spans it, however the kernel
    /// measured the sleep — or failed to. Each sign is enough on its own.
    #[test]
    fn a_suspend_closes_every_window_that_spans_it() {
        let clock = ManualClock::new(BOOT_A, 10_000);
        let window = BootWindow::opening_now(&clock, 3_600).unwrap();
        clock.advance_secs(5);
        assert!(window.is_open(clock.now().as_ref()));

        // The lid closes for ten seconds and the kernel counts all of it:
        // an hour-long window, five seconds old, is closed all the same.
        clock.suspend(10_000);
        assert!(!window.is_open(clock.now().as_ref()));
        assert_eq!(window.remaining_ms(clock.now().as_ref()), None);
        assert_eq!(elapsed_ms(&window.start, &clock.now().unwrap()), None);
        // A window opened after the resume is a new span, and live.
        let fresh = BootWindow::opening_now(&clock, 60).unwrap();
        clock.advance_secs(1);
        assert!(fresh.is_open(clock.now().as_ref()));

        let start = after_sleep(20_000, 5_000, 2);
        let window = BootWindow::of_secs(start, 3_600);
        assert!(window.is_open(Some(&after_sleep(21_000, 5_000, 2))));
        // The kernel counted a suspend but measured no sleep (an RTC that
        // did not move forward): the count alone closes it.
        assert!(!window.is_open(Some(&after_sleep(21_000, 5_000, 3))));
        // The kernel measured a sleep a moment before bumping its count (it
        // thaws user space first): the suspended time alone closes it.
        assert!(!window.is_open(Some(&after_sleep(21_000 + 2, 5_002, 2))));
        assert!(!window.is_open(Some(&after_sleep(21_000, 4_998, 2))));
        // One millisecond is reading noise, not a suspend.
        assert!(window.is_open(Some(&after_sleep(21_001, 5_001, 2))));
        assert!(window.is_open(Some(&after_sleep(20_999, 4_999, 2))));
        // A count that went backwards is no better.
        assert!(!window.is_open(Some(&after_sleep(21_000, 5_000, 1))));
    }

    /// Inside one waking span, elapsed time is the raw clock's difference
    /// alone: the millisecond of noise in the suspended time never enters
    /// it, so the floor argument holds exactly.
    #[test]
    fn elapsed_time_is_measured_on_the_raw_clock_alone() {
        let start = after_sleep(10_000, 5_000, 1); // raw 5 000
        let now = after_sleep(10_101, 5_001, 1); // raw 5 100
        assert_eq!(start.raw_ms(), Some(5_000));
        assert_eq!(now.raw_ms(), Some(5_100));
        assert_eq!(elapsed_ms(&start, &now), Some(100));
        let now = after_sleep(10_099, 4_999, 1); // raw 5 100 again
        assert_eq!(elapsed_ms(&start, &now), Some(100));
        // The budget is judged on that raw difference: 102 ms less its
        // 1 ms drift allowance is 101, and 100 < 101; 101 ms leaves 100.
        let window = BootWindow::new(start, 102);
        assert!(window.is_open(Some(&now)));
        let window = BootWindow::new(after_sleep(10_000, 5_000, 1), 101);
        assert!(!window.is_open(Some(&now)));
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
            // A negative suspended time, or more asleep than the boot is old.
            after_sleep(50, -1, 0),
            after_sleep(50, 51, 0),
        ] {
            assert!(!is_within(&start, Some(&now), 60_000), "{start:?}");
        }
        // A malformed *now* is no better.
        assert!(!is_within(&at(BOOT_A, 0), Some(&at("", 100)), 60_000));
        assert!(!is_within(
            &at(BOOT_A, 0),
            Some(&after_sleep(100, 101, 0)),
            60_000
        ));
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
        // Suspended times at the extremes neither wrap nor match.
        let top = after_sleep(i64::MAX, i64::MAX, u64::MAX);
        assert_eq!(top.raw_ms(), Some(0));
        assert_eq!(elapsed_ms(&top, &top), Some(0));
        assert!(!top.same_waking_span(&after_sleep(i64::MAX, 0, u64::MAX)));
        // A difference of exactly i64::MIN has no absolute value; it is not
        // a match, and it does not panic.
        assert!(!after_sleep(0, -1, 0).same_waking_span(&after_sleep(i64::MAX, i64::MAX, 0)));
        assert!(!after_sleep(0, i64::MIN, 0).is_well_formed());
        assert_eq!(after_sleep(0, i64::MIN, 0).raw_ms(), None);
        assert_eq!(secs_to_ms(u64::MAX), i64::MAX);
        assert_eq!(secs_to_ms(300), 300_000);

        let clock = ManualClock::new(BOOT_A, i64::MAX - 1);
        clock.advance_ms(10);
        assert_eq!(clock.now().unwrap().raw_bt_ms, i64::MAX);
        clock.suspend(i64::MAX);
        let stamp = clock.now().unwrap();
        assert_eq!((stamp.sleep_ms, stamp.suspends), (i64::MAX, 1));
    }

    #[test]
    fn the_manual_clock_moves_suspends_reboots_and_fails_on_request() {
        let clock = ManualClock::new(BOOT_A, 1_000);
        let window = BootWindow::opening_now(&clock, 60).unwrap();
        assert_eq!(window.start, at(BOOT_A, 1_000));
        assert_eq!(window.duration_ms, 60_000);
        clock.advance_secs(59);
        assert!(window.is_open(clock.now().as_ref()));
        clock.advance_secs(1);
        assert!(!window.is_open(clock.now().as_ref()));
        clock.suspend(2_500);
        assert_eq!(clock.now(), Some(after_sleep(63_500, 2_500, 1)));
        clock.suspend(-7); // a negative sleep is no sleep, but still a suspend
        assert_eq!(clock.now(), Some(after_sleep(63_500, 2_500, 2)));
        clock.reboot(BOOT_B, 0);
        assert_eq!(clock.now(), Some(at(BOOT_B, 0)));
        clock.set(None);
        assert_eq!(clock.now(), None);
        clock.advance_ms(5); // advancing an unreadable clock leaves it unreadable
        clock.suspend(5);
        assert_eq!(clock.now(), None);
    }

    #[test]
    fn boot_ids_are_read_exactly_and_refused_otherwise() {
        let dir = scratch("boot-id");
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

    /// The suspend count is `success + fail`, read strictly. A kernel
    /// without the directory cannot suspend, and reads as zero; anything
    /// else unreadable closes every window.
    #[test]
    fn the_suspend_count_is_read_exactly_and_refused_otherwise() {
        let dir = scratch("suspend-stats");
        let stats = dir.join("suspend_stats");
        assert_eq!(read_suspend_count(&stats), Some(0), "no sleep support");

        std::fs::create_dir_all(&stats).unwrap();
        assert_eq!(read_suspend_count(&stats), None, "counters missing");
        std::fs::write(stats.join("success"), "7\n").unwrap();
        assert_eq!(read_suspend_count(&stats), None, "fail missing");
        std::fs::write(stats.join("fail"), "2\n").unwrap();
        assert_eq!(read_suspend_count(&stats), Some(9));
        std::fs::write(stats.join("fail"), "0").unwrap();
        assert_eq!(read_suspend_count(&stats), Some(7));
        for bad in [
            "",
            "\n",
            "-1\n",
            "+1\n",
            " 1\n",
            "1 2\n",
            "0x10\n",
            "18446744073709551616\n", // u64::MAX + 1
            "1\n\n",
        ] {
            std::fs::write(stats.join("fail"), bad).unwrap();
            assert_eq!(read_suspend_count(&stats), None, "{bad:?}");
        }
        std::fs::write(stats.join("fail"), "18446744073709551615\n").unwrap();
        assert_eq!(read_suspend_count(&stats), None, "the sum overflows");

        // A file where the directory should be is not a kernel's answer.
        let file = dir.join("not-a-dir");
        std::fs::write(&file, "0\n").unwrap();
        assert_eq!(read_suspend_count(&file), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A scripted source for [`read_clocks`]: each clock read must be the
    /// next one expected, in order, and each counter read likewise.
    struct Script {
        clocks: VecDeque<(Clock, Option<i128>)>,
        counts: VecDeque<Option<u64>>,
    }

    impl Script {
        fn new() -> Self {
            Script {
                clocks: VecDeque::new(),
                counts: VecDeque::new(),
            }
        }

        /// One bracket: MONOTONIC `mono`, BOOTTIME read `gap` later with
        /// `sleep` suspended, MONOTONIC `width` after the first.
        fn bracket(&mut self, mono: i128, gap: i128, width: i128, sleep: i128) -> &mut Self {
            self.clocks.push_back((Clock::Monotonic, Some(mono)));
            self.clocks
                .push_back((Clock::Boottime, Some(mono + gap + sleep)));
            self.clocks
                .push_back((Clock::Monotonic, Some(mono + width)));
            self
        }

        fn raw(&mut self, raw: i128) -> &mut Self {
            self.clocks.push_back((Clock::MonotonicRaw, Some(raw)));
            self
        }

        fn count(&mut self, count: u64) -> &mut Self {
            self.counts.push_back(Some(count));
            self
        }

        /// A clean attempt: a narrow bracket, the raw clock, another.
        fn clean(&mut self, count: u64, mono: i128, raw: i128, sleep: i128) -> &mut Self {
            self.count(count)
                .bracket(mono, 50, 100, sleep)
                .raw(raw)
                .bracket(mono + 300, 50, 100, sleep)
                .count(count)
        }

        fn run(&mut self) -> Option<ClockReading> {
            let clocks = &mut self.clocks;
            let counts = &mut self.counts;
            let mut read = |clock: Clock| {
                let (expected, value) = clocks.pop_front().expect("an unscripted clock read");
                assert_eq!(clock, expected, "clocks read out of order");
                value
            };
            let mut suspends = || counts.pop_front().expect("an unscripted count read");
            read_clocks(&mut read, &mut suspends)
        }

        fn is_spent(&self) -> bool {
            self.clocks.is_empty() && self.counts.is_empty()
        }
    }

    const SEC: i128 = 1_000_000_000;

    /// A clean reading: the raw clock exactly, floored; the suspended time
    /// never above the truth and at most the bracket below it.
    #[test]
    fn a_clean_reading_is_exact_on_the_raw_clock() {
        let mut script = Script::new();
        script.clean(3, 10 * SEC, 9_876_543_210, 5 * SEC);
        let reading = script.run().expect("a clean reading");
        assert!(script.is_spent());
        // BOOTTIME read 50 ns into a 100 ns bracket: 5 s less 50 ns.
        assert_eq!(reading.sleep_ms, 4_999);
        assert_eq!(reading.raw_bt_ms, 9_876 + 4_999);
        assert_eq!(reading.suspends, 3);
        // Never above the exact CLOCK_MONOTONIC_RAW + suspended time.
        assert!(i128::from(reading.raw_bt_ms) * 1_000_000 <= 9_876_543_210 + 5 * SEC);
    }

    /// The case the reviewers scripted: a preemption between the BOOTTIME
    /// and MONOTONIC reads would under-read the suspended time. The bracket
    /// is wider than allowed, so the reading is taken again — and when every
    /// attempt is preempted, the clock is unreadable rather than guessed.
    #[test]
    fn a_preempted_reading_is_retried_and_never_trusted() {
        let mut script = Script::new();
        for _ in 0..READ_ATTEMPTS {
            // 50 ms stolen between BOOTTIME and the second MONOTONIC.
            script.count(0).bracket(10 * SEC, 0, 50_000_000, 5 * SEC);
        }
        assert_eq!(script.run(), None);
        assert!(script.is_spent());

        // The same preemption in the second bracket.
        let mut script = Script::new();
        for _ in 0..READ_ATTEMPTS {
            script
                .count(0)
                .bracket(10 * SEC, 50, 100, 5 * SEC)
                .raw(10 * SEC)
                .bracket(10 * SEC, 0, 50_000_000, 5 * SEC);
        }
        assert_eq!(script.run(), None);
        assert!(script.is_spent());

        // Preempted once, then clean: the clean attempt's reading.
        let mut script = Script::new();
        script.count(0).bracket(10 * SEC, 0, 50_000_000, 5 * SEC);
        script.clean(0, 11 * SEC, 12 * SEC, 5 * SEC);
        let reading = script.run().unwrap();
        assert!(script.is_spent());
        assert_eq!(reading.raw_bt_ms, 12_000 + 4_999);
    }

    /// A suspend that lands inside a reading moves the suspended time, the
    /// count, or both, between the two sides of the raw clock: taken again.
    #[test]
    fn a_reading_a_suspend_split_is_taken_again() {
        // The suspended time moved by 10 s across the raw read, before the
        // kernel bumped its count.
        let mut script = Script::new();
        for _ in 0..READ_ATTEMPTS {
            script
                .count(4)
                .bracket(10 * SEC, 50, 100, 5 * SEC)
                .raw(10 * SEC)
                .bracket(10 * SEC, 50, 100, 15 * SEC)
                .count(4);
        }
        assert_eq!(script.run(), None);
        assert!(script.is_spent());

        // The count moved while the clocks agreed.
        let mut script = Script::new();
        script
            .count(4)
            .bracket(10 * SEC, 50, 100, 5 * SEC)
            .raw(10 * SEC)
            .bracket(10 * SEC, 50, 100, 5 * SEC)
            .count(5);
        script.clean(5, 20 * SEC, 20 * SEC, 5 * SEC);
        let reading = script.run().unwrap();
        assert!(script.is_spent());
        assert_eq!(reading.suspends, 5);
        assert_eq!(reading.raw_bt_ms, 20_000 + 4_999);
    }

    /// Any clock or counter that cannot be read, a MONOTONIC that ran
    /// backwards, or a negative raw clock: unreadable, at once.
    #[test]
    fn an_unreadable_source_makes_the_whole_reading_unreadable() {
        let mut script = Script::new();
        script.count(0);
        script.clocks.push_back((Clock::Monotonic, None));
        assert_eq!(script.run(), None);
        assert!(script.is_spent());

        let mut script = Script::new();
        script.counts.push_back(None);
        assert_eq!(script.run(), None);
        assert!(script.is_spent());

        let mut script = Script::new();
        script
            .count(0)
            .bracket(10 * SEC, 50, 100, 5 * SEC)
            .clocks
            .push_back((Clock::MonotonicRaw, None));
        assert_eq!(script.run(), None);
        assert!(script.is_spent());

        let mut script = Script::new();
        script.count(0).bracket(10 * SEC, 0, -1, 0);
        assert_eq!(script.run(), None, "MONOTONIC ran backwards");
        assert!(script.is_spent());

        let mut script = Script::new();
        script.clean(0, 10 * SEC, -1, 0);
        assert_eq!(script.run(), None, "a negative raw clock");
        assert!(script.is_spent());
    }

    /// The `timespec` guard: a negative second or a nanosecond field out of
    /// range is not a reading.
    #[test]
    fn a_timespec_out_of_range_is_not_a_reading() {
        assert_eq!(timespec_nanos(-1, 0), None);
        assert_eq!(timespec_nanos(0, -1), None);
        assert_eq!(timespec_nanos(0, 1_000_000_000), None);
        assert_eq!(timespec_nanos(0, 999_999_999), Some(999_999_999));
        assert_eq!(timespec_nanos(2, 5), Some(2 * SEC + 5));
        assert_eq!(timespec_nanos(i128::MAX, 0), None, "overflow");
    }

    /// On the machine running the test: a readable, well-formed, monotone
    /// clock, the real boot id, and a suspend count that only rises.
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
        assert!(second.suspends >= first.suspends);
        if second.suspends != first.suspends {
            return; // the machine slept during the test: nothing to measure
        }
        let elapsed = elapsed_ms(&first, &second).unwrap();
        assert!(elapsed >= 19, "slept 20 ms, measured {elapsed}");
        assert!(elapsed < 60_000, "measured {elapsed}");
    }

    /// The system clock refuses to answer when the suspend count cannot be
    /// read, and carries the count it read.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_system_clock_carries_the_kernels_suspend_count() {
        let dir = scratch("system-count");
        let boot_id = dir.join("boot_id");
        std::fs::write(&boot_id, format!("{BOOT_A}\n")).unwrap();
        let stats = dir.join("suspend_stats");
        std::fs::create_dir_all(&stats).unwrap();
        std::fs::write(stats.join("success"), "not a number\n").unwrap();
        std::fs::write(stats.join("fail"), "0\n").unwrap();
        let clock = SystemClock::with_paths(&boot_id, &stats);
        assert_eq!(clock.now(), None, "an unreadable count reads no time");

        std::fs::write(stats.join("success"), "12\n").unwrap();
        std::fs::write(stats.join("fail"), "1\n").unwrap();
        if let Some(stamp) = clock.now() {
            assert_eq!(stamp.boot_id, BOOT_A);
            assert_eq!(stamp.suspends, 13);
            assert!(stamp.is_well_formed(), "{stamp:?}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn stamps_and_windows_round_trip_and_refuse_extra_or_missing_fields() {
        let window = BootWindow::of_secs(after_sleep(42, 2, 1), 300);
        let text = serde_json::to_string(&window).unwrap();
        assert_eq!(
            text,
            format!(
                r#"{{"start":{{"boot_id":"{BOOT_A}","raw_bt_ms":42,"sleep_ms":2,"suspends":1}},"duration_ms":300000}}"#
            )
        );
        assert_eq!(serde_json::from_str::<BootWindow>(&text).unwrap(), window);
        let smuggled = format!(
            r#"{{"boot_id":"{BOOT_A}","raw_bt_ms":42,"sleep_ms":0,"suspends":0,"wall":1}}"#
        );
        assert!(serde_json::from_str::<BootStamp>(&smuggled).is_err());
        // A stamp that does not say which waking span it is from is not
        // read as "the first one".
        let unlabelled = format!(r#"{{"boot_id":"{BOOT_A}","raw_bt_ms":42}}"#);
        assert!(serde_json::from_str::<BootStamp>(&unlabelled).is_err());
    }
}
