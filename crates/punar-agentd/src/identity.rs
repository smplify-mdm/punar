//! Detection identity (milestone-10.md section 4) — the substrate the
//! set-diff, the persisted record and the anti-nag rule are all built on.
//!
//! # Two identities, deliberately
//!
//! ```text
//! detection_id = "agt_" + hex12( sha256( exe ‖ 0x00 ‖ uid ‖ 0x00 ‖ boot_id
//!                                        ‖ 0x00 ‖ pid ‖ 0x00 ‖ starttime ) )
//! signature_id = "sig_" + hex12( sha256( exe ‖ 0x00 ‖ uid ) )
//! ```
//!
//! [`detection_id`] names **one running process**. It is stable for that
//! process's whole life — which is exactly the property the scan diff
//! depends on: a detection that persists across passes is not news, and a
//! pass that finds the same set writes nothing at all.
//!
//! [`signature_id`] names **one thing seen**, and is deliberately
//! coarser: restarting the same binary is the same thing seen, and the
//! user does not need to be told twice. It is the anti-nag key
//! ([`crate::alerts`]) and the fleet-dedup key.
//!
//! # Why pid reuse cannot collide
//!
//! A pid is recycled by the kernel within minutes on a busy machine, so
//! `(exe, uid, pid)` alone would let a *new* process inherit a *dead*
//! detection's identity — and with it that detection's persisted record,
//! its ledger, and its place in the previous scan's set. The diff would
//! then miss both the disappearance and the appearance, and the ledger
//! would silently merge two unrelated processes.
//!
//! Two fields close that:
//!
//! - **`starttime_ticks`** — field 22 of `/proc/<pid>/stat`, the kernel's
//!   own clock-tick stamp for when *this* task started. Two processes
//!   sharing a pid cannot share it: the kernel only reuses a pid after
//!   the first task is reaped, which is strictly earlier in time, and the
//!   pair `(pid, starttime)` is the standard kernel-attested process
//!   identity for exactly this reason (M8's ledger already dedups on it).
//! - **`boot_id`** — `/proc/sys/kernel/random/boot_id`, freshly generated
//!   by the kernel each boot. `starttime` is measured *since boot*, so
//!   without the boot id a process from a previous boot with the same
//!   pid and the same tick count would collide. It also makes the id
//!   honestly boot-scoped, which is what a "currently running process"
//!   identity should be.
//!
//! A recycled pid therefore produces a **different** id, which is the
//! correct semantics: it is a different detection, and it is reported as
//! one process clearing and another appearing.
//!
//! # It is a hash, not a path
//!
//! Both ids can appear in an exported inventory answer without leaking
//! where a binary lives or who owns it. That is not decoration: spec 51's
//! administrator query asks *how many distinct unmanaged things*, and the
//! `sig_` count answers it without the paths.
//!
//! Twelve hex digits (48 bits) is the width `punar-env` already mints for
//! managed session ids and the width `registry-record.json`'s
//! `^agt_[A-Za-z0-9]+$` pattern has always carried. At the scale this
//! keys — the processes alive on one desktop — 48 bits is far past the
//! point where a collision is a real risk, and the id is not a security
//! token (nothing authenticates on it).

use punar_common::ledger::{CLASS_UNKNOWN, ZONE_DOWNLOADS, ZONE_HOME, ZONE_SYSTEM, ZONE_TMP};
use punar_common::time::rfc3339_utc_from_unix_seconds;

use crate::sha256::sha256_hex;

/// Hex digits kept from the digest — the `punar-env` session-id width.
pub const IDENTITY_HEX_LEN: usize = 12;

/// `USER_HZ`, the unit of `/proc/<pid>/stat` field 22.
///
/// Hard-coded rather than read through `sysconf(_SC_CLK_TCK)`, which is
/// not reachable from safe Rust and would need `libc` (workspace crates
/// are `#![forbid(unsafe_code)]`). 100 is the Linux userspace ABI value
/// on every architecture Linux supports — `USER_HZ` is fixed in
/// `include/asm-generic/param.h` and deliberately decoupled from the
/// kernel's internal `HZ` precisely so userspace may assume it.
pub const USER_HZ: u64 = 100;

/// NUL-joined field encoding. A separator that cannot occur inside any
/// field (a path, a decimal number and a UUID are all NUL-free) is what
/// makes the construction unambiguous: no two different field tuples can
/// produce the same byte string, so no two processes can be given the
/// same id by a clever path.
fn digest_of(fields: &[&str]) -> String {
    let mut bytes: Vec<u8> = Vec::new();
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            bytes.push(0);
        }
        bytes.extend_from_slice(field.as_bytes());
    }
    let hex = sha256_hex(&bytes);
    hex[..IDENTITY_HEX_LEN].to_string()
}

/// `agt_` + 12 hex — one running process (milestone-10.md section 4.1).
///
/// `agt_`-prefixed because `registry-record.json` and `audit-event.json`
/// both require an `agent_session_id`-shaped value and M7's
/// `agents.json` already emits detection rows with `agt_`-shaped ids. No
/// schema moves.
pub fn detection_id(
    exe_realpath: &str,
    owner_uid: u32,
    boot_id: &str,
    pid: u32,
    starttime_ticks: u64,
) -> String {
    format!(
        "agt_{}",
        digest_of(&[
            exe_realpath,
            &owner_uid.to_string(),
            boot_id,
            &pid.to_string(),
            &starttime_ticks.to_string(),
        ])
    )
}

/// `sig_` + 12 hex — one thing seen (milestone-10.md section 4.2).
pub fn signature_id(exe_realpath: &str, owner_uid: u32) -> String {
    format!("sig_{}", digest_of(&[exe_realpath, &owner_uid.to_string()]))
}

/// `alr_` + 12 hex — one raised alert. Derived from the signature and the
/// moment it was raised, so a fresh alert after the quiet window expires
/// gets a fresh id while the old filed card keeps its own.
pub fn alert_id(signature_id: &str, raised_at: &str) -> String {
    format!("alr_{}", digest_of(&[signature_id, raised_at]))
}

/// The zone **class** of an executable's own location (milestone-10.md
/// section 6.3) — `downloads`, `tmp`, `home`, `system`, or the
/// [`CLASS_UNKNOWN`] sentinel.
///
/// A class, never a path. This is derived from the path the signature
/// already matched on; nothing here reads `/proc/<pid>/cwd`, and the path
/// itself never crosses into ledger storage.
pub fn executable_zone(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    if lower.starts_with("/tmp/") || lower.starts_with("/var/tmp/") {
        return ZONE_TMP;
    }
    // `/downloads/` anywhere in the path: the directory is the signal,
    // and it is not always directly under the home root (XDG allows a
    // relocated `XDG_DOWNLOAD_DIR`).
    if lower.contains("/downloads/") {
        return ZONE_DOWNLOADS;
    }
    if lower.starts_with("/home/") || lower.starts_with("/root/") {
        return ZONE_HOME;
    }
    if [
        "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/srv/", "/var/",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
    {
        return ZONE_SYSTEM;
    }
    CLASS_UNKNOWN
}

/// Every value [`executable_zone`] can return — the closed class set, and
/// therefore `device_builtin_max` for the one location datum that leaves
/// the device (milestone-10.md sections 8.2, 8.3).
pub const ZONE_CLASSES: [&str; 5] = [
    ZONE_DOWNLOADS,
    ZONE_TMP,
    ZONE_HOME,
    ZONE_SYSTEM,
    CLASS_UNKNOWN,
];

/// Re-check a stored zone against the closed class set on the way out.
///
/// milestone-10.md section 8.3 rests on a distinction worth defending:
/// what an export may not contain is absent because **no field exists to
/// carry it**, not because a filter drops it. The detection index is the
/// one place that claim is thinner than it looks — its `zone` is a
/// `String` read back from a file, and the field one line above it in the
/// same struct holds a full executable path. A wrong index, a corrupt
/// file or a future writer that swaps two fields would put a path into a
/// datum documented as a class, on the one surface that leaves the
/// device.
///
/// So the export narrows the stored string back to the closed set and
/// answers [`CLASS_UNKNOWN`] for anything else. An honest `unknown` is
/// always a safe answer here; a path never is.
pub fn zone_class_or_unknown(stored: &str) -> &'static str {
    ZONE_CLASSES
        .into_iter()
        .find(|class| *class == stored)
        .unwrap_or(CLASS_UNKNOWN)
}

/// The process's **own** start time, from the kernel's boot time plus its
/// `starttime` clock ticks (milestone-10.md section 6.4).
///
/// `None` when either input is unavailable — the caller then falls back
/// to the time this daemon first observed the process and says so, rather
/// than inventing a start it cannot derive (spec 1.22). M7 recorded the
/// first-observed time in this field and documented that it did *not*
/// know the process's start; M10 knows it, and the honest empty is the
/// only remaining case.
pub fn process_started_at(
    boot_unix_secs: Option<u64>,
    starttime_ticks: Option<u64>,
) -> Option<String> {
    let boot = boot_unix_secs?;
    let ticks = starttime_ticks?;
    Some(rfc3339_utc_from_unix_seconds(boot + ticks / USER_HZ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: &str = "6f2c6b1e-0e2a-4c37-9f4e-6b6f2a1d9c31";
    const EXE: &str = "/home/punar/Downloads/foo-agent";

    #[test]
    fn identities_are_shaped_and_stable() {
        let a = detection_id(EXE, 1000, BOOT, 2410, 918_273);
        let b = detection_id(EXE, 1000, BOOT, 2410, 918_273);
        assert_eq!(a, b, "the same process keeps its id across scan passes");
        assert_eq!(a.len(), "agt_".len() + IDENTITY_HEX_LEN);
        assert!(punar_common::agent::session_id_ok(&a), "{a}");
        assert!(a[4..].chars().all(|c| c.is_ascii_hexdigit()));

        let s = signature_id(EXE, 1000);
        assert_eq!(s, signature_id(EXE, 1000));
        assert!(punar_common::agent::signature_identity_ok(&s), "{s}");
        assert!(
            !a.contains("foo-agent") && !s.contains("foo-agent"),
            "an id is a hash, not a path — it may appear in an exported answer"
        );
    }

    /// The collision-resistance argument, one assertion per field: change
    /// any one input and the identity changes.
    #[test]
    fn every_identity_field_changes_the_detection_id() {
        let base = detection_id(EXE, 1000, BOOT, 2410, 918_273);
        assert_ne!(
            base,
            detection_id("/tmp/foo-agent", 1000, BOOT, 2410, 918_273)
        );
        assert_ne!(base, detection_id(EXE, 1001, BOOT, 2410, 918_273));
        assert_ne!(
            base,
            detection_id(
                EXE,
                1000,
                "00000000-0000-0000-0000-000000000000",
                2410,
                918_273
            )
        );
        assert_ne!(base, detection_id(EXE, 1000, BOOT, 2411, 918_273));
        assert_ne!(base, detection_id(EXE, 1000, BOOT, 2410, 918_274));
    }

    /// The whole point of `starttime_ticks` + `boot_id`: a recycled pid
    /// is a *different* detection, never a resurrected one.
    #[test]
    fn pid_reuse_cannot_collide() {
        let first = detection_id(EXE, 1000, BOOT, 2410, 918_273);
        // Same pid, same binary, same user — a later process that the
        // kernel handed the recycled number to. Its start tick is
        // necessarily later, because the pid was only free after the
        // first task was reaped.
        let recycled = detection_id(EXE, 1000, BOOT, 2410, 1_204_915);
        assert_ne!(first, recycled);
        // And across boots, where tick counts restart from zero.
        let next_boot = detection_id(
            EXE,
            1000,
            "9a1c0f11-2222-4333-8444-555566667777",
            2410,
            918_273,
        );
        assert_ne!(first, next_boot);
    }

    /// The signature is coarser **on purpose**: same binary, same owner,
    /// different process ⇒ the same thing seen.
    #[test]
    fn a_restart_is_the_same_thing_seen_but_a_different_process() {
        let sig_a = signature_id(EXE, 1000);
        let sig_b = signature_id(EXE, 1000);
        assert_eq!(sig_a, sig_b);
        assert_ne!(
            sig_a,
            signature_id(EXE, 1001),
            "a different user is a different thing"
        );
        assert_ne!(sig_a, signature_id("/tmp/foo-agent", 1000));

        let run_1 = detection_id(EXE, 1000, BOOT, 2410, 918_273);
        let run_2 = detection_id(EXE, 1000, BOOT, 2999, 1_204_915);
        assert_ne!(run_1, run_2, "two runs are two processes");
    }

    /// The NUL separator: no field tuple can be forged into another by
    /// moving a boundary.
    #[test]
    fn field_boundaries_cannot_be_forged() {
        // "/a" + uid 1000  vs  "/a\u{0}1000" + uid "" is not expressible,
        // but the nearest attack — sliding the boundary — must differ.
        assert_ne!(signature_id("/a", 1000), signature_id("/a\u{0}1000", 0));
        assert_ne!(signature_id("/ab", 1), signature_id("/a", 11));
    }

    #[test]
    fn zones_are_classes_never_paths() {
        assert_eq!(
            executable_zone("/home/punar/Downloads/foo-agent"),
            "downloads"
        );
        assert_eq!(
            executable_zone("/home/punar/downloads/foo-agent"),
            "downloads"
        );
        assert_eq!(executable_zone("/tmp/foo-agent"), "tmp");
        assert_eq!(executable_zone("/var/tmp/foo-agent"), "tmp");
        assert_eq!(executable_zone("/home/punar/.local/bin/foo-agent"), "home");
        assert_eq!(executable_zone("/usr/bin/claude"), "system");
        assert_eq!(executable_zone("relative-nonsense"), "unknown");
        // Every zone is a valid ledger class — the type refuses paths.
        for path in [
            "/home/punar/Downloads/x",
            "/tmp/x",
            "/home/punar/x",
            "/usr/bin/x",
            "nope",
        ] {
            assert!(
                punar_common::ledger::ResourceClass::new(
                    punar_common::ledger::ResourceCategory::DirectoryZones,
                    executable_zone(path)
                )
                .is_ok(),
                "{path}"
            );
        }
    }

    #[test]
    fn a_process_start_is_derived_never_invented() {
        // boot at 2026-08-25T00:00:00Z, 918_273 ticks = 9182.73 s later.
        let boot = punar_common::time::unix_seconds_from_rfc3339("2026-08-25T00:00:00Z").unwrap();
        assert_eq!(
            process_started_at(Some(boot), Some(918_273)).as_deref(),
            Some("2026-08-25T02:33:02Z")
        );
        assert_eq!(process_started_at(None, Some(1)), None);
        assert_eq!(process_started_at(Some(boot), None), None);
    }

    #[test]
    fn alert_ids_are_shaped_and_fresh_per_raise() {
        let sig = signature_id(EXE, 1000);
        let first = alert_id(&sig, "2026-08-25T14:31:00Z");
        assert!(punar_common::agent::alert_id_ok(&first), "{first}");
        assert_eq!(first, alert_id(&sig, "2026-08-25T14:31:00Z"));
        assert_ne!(first, alert_id(&sig, "2026-08-26T15:02:00Z"));
    }
}
