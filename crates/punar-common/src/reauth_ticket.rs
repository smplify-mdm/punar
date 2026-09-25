//! What a `punar-authd` ticket binds (F0-S1, F0-S4; docs/api/ipc.md sections
//! 23.1 and 23.5).
//!
//! A ticket is a file `punar-authd` writes under
//! `/run/punar-authd/tickets/<uid>/<token>` after a real PAM success, and
//! punard spends by unlinking it. Its directory says WHO proved themselves
//! (the uid is the subdirectory, and only root can create an entry there).
//! Its body, defined here once for both sides, says three more things:
//!
//! * **when** — [`TicketBody::minted`], a boot-clock stamp punard judges
//!   against its own clock (the ticket lives two minutes, on this boot, with
//!   no suspend in between);
//! * **for which call** — [`TicketBody::action`], the IPC method the person
//!   typed their password for (`policy.set`, `admins.set`, …). punard spends a
//!   ticket only on that method, so a confirmation given for one change can
//!   never be spent on another;
//! * **by which process** — [`TicketBody::spender`], the pid and kernel start
//!   time of the one process allowed to present it. punard compares that with
//!   the peer the kernel reports on the connection (`SO_PEERCRED`) and with
//!   that pid's start time in `/proc`, so a ticket copied out of the process
//!   it was meant for — read from a pipe, answered to a socket some other
//!   program swapped in, found in a core file — is worth nothing to whoever
//!   copied it. The start time is what makes a recycled pid a different
//!   process.
//!
//! WHY THE PROCESS AND NOT ONLY THE UID. Every program a person runs has the
//! person's uid, and so does every AI agent they start. A ticket bound only to
//! the uid is a bearer token inside that person's session: whichever of their
//! programs got hold of it could spend it on anything an administrator may do.
//! Bound to one process, it is spent by the command the person started for
//! the change they typed it for, or by nothing.
//!
//! A ticket in any other shape — an older `punar-authd`'s bare stamp, a
//! damaged file — is not one punard spends: the person types their password
//! again.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::trusted_time::BootStamp;

/// The most a ticket body may hold, and the most either side reads of one.
/// A stamp is ~120 bytes, an action at most [`MAX_ACTION_LEN`], a spender two
/// integers; anything larger is not a ticket.
pub const TICKET_MAX_BYTES: u64 = 512;

/// The longest method name a ticket may carry.
pub const MAX_ACTION_LEN: usize = 64;

/// A ticket's body (module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketBody {
    /// When `punar-authd` minted it, on the boot clock.
    pub minted: BootStamp,
    /// The IPC method it may be spent on, exactly (`policy.set`).
    pub action: String,
    /// The one process that may present it.
    pub spender: Spender,
}

impl TicketBody {
    /// A body read back from a ticket file: `None` for anything that is not
    /// exactly one well-shaped ticket body.
    pub fn parse(bytes: &[u8]) -> Option<TicketBody> {
        if bytes.len() as u64 > TICKET_MAX_BYTES {
            return None;
        }
        serde_json::from_slice::<TicketBody>(bytes)
            .ok()
            .filter(|body| action_ok(&body.action) && body.spender.pid > 0)
    }
}

/// One process, as the kernel names it: a pid and the time it started, in
/// clock ticks since boot (`/proc/<pid>/stat` field 22). A pid alone can be
/// recycled; the pair cannot within a boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spender {
    pub pid: u32,
    pub start: u64,
}

impl Spender {
    /// The live process `pid` under `proc_root` (`/proc` in production), or
    /// `None` when it is gone or its stat file cannot be read.
    pub fn of(proc_root: &Path, pid: u32) -> Option<Spender> {
        if pid == 0 {
            return None;
        }
        process_start_time(proc_root, pid).map(|start| Spender { pid, start })
    }
}

/// Whether `name` has the shape of an IPC method name a ticket may carry:
/// dotted lowercase words (`policy.set`, `approvals.resolve`), at most
/// [`MAX_ACTION_LEN`] bytes. Whether it names a method that takes tickets is
/// punard's question, answered by comparing it with the call being made.
pub fn action_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_ACTION_LEN
        && name.split('.').all(|word| {
            let mut bytes = word.bytes();
            matches!(bytes.next(), Some(b'a'..=b'z'))
                && bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
        })
}

/// Field 22 of `<proc_root>/<pid>/stat`: when the process started, in clock
/// ticks since boot. The command name (field 2) may contain spaces and
/// parentheses, so the fields are counted from the LAST `)`.
pub fn process_start_time(proc_root: &Path, pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    let after = &stat[stat.rfind(')')? + 1..];
    // After the name come field 3 (state) onwards: field 22 is the 20th.
    after.split_whitespace().nth(19)?.parse().ok()
}

/// The real, effective, saved and filesystem uids of `pid` (the `Uid:` line
/// of `<proc_root>/<pid>/status`), or `None` when it cannot be read.
pub fn process_uids(proc_root: &Path, pid: u32) -> Option<[u32; 4]> {
    let status = fs::read_to_string(proc_root.join(pid.to_string()).join("status")).ok()?;
    let line = status.lines().find_map(|line| line.strip_prefix("Uid:"))?;
    let ids: Vec<u32> = line
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    <[u32; 4]>::try_from(ids).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp() -> BootStamp {
        BootStamp {
            boot_id: "0f2a6c1e-7d3b-4a59-9c8e-1b2d3e4f5a6b".to_string(),
            raw_bt_ms: 5_000_000,
            sleep_ms: 0,
            suspends: 0,
        }
    }

    #[test]
    fn a_body_round_trips_and_nothing_else_parses_as_one() {
        let body = TicketBody {
            minted: stamp(),
            action: "policy.set".to_string(),
            spender: Spender {
                pid: 4242,
                start: 98_765,
            },
        };
        let bytes = serde_json::to_vec(&body).unwrap();
        assert!((bytes.len() as u64) < TICKET_MAX_BYTES);
        assert_eq!(TicketBody::parse(&bytes), Some(body.clone()));

        // An older punar-authd's ticket: a bare stamp, bound to nothing.
        let bare = serde_json::to_vec(&stamp()).unwrap();
        assert_eq!(TicketBody::parse(&bare), None);
        // A field this build does not know is not ignored.
        let mut extra = serde_json::to_value(&body).unwrap();
        extra["purpose"] = "anything".into();
        assert_eq!(TicketBody::parse(extra.to_string().as_bytes()), None);
        // An action that is not a method name.
        let mut wild = body.clone();
        wild.action = "*".to_string();
        assert_eq!(TicketBody::parse(&serde_json::to_vec(&wild).unwrap()), None);
        // No process.
        let mut nobody = body;
        nobody.spender.pid = 0;
        assert_eq!(
            TicketBody::parse(&serde_json::to_vec(&nobody).unwrap()),
            None
        );
        // Oversized.
        assert_eq!(
            TicketBody::parse(&vec![b' '; TICKET_MAX_BYTES as usize + 1]),
            None
        );
    }

    #[test]
    fn only_method_names_are_actions() {
        for good in [
            "policy.set",
            "approvals.resolve",
            "enroll.start",
            "admins.set",
        ] {
            assert!(action_ok(good), "{good}");
        }
        for bad in [
            "",
            "*",
            "Policy.set",
            "policy..set",
            ".policy",
            "policy.",
            "policy set",
            "1policy.set",
            "policy/set",
        ] {
            assert!(!action_ok(bad), "{bad:?}");
        }
        assert!(!action_ok(&"a".repeat(MAX_ACTION_LEN + 1)));
    }

    #[test]
    fn the_start_time_is_counted_from_the_last_parenthesis() {
        let root = std::env::temp_dir().join(format!("punar-ticket-stat-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("77")).unwrap();
        // A command name with a space and a `)` in it, as a hostile program
        // may name itself.
        fs::write(
            root.join("77/stat"),
            "77 (evil) 1 2 3) S 1 77 77 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 123456 0 0\n",
        )
        .unwrap();
        assert_eq!(process_start_time(&root, 77), Some(123_456));
        assert_eq!(
            Spender::of(&root, 77),
            Some(Spender {
                pid: 77,
                start: 123_456
            })
        );
        assert_eq!(Spender::of(&root, 78), None);
        assert_eq!(Spender::of(&root, 0), None);
        fs::write(
            root.join("77/status"),
            "Name:\tx\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n",
        )
        .unwrap();
        assert_eq!(process_uids(&root, 77), Some([1000; 4]));
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn this_process_has_a_start_time() {
        let me = std::process::id();
        let spender = Spender::of(Path::new("/proc"), me).expect("/proc/self/stat");
        assert_eq!(spender.pid, me);
        assert!(process_uids(Path::new("/proc"), me).is_some());
    }
}
