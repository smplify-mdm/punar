//! Who is running this `punarctl` — for **display only**.
//!
//! Milestone 9 (contract section 14.5) makes `approvals.resolve`
//! human-only, and Plate D-014 register 05 says the `[A]` / `[D]`
//! affordance appears **only when the invoking peer is eligible to
//! resolve**: an agent running `punarctl approvals wait` sees the card
//! and the countdown and no buttons.
//!
//! This module answers that display question and nothing else.
//!
//! **The daemon is the authorization point.** punard re-derives every
//! rule from `SO_PEERCRED` and the peer's own cgroup at `accept()` time
//! and refuses an ineligible resolve regardless of what was printed
//! here — so a process that lies to itself about its identity gains
//! nothing. Printing the affordance is a courtesy; withholding it is
//! honesty about who may act (SPEC section 73).
//!
//! The honest limit, stated where it is relied on: the cgroup is
//! *evidence of attribution*, not a sandbox. An agent that launches a
//! helper outside its own scope escapes attribution and presents as the
//! console user. M9 records the resolver's uid/pid/cgroup so an escape is
//! visible after the fact; the real fixes (a dedicated uid per agent
//! session, a logind seat-presence check) are deferred and named in
//! `docs/development/milestone-9.md` section 4.4.

use std::fs;

/// The systemd scope-name fragment that marks a managed agent session
/// (`punar-agent-<id>.scope`; contract section 12.5).
const AGENT_SCOPE_MARKER: &str = "punar-agent-";

/// This process's **real** uid, read from `/proc/self/status`.
///
/// Read from `/proc` rather than `getuid(2)` deliberately: workspace
/// crates are `#![forbid(unsafe_code)]`, and this value only decides
/// whether a hint is printed. `None` on a non-Linux dev host, where the
/// file does not exist.
pub fn self_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // "Uid:\t<real>\t<effective>\t<saved>\t<fs>"
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// The login name for `uid`, from `/etc/passwd`. No NSS, no getpwuid —
/// this is a display lookup on a single-user appliance, and a name that
/// cannot be resolved simply means the hint is not printed.
pub fn username_of(uid: u32) -> Option<String> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _password = fields.next()?;
        let entry_uid: u32 = fields.next()?.parse().ok()?;
        if entry_uid == uid {
            return Some(name.to_string());
        }
    }
    None
}

/// True when this process sits inside a managed agent scope — the
/// contract section 14.5 rule 1 test, applied to ourselves.
///
/// Checked the strict way the contract specifies: the cgroup path must
/// contain no `punar-agent-` segment **at all**, not merely fail to
/// resolve to a live session. A process that cannot read its own cgroup
/// is treated as attributed (fail closed): the affordance is withheld,
/// never granted, on missing evidence.
pub fn in_agent_scope() -> bool {
    match fs::read_to_string("/proc/self/cgroup") {
        Ok(cgroup) => cgroup.contains(AGENT_SCOPE_MARKER),
        // On Linux, evidence that cannot be read is treated as the worst
        // case: fail closed, withhold the affordance. On a non-Linux dev
        // host there are no agent scopes to be inside of.
        Err(_) => cfg!(target_os = "linux"),
    }
}

/// The eligibility rule itself, as a pure function of its inputs so the
/// three branches of contract section 14.5 are testable without a
/// process to run them in.
fn eligible(in_scope: bool, uid: Option<u32>, login: Option<&str>, routed_user: &str) -> bool {
    // Rule 1 is checked FIRST, exactly as the contract orders it: an AI
    // agent may resolve nothing, ever, including a human's request.
    if in_scope {
        return false;
    }
    match uid {
        Some(0) => true,
        // Approvals are routed to a person; only that person answers.
        Some(_) => !routed_user.is_empty() && login == Some(routed_user),
        // Unknown uid (no procfs — a dev host): show the affordance
        // rather than pretend to know. The daemon still decides.
        None => true,
    }
}

/// Whether this process would be permitted to resolve an approval routed
/// to `routed_user` (contract section 14.5): not agent-attributed,
/// **and** root or the routed person.
///
/// Display only — see the module docs.
pub fn may_resolve(routed_user: &str) -> bool {
    let uid = self_uid();
    let login = uid.and_then(username_of);
    eligible(in_agent_scope(), uid, login.as_deref(), routed_user)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scope marker is the contract's spelling, not an approximation
    /// of it — a rename on either side must break this test.
    #[test]
    fn the_agent_scope_marker_is_the_contract_spelling() {
        assert_eq!(AGENT_SCOPE_MARKER, "punar-agent-");
        assert!("0::/user.slice/punar-agent-agt_4f21.scope".contains(AGENT_SCOPE_MARKER));
        assert!(!"0::/user.slice/session-1.scope".contains(AGENT_SCOPE_MARKER));
    }

    /// Rule 1 outranks everything, including root: root-ness inside an
    /// agent scope buys no bypass (SPEC section 60).
    #[test]
    fn an_agent_scope_is_never_eligible_even_as_root() {
        assert!(!eligible(true, Some(0), Some("root"), "root"));
        assert!(!eligible(true, Some(1000), Some("punar"), "punar"));
    }

    /// Root answers anything; a named user answers only what is routed
    /// to them; an unrouted approval is nobody's to answer.
    #[test]
    fn routing_decides_for_everyone_but_root() {
        assert!(eligible(false, Some(0), Some("root"), "punar"));
        assert!(eligible(false, Some(1000), Some("punar"), "punar"));
        assert!(!eligible(false, Some(1000), Some("punar"), "alice"));
        assert!(!eligible(false, Some(1000), Some("punar"), ""));
        assert!(!eligible(false, Some(1000), None, "punar"));
    }

    /// A dev host with no procfs gets the affordance — the CLI never
    /// pretends to know an identity it could not read, and the daemon is
    /// the authorization point regardless.
    #[test]
    fn an_unknown_uid_shows_the_affordance() {
        assert!(eligible(false, None, None, "punar"));
    }
}
