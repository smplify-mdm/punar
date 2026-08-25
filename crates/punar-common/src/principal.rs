use std::path::Path;

use serde::{Deserialize, Serialize};

/// Identity types recognized by Punar as first-class principals.
///
/// SPEC section 18 ("AI-Native Architecture") lists these identity types:
/// Device, Human, Organization, Project, Application, AI Agent, Service.
///
/// Serialized in `snake_case`; `AiAgent` serializes as `"ai_agent"`, which is
/// the spelling the SPEC section 53 audit example uses for `source`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    Device,
    Human,
    Organization,
    Project,
    Application,
    AiAgent,
    Service,
}

impl PrincipalKind {
    /// All principal kinds, in SPEC section 18 order.
    pub const ALL: [PrincipalKind; 7] = [
        PrincipalKind::Device,
        PrincipalKind::Human,
        PrincipalKind::Organization,
        PrincipalKind::Project,
        PrincipalKind::Application,
        PrincipalKind::AiAgent,
        PrincipalKind::Service,
    ];
}

// ---------------------------------------------------------------------------
// Agent-session attribution (M8 rule, promoted to shared code in M9)
// ---------------------------------------------------------------------------

/// The unit-name prefix `punar-env` gives a managed agent session's
/// transient scope (`punar-agent-<id>.scope`).
pub const AGENT_SCOPE_PREFIX: &str = "punar-agent-";
const AGENT_SCOPE_SUFFIX: &str = ".scope";

/// The M8 attribution rule (docs/api/ipc.md section 12.5, SPEC section 22),
/// **shared** since M9.
///
/// `accept()` already gave the caller the peer's pid from `SO_PEERCRED`.
/// Read that pid's `/proc/<pid>/cgroup`; if the kernel says it lives in a
/// `punar-agent-<id>.scope`, the call was made from inside that managed
/// agent session and the audit event for it is attributed accordingly.
///
/// This is a *read of one small file already owned by a mediation point we
/// terminate* — not tracing. There is no eBPF, no ptrace, no interception,
/// and nothing here observes what the call did (SPEC 1.14). A peer that is
/// not in a scope, whose pid the kernel did not report, or whose `/proc`
/// entry vanished between `accept()` and this read, gets `None` and the
/// pre-M8 `agt_none` sentinel — fail-closed towards "no agent", never
/// towards a guess.
///
/// **Why this lives in `punar-common` as of Milestone 9** (design plan
/// section 3.4): `punard` and `punar-secrets` both have to answer "is this
/// peer an agent?" — punard to gate a mutation behind an approval, the
/// broker to attribute a `credential.request`. Two implementations could
/// disagree about who an agent is, and the disagreement would be a
/// privilege boundary. There is one implementation, with one test suite.
pub fn agent_session_of_pid(proc_root: &Path, pid: Option<i32>) -> Option<String> {
    agent_session_in_cgroup(&peer_cgroup(proc_root, pid)?)
}

/// The peer's raw `/proc/<pid>/cgroup` body, when it can be read.
///
/// Recorded verbatim in an approval's `resolved_by.cgroup` (docs/api/ipc.md
/// section 14.5) so that an attribution escape is **visible after the
/// fact** even where M9 cannot prevent it.
pub fn peer_cgroup(proc_root: &Path, pid: Option<i32>) -> Option<String> {
    let pid = pid?;
    if pid <= 0 {
        return None;
    }
    std::fs::read_to_string(proc_root.join(pid.to_string()).join("cgroup")).ok()
}

/// Extract `agt_<id>` from a `/proc/<pid>/cgroup` body, or `None`.
///
/// Split out from the file read so the parse is testable without a `/proc`
/// fixture. Accepts the cgroup v2 (`0::/…`) and v1 (`N:ctrl:/…`) line
/// shapes alike, because it only looks for the unit name inside the path.
pub fn agent_session_in_cgroup(cgroup: &str) -> Option<String> {
    for line in cgroup.lines() {
        for segment in line.split('/') {
            let Some(rest) = segment.strip_prefix(AGENT_SCOPE_PREFIX) else {
                continue;
            };
            let Some(id) = rest.strip_suffix(AGENT_SCOPE_SUFFIX) else {
                continue;
            };
            // Only a well-formed session id is accepted: the audit schema
            // binds `agent_session_id` to `^agt_[A-Za-z0-9]+$`, and an
            // event that fails validation is worse than no attribution.
            let ok = id.strip_prefix("agt_").is_some_and(|tail| {
                !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_alphanumeric())
            });
            if ok {
                return Some(id.to_string());
            }
        }
    }
    None
}

/// Whether a cgroup body mentions a managed-agent scope **at all**, even a
/// malformed one (`punar-agent-.scope`, `punar-agent-notasession.scope`).
///
/// The strict half of the Milestone 9 human-only rule (docs/api/ipc.md
/// section 14.5). [`agent_session_in_cgroup`] is deliberately conservative:
/// it refuses to *name* a session it cannot spell, because a false name in
/// the tamper-evident record is worse than none. Refusing to *approve* is
/// the opposite trade — there, any smell of an agent scope is enough, and
/// the caller loses nothing by being wrong (a human can always resolve from
/// a shell that is not inside an agent scope).
pub fn cgroup_mentions_agent_scope(cgroup: &str) -> bool {
    cgroup
        .lines()
        .any(|line| line.split('/').any(|s| s.starts_with(AGENT_SCOPE_PREFIX)))
}

/// Whether the peer behind `pid` shows any sign of running inside a managed
/// agent scope. Used by `approvals.resolve` — see
/// [`cgroup_mentions_agent_scope`] for why this is stricter than
/// attribution.
pub fn peer_smells_of_agent_scope(proc_root: &Path, pid: Option<i32>) -> bool {
    peer_cgroup(proc_root, pid).is_some_and(|c| cgroup_mentions_agent_scope(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCOPE_CGROUP: &str = "0::/user.slice/user-1000.slice/user@1000.service/\
app.slice/punar-agent-agt_4f21c09ab3e1.scope\n";

    /// The M8 attribution rule reads exactly one thing out of the cgroup:
    /// the session id in the scope unit name.
    #[test]
    fn a_call_from_inside_an_agent_scope_is_attributed_to_that_session() {
        assert_eq!(
            agent_session_in_cgroup(SCOPE_CGROUP).as_deref(),
            Some("agt_4f21c09ab3e1")
        );
        // cgroup v1 line shape, same answer.
        assert_eq!(
            agent_session_in_cgroup(
                "1:name=systemd:/user.slice/punar-agent-agt_0011aabb2233.scope\n"
            )
            .as_deref(),
            Some("agt_0011aabb2233")
        );
    }

    /// Everything else stays `agt_none`. A daemon that guessed here would
    /// put a false attribution in the tamper-evident record (SPEC 53).
    #[test]
    fn nothing_else_is_attributed_to_an_agent() {
        for cgroup in [
            "",
            "0::/\n",
            "0::/system.slice/punard.service\n",
            "0::/user.slice/user-1000.slice/session-1.scope\n",
            // Looks like a scope, carries no valid session id.
            "0::/user.slice/punar-agent-.scope\n",
            "0::/user.slice/punar-agent-notasession.scope\n",
            "0::/user.slice/punar-agent-agt_bad-id.scope\n",
            // A directory NAMED like a scope but not a unit segment.
            "0::/user.slice/punar-agent-agt_4f21c09ab3e1.service\n",
        ] {
            assert_eq!(agent_session_in_cgroup(cgroup), None, "cgroup: {cgroup:?}");
        }
    }

    /// The resolve-side rule is strictly wider than the attribution rule:
    /// every cgroup that *names* a session smells of one, and so do the
    /// malformed ones that attribution refuses to name (M9 section 14.5).
    #[test]
    fn the_resolve_rule_is_wider_than_the_attribution_rule() {
        for cgroup in [
            SCOPE_CGROUP,
            "0::/user.slice/punar-agent-.scope\n",
            "0::/user.slice/punar-agent-notasession.scope\n",
            "0::/user.slice/punar-agent-agt_bad-id.scope\n",
            "0::/user.slice/punar-agent-agt_4f21c09ab3e1.service\n",
        ] {
            assert!(cgroup_mentions_agent_scope(cgroup), "cgroup: {cgroup:?}");
        }
        for cgroup in [
            "",
            "0::/\n",
            "0::/system.slice/punard.service\n",
            "0::/user.slice/user-1000.slice/session-1.scope\n",
        ] {
            assert!(!cgroup_mentions_agent_scope(cgroup), "cgroup: {cgroup:?}");
        }
    }

    /// A peer with no pid (the `Fixed` test source, or a kernel that did
    /// not report one) is never attributed — and never panics.
    #[test]
    fn a_peer_without_a_pid_is_never_attributed() {
        let root = Path::new("/nonexistent-proc-root");
        assert_eq!(agent_session_of_pid(root, None), None);
        assert_eq!(agent_session_of_pid(root, Some(0)), None);
        assert_eq!(agent_session_of_pid(root, Some(-1)), None);
        assert_eq!(agent_session_of_pid(root, Some(4242)), None);
        assert!(!peer_smells_of_agent_scope(root, Some(4242)));
    }

    /// The `/proc` read itself, against a fixture tree — one file, exactly
    /// the shape the kernel writes.
    #[test]
    fn the_proc_read_finds_the_session() {
        let dir = std::env::temp_dir().join(format!("punar-principal-{}", std::process::id()));
        let proc_pid = dir.join("4242");
        std::fs::create_dir_all(&proc_pid).unwrap();
        std::fs::write(proc_pid.join("cgroup"), SCOPE_CGROUP).unwrap();
        assert_eq!(
            agent_session_of_pid(&dir, Some(4242)).as_deref(),
            Some("agt_4f21c09ab3e1")
        );
        assert!(peer_smells_of_agent_scope(&dir, Some(4242)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn serializes_to_expected_snake_case_names() {
        let expected = [
            (PrincipalKind::Device, "\"device\""),
            (PrincipalKind::Human, "\"human\""),
            (PrincipalKind::Organization, "\"organization\""),
            (PrincipalKind::Project, "\"project\""),
            (PrincipalKind::Application, "\"application\""),
            (PrincipalKind::AiAgent, "\"ai_agent\""),
            (PrincipalKind::Service, "\"service\""),
        ];
        for (kind, json) in expected {
            assert_eq!(serde_json::to_string(&kind).unwrap(), json);
        }
    }

    #[test]
    fn serde_round_trips_every_variant() {
        for kind in PrincipalKind::ALL {
            let json = serde_json::to_string(&kind).unwrap();
            let back: PrincipalKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn unknown_principal_kind_is_rejected() {
        assert!(serde_json::from_str::<PrincipalKind>("\"robot\"").is_err());
    }
}
