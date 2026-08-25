//! Peer identity and authorization (docs/api/ipc.md sections 1.2, 5).
//!
//! Admission is the socket's filesystem permissions (root or group `punar`
//! can connect at all); this module covers what happens after `accept()`:
//! `SO_PEERCRED` identity and the M3 authorization rule — mutations are
//! root-only under the built-in `personal-defaults` rule
//! ([`punar_common::audit::POLICY_PERSONAL_DEFAULTS`]) until Milestone 9
//! JIT elevation.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;

use punar_common::Decision;

/// Peer identity of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    pub gid: u32,
    /// Present when the kernel reported one (always, on Linux).
    pub pid: Option<i32>,
}

impl Peer {
    pub fn root() -> Self {
        Peer {
            uid: 0,
            gid: 0,
            pid: None,
        }
    }
}

/// Where a connection's peer identity comes from.
///
/// `Fixed` is the test-only authz hook: it is not reachable from the CLI or
/// any config file — only code constructing a `DaemonConfig` directly (the
/// integration tests) can select it.
#[derive(Debug, Clone, Copy)]
pub enum PeerSource {
    /// Read `SO_PEERCRED` from the connection (production).
    SoPeercred,
    /// Pretend every connection comes from this peer (tests only).
    Fixed(Peer),
}

impl PeerSource {
    /// Resolve the peer for an accepted connection.
    pub fn peer_of(&self, stream: &UnixStream) -> io::Result<Peer> {
        match self {
            PeerSource::Fixed(peer) => Ok(*peer),
            PeerSource::SoPeercred => peercred(stream),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peercred(stream: &UnixStream) -> io::Result<Peer> {
    let cred = rustix::net::sockopt::socket_peercred(stream)?;
    Ok(Peer {
        uid: cred.uid.as_raw(),
        gid: cred.gid.as_raw(),
        pid: Some(cred.pid.as_raw_nonzero().get()),
    })
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn peercred(_stream: &UnixStream) -> io::Result<Peer> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_PEERCRED is only available on Linux; use PeerSource::Fixed in tests",
    ))
}

/// The unit-name prefix `punar-env` gives a managed agent session's
/// transient scope (`punar-agent-<id>.scope`).
const AGENT_SCOPE_PREFIX: &str = "punar-agent-";
const AGENT_SCOPE_SUFFIX: &str = ".scope";

/// The M8 attribution rule (docs/api/ipc.md section 12.5, SPEC section 22).
///
/// `accept()` already gave us the peer's **pid** from `SO_PEERCRED`. Read
/// that pid's `/proc/<pid>/cgroup`; if the kernel says it lives in a
/// `punar-agent-<id>.scope`, the call was made from inside that managed
/// agent session and the audit event for it is attributed accordingly.
///
/// This is a *read of one small file already owned by a mediation point we
/// terminate* — not tracing. There is no eBPF, no ptrace, no interception,
/// and nothing here observes what the call did (SPEC 1.14). A peer that is
/// not in a scope, whose pid the kernel did not report, or whose `/proc`
/// entry vanished between `accept()` and this read, simply gets `None` and
/// the pre-M8 `agt_none` sentinel — fail-closed towards "no agent", never
/// towards a guess.
pub fn agent_session_of_peer(proc_root: &Path, peer: &Peer) -> Option<String> {
    let pid = peer.pid?;
    if pid <= 0 {
        return None;
    }
    let cgroup = std::fs::read_to_string(proc_root.join(pid.to_string()).join("cgroup")).ok()?;
    agent_session_in_cgroup(&cgroup)
}

/// Extract `agt_<id>` from a `/proc/<pid>/cgroup` body, or `None`.
///
/// Split out from the file read so the parse is testable without a `/proc`
/// fixture. Accepts the cgroup v2 (`0::/…`) and v1 (`N:ctrl:/…`) line
/// shapes alike, because it only looks for the unit name inside the path.
fn agent_session_in_cgroup(cgroup: &str) -> Option<String> {
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

/// The M3 mutation rule: uid 0 only. Reads are open to any admitted peer and
/// never reach this function.
pub fn authorize_mutation(peer: &Peer) -> Decision {
    if peer.uid == 0 {
        Decision::Allow
    } else {
        Decision::Deny
    }
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

    /// A peer with no pid (the `Fixed` test source, or a kernel that did
    /// not report one) is never attributed — and never panics.
    #[test]
    fn a_peer_without_a_pid_is_never_attributed() {
        let root = std::path::Path::new("/nonexistent-proc-root");
        assert_eq!(agent_session_of_peer(root, &Peer::root()), None);
        let ghost = Peer {
            uid: 1000,
            gid: 1000,
            pid: Some(0),
        };
        assert_eq!(agent_session_of_peer(root, &ghost), None);
    }

    #[test]
    fn only_uid_zero_may_mutate() {
        assert_eq!(authorize_mutation(&Peer::root()), Decision::Allow);
        for uid in [1, 1000, 65534] {
            let peer = Peer {
                uid,
                gid: uid,
                pid: None,
            };
            assert_eq!(authorize_mutation(&peer), Decision::Deny);
        }
    }
}
