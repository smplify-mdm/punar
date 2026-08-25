//! Peer identity for the broker socket (docs/api/ipc.md sections 1.2,
//! 16.1).
//!
//! Admission is the socket's filesystem permissions (`0660 root:punar`
//! inside `0750 root:punar`): only root or a member of group `punar`
//! reaches `accept()` at all. This module covers what happens after —
//! `SO_PEERCRED` for the kernel-attested uid/pid, and the section 12.5
//! agent-attribution rule.
//!
//! # One rule, two daemons
//!
//! The attribution rule itself is **not** implemented here. It lives in
//! [`punar_common::principal`], promoted to shared code by the Milestone 9
//! design (plan section 3.4) precisely so that `punard` and `punar-secrets`
//! cannot disagree about who an agent is: punard gates a mutation on that
//! answer, the broker attributes a `credential.request` on it, and a
//! disagreement between two copies would be a privilege boundary with two
//! opinions. This module only carries the per-daemon peer struct and the
//! test hook.
//!
//! Fail-closed direction, restated because it is the security property: a
//! peer whose pid the kernel did not report, whose `/proc` entry vanished,
//! or whose cgroup carries no well-formed session id is *not an agent* —
//! `None`, never a guess.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;

pub use punar_common::principal::{agent_session_in_cgroup, agent_session_of_pid};

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

    /// An unprivileged peer with this uid (`gid` mirrors it).
    pub fn user(uid: u32) -> Self {
        Peer {
            uid,
            gid: uid,
            pid: None,
        }
    }

    pub fn is_root(&self) -> bool {
        self.uid == 0
    }
}

/// Where a connection's peer identity comes from.
///
/// `Fixed` is the test-only hook: unreachable from the CLI or any config
/// file — only code building a [`crate::server::SecretsConfig`] directly
/// (the tests) can select it.
#[derive(Debug, Clone, Copy)]
pub enum PeerSource {
    /// Read `SO_PEERCRED` from the connection (production).
    SoPeercred,
    /// Pretend every connection comes from this peer (tests only).
    Fixed(Peer),
}

impl PeerSource {
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

/// The managed agent session this peer is calling from, if any — the shared
/// section 12.5 rule, applied to a broker connection.
pub fn agent_session_of_peer(proc_root: &Path, peer: &Peer) -> Option<String> {
    agent_session_of_pid(proc_root, peer.pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCOPE_CGROUP: &str = "0::/user.slice/user-1000.slice/user@1000.service/\
app.slice/punar-agent-agt_4f21c09ab3e1.scope\n";

    /// The shared rule is exercised by `punar-common`'s own tests; what
    /// matters here is that the broker is wired to it and that a
    /// `PeerSource::Fixed` peer (no pid) is never attributed — the shape
    /// every unit test in this crate runs under.
    #[test]
    fn the_broker_reads_attribution_from_the_shared_rule() {
        assert_eq!(
            agent_session_in_cgroup(SCOPE_CGROUP).as_deref(),
            Some("agt_4f21c09ab3e1")
        );
        assert_eq!(
            agent_session_in_cgroup("0::/system.slice/punar-secrets.service\n"),
            None
        );
    }

    #[test]
    fn a_peer_without_a_pid_is_never_attributed() {
        let root = Path::new("/nonexistent-proc-root");
        assert_eq!(agent_session_of_peer(root, &Peer::root()), None);
        assert_eq!(agent_session_of_peer(root, &Peer::user(1000)), None);
        let ghost = Peer {
            uid: 1000,
            gid: 1000,
            pid: Some(0),
        };
        assert_eq!(agent_session_of_peer(root, &ghost), None);
    }
}
