//! Peer identity for the agentd socket (docs/api/ipc.md sections 1.2 and
//! 10.1 — the transport mechanics are punard's, verbatim).
//!
//! Admission is the socket's filesystem permissions (`0660 root:punar` in a
//! root-owned directory): only root or a member of group `punar` can
//! connect at all. This module covers what happens after `accept()` —
//! `SO_PEERCRED`, the kernel-attested uid that registration verification
//! and `agents.end` authorization are built on (spec section 22:
//! attribution is *checked*, never claimed).

use std::io;
use std::os::unix::net::UnixStream;

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

    /// An unprivileged peer with this uid (`gid` mirrors it; agentd
    /// authorizes on uid alone).
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
/// `Fixed` is the test-only hook — unreachable from the CLI or any config
/// file; only code building an [`crate::server::AgentdConfig`] directly
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

/// May this peer act on a session owned by `owner_uid`?
///
/// Root always may. Otherwise the uids must match — and a session whose
/// owner uid is unknown (replayed from disk after a restart, with a user
/// name that no longer resolves) is root-only: fail closed rather than let
/// an unrelated account end someone else's session.
pub fn may_act_on_session(peer: &Peer, owner_uid: Option<u32>) -> bool {
    peer.is_root() || owner_uid.is_some_and(|uid| uid == peer.uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_authorization_is_owner_or_root_and_fails_closed() {
        assert!(may_act_on_session(&Peer::root(), Some(1000)));
        assert!(may_act_on_session(&Peer::root(), None));
        assert!(may_act_on_session(&Peer::user(1000), Some(1000)));
        assert!(!may_act_on_session(&Peer::user(1001), Some(1000)));
        assert!(
            !may_act_on_session(&Peer::user(1000), None),
            "an unknown owner is root-only, not everyone"
        );
    }
}
