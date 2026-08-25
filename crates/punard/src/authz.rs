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
