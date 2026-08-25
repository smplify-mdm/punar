//! Peer identity and authorization (docs/api/ipc.md sections 1.2, 5).
//!
//! Admission is the socket's filesystem permissions (root or group `punar`
//! can connect at all); this module covers what happens after `accept()`:
//! `SO_PEERCRED` identity, and the M8 attribution adapter.
//!
//! [`authorize_mutation`] is still the M3 rule (uid 0 only) and is still the
//! whole rule for `reconcile` and the enrollment mutations. **It is no
//! longer the whole rule for `capabilities.set`**: Milestone 9 evaluates an
//! agent-attributed peer against the section 20 AI authority document
//! *before* the uid test, and lets a non-root peer through on a live
//! section 48 grant. That ladder lives in `server::m9`, where the policy
//! documents and the approval store are, not here.

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

/// The M8 attribution rule (docs/api/ipc.md section 12.5, SPEC section 22),
/// applied to a connected peer.
///
/// **The rule itself moved to [`punar_common::principal`] in Milestone 9**
/// and this is the thin adapter that feeds it a [`Peer`]. The reason is a
/// privilege boundary, not tidiness: `punar-secrets` has to answer the same
/// question ("is this peer an agent?") to attribute a `credential.request`,
/// and two implementations could disagree about who an agent is. There is
/// one implementation and one test suite; punard and the broker cannot
/// drift apart.
pub fn agent_session_of_peer(proc_root: &Path, peer: &Peer) -> Option<String> {
    punar_common::principal::agent_session_of_pid(proc_root, peer.pid)
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

    /// The parse and the `/proc` read are tested in
    /// `punar_common::principal`, which now owns them (module docs). What
    /// is still punard's to prove is the adapter: a peer the kernel gave no
    /// pid for is never attributed, and never panics.
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
