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

/// Where logind records seat0's state; its `ACTIVE_UID=` line names the
/// user of the session in the foreground on the local seat.
pub const SEAT0_STATE: &str = "/run/systemd/seats/seat0";

/// Capabilities a person may set for themselves from the active local
/// session, with no administrator and no grant (SMP-1405 WP-02). Only
/// person-scoped preferences belong here, never a security setting: the
/// keyboard layout is the tool someone types with, and a password prompt
/// between a person and their own keyboard helps no one. Everything else
/// about the call is unchanged: typed validation, the audit event, the agent
/// refusal that runs first, and an organization's pin, which still wins.
pub const PERSON_SCOPED: &[&str] = &[punar_common::keymap::CAPABILITY_ID];

/// The uid logind reports as active on seat0, if any.
///
/// This is the file sd-login's `sd_seat_get_active` reads. A remote session
/// has no seat and never appears here; the greeter does while it is on
/// screen, but it is not admitted to punard's socket at all.
pub fn seat_active_uid(seat_file: &Path) -> Option<u32> {
    let text = std::fs::read_to_string(seat_file).ok()?;
    text.lines()
        .find_map(|line| line.trim().strip_prefix("ACTIVE_UID="))
        .and_then(|uid| uid.trim().parse().ok())
}

/// Whether `peer` is the person in the active local session.
pub fn is_active_local_person(seat_file: &Path, peer: &Peer) -> bool {
    peer.uid != 0 && seat_active_uid(seat_file) == Some(peer.uid)
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
    fn the_active_local_person_is_read_from_seat0() {
        let dir = std::env::temp_dir().join(format!("punard-seat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let seat = dir.join("seat0");
        let person = Peer {
            uid: 1000,
            gid: 1000,
            pid: None,
        };
        assert!(!is_active_local_person(&seat, &person), "no seat file");
        std::fs::write(
            &seat,
            "# This is private data. Do not parse.\nIS_SEAT0=1\nACTIVE=3\nACTIVE_UID=1000\n",
        )
        .unwrap();
        assert_eq!(seat_active_uid(&seat), Some(1000));
        assert!(is_active_local_person(&seat, &person));
        let other = Peer {
            uid: 1001,
            gid: 1001,
            pid: None,
        };
        assert!(!is_active_local_person(&seat, &other));
        // Root never needs this rule, and never gets it from a file.
        std::fs::write(&seat, "ACTIVE_UID=0\n").unwrap();
        assert!(!is_active_local_person(&seat, &Peer::root()));
        std::fs::write(&seat, "ACTIVE=3\n").unwrap();
        assert_eq!(seat_active_uid(&seat), None, "a seat nobody is using");
        let _ = std::fs::remove_dir_all(&dir);
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
