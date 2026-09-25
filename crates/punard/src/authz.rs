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

/// Where logind records each session (`/run/systemd/sessions/<id>`): its
/// `UID=`, `SEAT=`, `ACTIVE=` and `REMOTE=` lines are what sd-login's
/// `sd_session_*` calls read.
pub const SESSIONS_DIR: &str = "/run/systemd/sessions";

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
/// This is the file sd-login's `sd_seat_get_active` reads. It says who is in
/// front of the machine, not that the CALLER is that person's seat session:
/// [`is_active_local_person`] checks the caller's own session too.
pub fn seat_active_uid(seat_file: &Path) -> Option<u32> {
    let text = std::fs::read_to_string(seat_file).ok()?;
    text.lines()
        .find_map(|line| line.trim().strip_prefix("ACTIVE_UID="))
        .and_then(|uid| uid.trim().parse().ok())
}

/// The logind session a `/proc/<pid>/cgroup` body places a process in, for
/// that uid: the unified-hierarchy path
/// `/user.slice/user-<uid>.slice/session-<id>.scope`.
///
/// Only that path counts. A user service, a D-Bus-activated app or anything
/// started with `systemd-run --user` lives under `user@<uid>.service`
/// instead, and a managed agent under its `punar-agent-<id>.scope`; none of
/// them is in a session scope. The session scope is root's (logind creates
/// it and delegates nothing), so a process of that uid cannot move itself
/// into it.
pub fn logind_session_in_cgroup(cgroup: &str, uid: u32) -> Option<String> {
    let slice = format!("user-{uid}.slice");
    for line in cgroup.lines() {
        let Some(path) = line.strip_prefix("0::") else {
            continue;
        };
        let mut segments = path.split('/').filter(|s| !s.is_empty());
        if segments.next() != Some("user.slice") || segments.next() != Some(slice.as_str()) {
            continue;
        }
        let Some(id) = segments
            .next()
            .and_then(|s| s.strip_prefix("session-"))
            .and_then(|s| s.strip_suffix(".scope"))
        else {
            continue;
        };
        if !id.is_empty() && id.len() <= 32 && id.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Some(id.to_string());
        }
    }
    None
}

/// Whether logind records `session` as this uid's active, local session on
/// seat0: `UID=<uid>`, `SEAT=seat0`, `ACTIVE=1` and `REMOTE=0`, all present.
/// An SSH login has `REMOTE=1` and no seat; a session on another VT is not
/// `ACTIVE=1`; the greeter's session belongs to the greeter's uid.
pub fn session_is_seated(sessions_dir: &Path, session: &str, uid: u32) -> bool {
    let Ok(text) = std::fs::read_to_string(sessions_dir.join(session)) else {
        return false;
    };
    let value = |key: &str| {
        text.lines()
            .find_map(|line| line.trim().strip_prefix(key)?.strip_prefix('='))
            .map(str::trim)
    };
    value("UID") == Some(uid.to_string().as_str())
        && value("SEAT") == Some("seat0")
        && value("ACTIVE") == Some("1")
        && value("REMOTE") == Some("0")
}

/// Where a person-scoped call is allowed to come from.
#[derive(Debug, Clone, Copy)]
pub struct SeatSources<'a> {
    /// `/run/systemd/seats/seat0`.
    pub seat_file: &'a Path,
    /// `/run/systemd/sessions`.
    pub sessions_dir: &'a Path,
    /// `/proc`, where the peer's cgroup is read.
    pub proc_root: &'a Path,
}

/// Whether `peer` is the person at the machine, calling from their own
/// session on it (SMP-1405 WP-02's seat-presence check, the fix docs/api/
/// ipc.md section 14.5 named for attribution).
///
/// Three things must agree, each read from a file root or the kernel owns:
/// logind names the peer's uid as seat0's active user; the kernel places the
/// peer's process in one of that uid's session scopes; and logind records
/// that session as active, local and on seat0. Same uid is not enough: a
/// user service, an SSH login or a helper an agent started outside its scope
/// with `systemd-run --user` runs as the same uid while the person is at the
/// machine, and none of them is refused by the uid alone.
///
/// What this cannot see (stated in docs/api/ipc.md, as for attribution): a
/// same-uid process that makes the session's own compositor or terminal
/// server start a command for it gets a process in the session scope. The
/// cgroup is evidence of where a call came from, not a sandbox.
pub fn is_active_local_person(sources: SeatSources<'_>, peer: &Peer) -> bool {
    if peer.uid == 0 || seat_active_uid(sources.seat_file) != Some(peer.uid) {
        return false;
    }
    let Some(cgroup) = punar_common::principal::peer_cgroup(sources.proc_root, peer.pid) else {
        return false;
    };
    logind_session_in_cgroup(&cgroup, peer.uid)
        .is_some_and(|session| session_is_seated(sources.sessions_dir, &session, peer.uid))
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

    /// A seat, a session record and a /proc, under one temporary root.
    struct SeatFixture {
        dir: std::path::PathBuf,
    }

    impl SeatFixture {
        fn new(name: &str) -> SeatFixture {
            let dir =
                std::env::temp_dir().join(format!("punard-seat-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("sessions")).unwrap();
            std::fs::create_dir_all(dir.join("proc")).unwrap();
            SeatFixture { dir }
        }

        fn seat(&self, text: &str) {
            std::fs::write(self.dir.join("seat0"), text).unwrap();
        }

        fn session(&self, id: &str, text: &str) {
            std::fs::write(self.dir.join("sessions").join(id), text).unwrap();
        }

        fn process(&self, pid: i32, cgroup: &str) {
            let proc_pid = self.dir.join("proc").join(pid.to_string());
            std::fs::create_dir_all(&proc_pid).unwrap();
            std::fs::write(proc_pid.join("cgroup"), cgroup).unwrap();
        }

        fn sources(&self) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
            (
                self.dir.join("seat0"),
                self.dir.join("sessions"),
                self.dir.join("proc"),
            )
        }

        fn allows(&self, peer: &Peer) -> bool {
            let (seat, sessions, proc_root) = self.sources();
            is_active_local_person(
                SeatSources {
                    seat_file: &seat,
                    sessions_dir: &sessions,
                    proc_root: &proc_root,
                },
                peer,
            )
        }
    }

    impl Drop for SeatFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    const SEATED: &str = "# This is private data. Do not parse.\nUID=1000\nUSER=punar\nACTIVE=1\n\
                          IS_DISPLAY=1\nSTATE=active\nREMOTE=0\nTYPE=wayland\nCLASS=user\n\
                          SEAT=seat0\nVTNR=1\n";

    fn person(pid: i32) -> Peer {
        Peer {
            uid: 1000,
            gid: 1000,
            pid: Some(pid),
        }
    }

    #[test]
    fn the_active_local_person_is_read_from_seat0() {
        let dir = std::env::temp_dir().join(format!("punard-seat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let seat = dir.join("seat0");
        assert_eq!(seat_active_uid(&seat), None, "no seat file");
        std::fs::write(
            &seat,
            "# This is private data. Do not parse.\nIS_SEAT0=1\nACTIVE=3\nACTIVE_UID=1000\n",
        )
        .unwrap();
        assert_eq!(seat_active_uid(&seat), Some(1000));
        std::fs::write(&seat, "ACTIVE=3\n").unwrap();
        assert_eq!(seat_active_uid(&seat), None, "a seat nobody is using");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_a_session_scope_of_that_uid_names_a_session() {
        assert_eq!(
            logind_session_in_cgroup("0::/user.slice/user-1000.slice/session-3.scope\n", 1000)
                .as_deref(),
            Some("3")
        );
        // logind's non-numeric ids (a session started by a background
        // manager) are still ids.
        assert_eq!(
            logind_session_in_cgroup("0::/user.slice/user-1000.slice/session-c1.scope", 1000)
                .as_deref(),
            Some("c1")
        );
        for cgroup in [
            // A user service, a D-Bus-activated app, `systemd-run --user`.
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-foot.scope",
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/run-u42.service",
            // A managed agent's scope.
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/punar-agent-agt_4f21.scope",
            // Another uid's session.
            "0::/user.slice/user-1001.slice/session-3.scope",
            // A system service.
            "0::/system.slice/punard.service",
            // cgroup v1 shapes are not read.
            "1:name=systemd:/user.slice/user-1000.slice/session-3.scope",
            "0::/user.slice/user-1000.slice/session-.scope",
            "0::/user.slice/user-1000.slice/session-3;x.scope",
            "",
        ] {
            assert_eq!(logind_session_in_cgroup(cgroup, 1000), None, "{cgroup:?}");
        }
    }

    #[test]
    fn the_person_at_the_seat_calling_from_their_seat_session_qualifies() {
        let f = SeatFixture::new("seated");
        f.seat("IS_SEAT0=1\nACTIVE=3\nACTIVE_UID=1000\n");
        f.session("3", SEATED);
        f.process(4242, "0::/user.slice/user-1000.slice/session-3.scope\n");
        assert!(f.allows(&person(4242)));
    }

    /// The same uid is not the same person at the machine (the review's M1).
    #[test]
    fn the_same_uid_from_anywhere_but_the_seat_session_does_not_qualify() {
        let f = SeatFixture::new("elsewhere");
        f.seat("ACTIVE_UID=1000\n");
        f.session("3", SEATED);
        f.session(
            "7",
            &SEATED
                .replace("REMOTE=0", "REMOTE=1")
                .replace("SEAT=seat0\n", ""),
        );
        f.session("9", &SEATED.replace("ACTIVE=1", "ACTIVE=0"));
        f.session("11", &SEATED.replace("SEAT=seat0", "SEAT=seat1"));
        f.session("13", &SEATED.replace("UID=1000", "UID=1001"));
        f.session("15", &SEATED.replace("REMOTE=0\n", ""));
        // A user service, and a helper an escaped agent started with
        // `systemd-run --user`: the same uid, while the person is seated.
        f.process(
            100,
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/punar-sync.service\n",
        );
        f.process(
            101,
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/run-u9.service\n",
        );
        // An SSH login, a session on another VT, another seat, a record
        // that names another uid, a record with no REMOTE line.
        for (pid, session) in [
            (102, "7"),
            (103, "9"),
            (104, "11"),
            (105, "13"),
            (106, "15"),
        ] {
            f.process(
                pid,
                &format!("0::/user.slice/user-1000.slice/session-{session}.scope\n"),
            );
        }
        // A session record that is gone.
        f.process(107, "0::/user.slice/user-1000.slice/session-99.scope\n");
        for pid in 100..=107 {
            assert!(!f.allows(&person(pid)), "pid {pid}");
        }
        // No pid from the kernel, or a /proc entry that is gone.
        assert!(!f.allows(&Peer {
            uid: 1000,
            gid: 1000,
            pid: None
        }));
        assert!(!f.allows(&person(4040)));
    }

    #[test]
    fn nobody_seated_or_someone_else_seated_does_not_qualify() {
        let f = SeatFixture::new("unseated");
        f.session("3", SEATED);
        f.process(4242, "0::/user.slice/user-1000.slice/session-3.scope\n");
        assert!(!f.allows(&person(4242)), "no seat file");
        f.seat("ACTIVE=3\n");
        assert!(!f.allows(&person(4242)), "a seat nobody is using");
        f.seat("ACTIVE_UID=1001\n");
        assert!(!f.allows(&person(4242)), "someone else is at the machine");
        // Root never needs this rule, and never gets it from a file.
        f.seat("ACTIVE_UID=0\n");
        f.process(1, "0::/user.slice/user-0.slice/session-3.scope\n");
        assert!(!f.allows(&Peer {
            uid: 0,
            gid: 0,
            pid: Some(1)
        }));
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
