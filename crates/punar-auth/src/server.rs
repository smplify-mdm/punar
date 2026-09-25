//! One connection, one verdict, then exit.
//!
//! systemd owns the listening socket (`punar-authd.socket`, `Accept=yes`) and
//! hands each accepted connection to a fresh process on stdin/stdout. That keeps
//! the crate free of `unsafe` — an accepted connection is addressable through
//! safe std and safe rustix, while inheriting a *listening* descriptor would
//! need a raw-fd conversion `#![forbid(unsafe_code)]` refuses — and it means no
//! root process with authentication authority is resident between attempts.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use pam_client2::conv_mock::Conversation;
use pam_client2::{Context, Flag};
use punar_common::reauth_ticket::{Spender, TICKET_MAX_BYTES, TicketBody, action_ok, process_uids};
use punar_common::trusted_time::{BootStamp, BootWindow, SystemClock, TrustedClock};
use rustix::net::sockopt::{Timeout, set_socket_timeout};
use rustix::rand::{GetRandomFlags, getrandom};
use zeroize::{Zeroize, Zeroizing};

use crate::protocol::{
    Framing, LINE_REQUEST_START, MAX_REQUEST_BYTES, PROTOCOL_VERSION, Purpose, TICKET_DIR, Verdict,
    VerifyRequest, VerifyResponse,
};

/// The stack this daemon runs. Deliberately the same file the lock surface
/// names, so faillock counts a relayed attempt exactly like a typed one and a
/// future edit to that stack applies here without anyone remembering to mirror
/// it.
const PAM_SERVICE: &str = "punar-lock";

/// Below this a uid is a system account. Nothing here has a lock screen, and a
/// service account must not be reachable through a desktop surface.
const MIN_HUMAN_UID: u32 = 1000;

/// Serve the single connection on stdin/stdout, then return.
pub fn session() -> io::Result<()> {
    let stdin = io::stdin();
    // THE IDENTITY COMES FROM THE KERNEL, and it is read before a single byte of
    // the body is parsed, so no request field can reach the code path that
    // decides who is being authenticated.
    let peer = rustix::net::sockopt::socket_peercred(&stdin)
        .map_err(|_| io::Error::other("peer credentials unavailable"))?;
    let uid = peer.uid.as_raw();
    let peer_pid = u32::try_from(peer.pid.as_raw_nonzero().get()).unwrap_or(0);

    // stdin and stdout are the same socket, so one pair of timeouts covers both
    // directions. These bound a single read; the unit's RuntimeMaxSec bounds the
    // whole transaction, because a peer dribbling one byte per interval stays
    // inside a per-read timeout indefinitely.
    let _ = set_socket_timeout(&stdin, Timeout::Recv, Some(Duration::from_secs(10)));
    let _ = set_socket_timeout(&stdin, Timeout::Send, Some(Duration::from_secs(10)));

    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    let decided = decide(uid, &mut reader);
    // The ticket is minted AFTER the verdict and only for the one purpose that
    // asked for it, so no path that merely opens a screen can leave a bearer
    // object behind. A minting failure is not turned into a denial: the secret
    // was correct, and saying otherwise would be the exact lie this daemon's
    // three-verdict rule exists to prevent. The caller sees `ok` with no
    // ticket, and punard refuses the change for a stated, fixable reason.
    let ticket = match (decided.verdict, decided.purpose, &decided.binding) {
        (Verdict::Ok, Purpose::Admin, Some(binding)) => {
            resolve_spender(Path::new("/proc"), uid, peer_pid, binding.for_pid).and_then(
                |spender| {
                    mint_ticket(
                        Path::new(TICKET_DIR),
                        uid,
                        &SystemClock::new(),
                        &binding.action,
                        spender,
                    )
                },
            )
        }
        _ => None,
    };
    write_response(&mut writer, decided.framing, decided.verdict, ticket)
}

/// What an administrative request asked the ticket to be bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Binding {
    /// The method the ticket may be spent on.
    action: String,
    /// The process that will spend it, when not the caller.
    for_pid: Option<u32>,
}

/// One request, understood as far as it could be.
#[derive(Debug)]
struct Decided {
    verdict: Verdict,
    purpose: Purpose,
    framing: Framing,
    /// Present only for an admin request that named a valid action.
    binding: Option<Binding>,
}

impl Decided {
    /// A request that was never understood: never an admin one.
    fn refused(verdict: Verdict, framing: Framing) -> Decided {
        Decided {
            verdict,
            purpose: Purpose::Unlock,
            framing,
            binding: None,
        }
    }
}

/// Read one request in either framing ([`Framing`]) into a buffer that is
/// wiped on drop. `Err(framing)` carries the verdict for a request that could
/// not be read: `Unavailable` for one cut short (the peer said nothing about
/// a password), `Denied` for one too large or malformed.
fn read_request(reader: &mut dyn Read) -> Result<(Zeroizing<Vec<u8>>, Framing), Decided> {
    let mut head = [0_u8; 2];
    if reader.read_exact(&mut head).is_err() {
        return Err(Decided::refused(Verdict::Unavailable, Framing::Length));
    }
    if head == LINE_REQUEST_START {
        // One line: bytes up to the first newline, never more than a request
        // may hold. Read a byte at a time so nothing past the line is
        // consumed and no buffered reader keeps a copy of the secret.
        let mut line = Zeroizing::new(Vec::with_capacity(MAX_REQUEST_BYTES + 1));
        line.extend_from_slice(&head);
        let mut byte = [0_u8; 1];
        loop {
            match reader.read(&mut byte) {
                Ok(0) => return Err(Decided::refused(Verdict::Unavailable, Framing::Line)),
                Ok(_) if byte[0] == b'\n' => break,
                Ok(_) => {
                    if line.len() == MAX_REQUEST_BYTES {
                        return Err(Decided::refused(Verdict::Denied, Framing::Line));
                    }
                    line.push(byte[0]);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(Decided::refused(Verdict::Unavailable, Framing::Line)),
            }
        }
        byte.zeroize();
        return Ok((line, Framing::Line));
    }
    let mut rest = [0_u8; 2];
    if reader.read_exact(&mut rest).is_err() {
        return Err(Decided::refused(Verdict::Unavailable, Framing::Length));
    }
    let len = u32::from_le_bytes([head[0], head[1], rest[0], rest[1]]) as usize;
    if len == 0 || len > MAX_REQUEST_BYTES {
        return Err(Decided::refused(Verdict::Denied, Framing::Length));
    }
    let mut payload = Zeroizing::new(vec![0_u8; len]);
    if reader.read_exact(&mut payload).is_err() {
        return Err(Decided::refused(Verdict::Unavailable, Framing::Length));
    }
    Ok((payload, Framing::Length))
}

/// Read one request and turn it into a verdict, plus what the caller said the
/// answer was for and, for an administrative request, what its ticket is to
/// be bound to.
fn decide(uid: u32, reader: &mut dyn Read) -> Decided {
    let (mut payload, framing) = match read_request(reader) {
        Ok(read) => read,
        Err(refused) => return refused,
    };
    let request: VerifyRequest = match serde_json::from_slice(&payload) {
        Ok(request) => request,
        Err(_) => {
            payload.zeroize();
            return Decided::refused(Verdict::Denied, framing);
        }
    };
    payload.zeroize();
    // The candidate moves into a Zeroizing wrapper BEFORE the version test, so
    // every return from here on scrubs it. Returning on the version mismatch
    // first left `request.password` to be dropped as an ordinary String — the
    // one path out of this function that did not clear the secret.
    let purpose = request.purpose;
    let password = Zeroizing::new(request.password);
    if request.v != PROTOCOL_VERSION {
        return Decided::refused(Verdict::Denied, framing);
    }
    // AN ADMINISTRATIVE TICKET IS ALWAYS BOUND to the call it is for. A
    // request that does not say which call is malformed, and is refused
    // before the stack is asked — so it costs no faillock attempt either.
    let binding = match purpose {
        Purpose::Unlock => None,
        Purpose::Admin => match request.action {
            Some(action) if action_ok(&action) => Some(Binding {
                action,
                for_pid: request.for_pid,
            }),
            _ => return Decided::refused(Verdict::Denied, framing),
        },
    };
    Decided {
        verdict: verify_for_uid(uid, &password),
        purpose,
        framing,
        binding,
    }
}

/// The process a ticket for `uid` will name as its spender: `for_pid` when
/// the caller named one, the caller (`peer_pid`) otherwise. It must be alive
/// and run ENTIRELY as `uid` — real, effective, saved and filesystem — so a
/// caller can name only a process of its own, and naming one gives it nothing
/// it did not have: the password was the caller's to type either way.
fn resolve_spender(
    proc_root: &Path,
    uid: u32,
    peer_pid: u32,
    for_pid: Option<u32>,
) -> Option<Spender> {
    let pid = for_pid.unwrap_or(peer_pid);
    if process_uids(proc_root, pid)? != [uid; 4] {
        return None;
    }
    Spender::of(proc_root, pid)
}

/// Create one single-use ticket for `uid` under `dir`, returning its name.
///
/// THE FILE'S EXISTENCE IS THE WHOLE PROOF OF WHO, which is why it has no
/// signature. `dir` is root-owned and mode 0700, so an unprivileged process
/// cannot create an entry in it; punard, which is root, therefore knows that
/// any name it finds there was written by this daemon after a real PAM success.
/// The uid is the SUBDIRECTORY rather than a field, so no parse can confuse
/// whose ticket it is.
///
/// THE CONTENTS SAY WHEN, FOR WHAT AND BY WHOM
/// ([`punar_common::reauth_ticket::TicketBody`]): the boot-clock stamp of the
/// mint (SMP-1405), the one method it may be spent on, and the one process —
/// pid and start time — that may present it. punard judges the age against
/// its own boot clock, so neither a wall clock stepped back nor a touched
/// mtime can stretch it, and it refuses the ticket from any other process or
/// for any other call. A clock that cannot be read mints no ticket: the
/// caller sees `ok` with no ticket, and punard refuses the change for a
/// stated, fixable reason.
///
/// The clock is read ONCE. The same reading dates the new ticket and judges
/// the old ones in the sweep, so a read that fails halfway through cannot
/// make every other ticket look expired and delete it.
fn mint_ticket(
    dir: &Path,
    uid: u32,
    clock: &dyn TrustedClock,
    action: &str,
    spender: Spender,
) -> Option<String> {
    let stamp = clock.now()?;
    let body = serde_json::to_vec(&TicketBody {
        minted: stamp.clone(),
        action: action.to_string(),
        spender,
    })
    .ok()?;
    let per_uid = dir.join(uid.to_string());
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&per_uid)
        .ok()?;
    // recursive(true) does not apply the mode to a directory that already
    // exists, and a wrong mode here is the one thing that would matter.
    fs::set_permissions(&per_uid, fs::Permissions::from_mode(0o700)).ok()?;
    sweep_expired(&per_uid, &stamp);

    let mut raw = [0_u8; 32];
    let mut filled = 0;
    while filled < raw.len() {
        let count = getrandom(&mut raw[filled..], GetRandomFlags::empty()).ok()?;
        if count == 0 {
            return None;
        }
        filled += count;
    }
    let name: String = raw.iter().map(|b| format!("{b:02x}")).collect();

    let path: PathBuf = per_uid.join(&name);
    // The body is written under a private name first and linked into place
    // complete, so no reader — punard spending it, or another punar-authd
    // sweeping — can ever find the ticket empty. The staging name starts
    // with a dot, which is never a token; the sweep removes one only once
    // the stamp inside it has aged out (a mint killed after writing it).
    let staging = per_uid.join(staging_name(&name));
    let linked = OpenOptions::new()
        .write(true)
        // create_new, here and in hard_link below: a name this daemon just
        // drew at random must not be able to land on an existing file, and 256
        // bits says it will not — so if it somehow does, that is a fact worth
        // failing on rather than papering over by truncating whatever was
        // there.
        .create_new(true)
        .mode(0o600)
        .open(&staging)
        .and_then(|mut file| file.write_all(&body))
        .and_then(|()| fs::hard_link(&staging, &path));
    let _ = fs::remove_file(&staging);
    linked.ok()?;
    Some(name)
}

/// A minted ticket's name: 64 lowercase hexadecimal characters. Anything else
/// in the directory (a staging file being written right now) is not one.
fn is_ticket_name(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

const STAGING_SUFFIX: &str = ".minting";

/// Where the ticket `name` is written before it is linked into place.
fn staging_name(name: &str) -> String {
    format!(".{name}{STAGING_SUFFIX}")
}

/// Whether `name` is a staging file this daemon writes: `.<token>.minting`.
fn is_staging_name(name: &str) -> bool {
    name.strip_prefix('.')
        .and_then(|rest| rest.strip_suffix(STAGING_SUFFIX))
        .is_some_and(is_ticket_name)
}

/// The mint stamp inside the ticket (or staging file) at `path`, or `None`
/// when it cannot be read, is oversized, or is not a ticket body (an older
/// release's bare stamp included: it binds nothing, so it is not kept).
fn read_ticket_stamp(path: &Path) -> Option<BootStamp> {
    let mut body = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(TICKET_MAX_BYTES + 1).read_to_end(&mut body))
        .ok()?;
    TicketBody::parse(&body).map(|ticket| ticket.minted)
}

/// Whether a ticket minted at `stamp` is still within its window at `now`.
fn stamp_is_live(stamp: BootStamp, now: &BootStamp) -> bool {
    BootWindow::of_secs(stamp, crate::protocol::TICKET_MAX_AGE_SECS).is_open(Some(now))
}

/// Whether the ticket at `path` is still within its window at `now`. A file
/// that cannot be read, is oversized, or holds no stamp is not.
fn ticket_is_live(path: &Path, now: &BootStamp) -> bool {
    read_ticket_stamp(path).is_some_and(|stamp| stamp_is_live(stamp, now))
}

/// Remove EXPIRED tickets before minting another, so a session that asks
/// repeatedly does not leave a growing pile of dead files in /run.
///
/// It bounds the litter, not the number of LIVE tickets: two mints inside the
/// window leave two spendable tickets, which is correct — a person who starts
/// two changes and completes both should not have the first one silently
/// invalidated by the second. Each is single-use and each expires on its own
/// clock; punard unlinks on use and re-checks the age, and that is where the
/// guarantee lives.
///
/// Age is read from each ticket's own stamp against `now` — the one reading
/// the caller took — on the boot clock, never from its mtime. A ticket that
/// cannot be dated (an empty one an older punar-authd minted, a damaged one,
/// one from another boot or before a suspend) is not one to keep.
///
/// A STAGING file is left behind only when a mint is killed between writing
/// it and removing it. It is removed once the stamp inside it has aged out,
/// exactly like a ticket. One that is empty or unreadable is kept: it may be
/// another punar-authd's mint, opened this instant and not yet written, and
/// deleting it would fail that person's mint. (The staging name can never be
/// spent: punard only accepts a 64-hex token.)
fn sweep_expired(per_uid: &Path, now: &BootStamp) {
    let Ok(entries) = fs::read_dir(per_uid) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let path = entry.path();
        let expired = if is_ticket_name(&name) {
            !ticket_is_live(&path, now)
        } else if is_staging_name(&name) {
            read_ticket_stamp(&path).is_some_and(|stamp| !stamp_is_live(stamp, now))
        } else {
            false
        };
        if expired {
            let _ = fs::remove_file(path);
        }
    }
}

/// Resolve the peer's uid to a name and run the stack for it.
///
/// Takes a uid rather than a name on purpose: the invariant "the caller cannot
/// choose who they are" is then structural, not a runtime check somebody could
/// later move or forget.
fn verify_for_uid(uid: u32, password: &str) -> Verdict {
    // Root has no lock screen and no need of this service; refusing it removes a
    // whole class of question about what a root-owned caller could ask for.
    if uid < MIN_HUMAN_UID {
        return Verdict::Denied;
    }
    // An empty secret is refused here as well as by DISALLOW_NULL_AUTHTOK below,
    // because a lock that opens on an empty string is not a lock.
    if password.is_empty() {
        return Verdict::Denied;
    }
    let Some(username) = username_for_uid(uid) else {
        // The device could not resolve its own peer. That is a fault here, not
        // a statement about the secret.
        return Verdict::Unavailable;
    };
    authenticate(&username, password)
}

/// `getent passwd <uid>`, the lookup punar-onboard already uses. NSS is what
/// knows about userdb records, and this process runs as root — precisely the
/// privilege the unprivileged caller lacked.
fn username_for_uid(uid: u32) -> Option<String> {
    let output = Command::new("/usr/bin/getent")
        .args(["passwd", &uid.to_string()])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let line = String::from_utf8(output.stdout).ok()?;
    let name = line.split(':').next()?.trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

fn authenticate(username: &str, password: &str) -> Verdict {
    let conversation = Conversation::with_credentials(username, password);
    let Ok(mut context) = Context::new(PAM_SERVICE, Some(username), conversation) else {
        // The stack itself could not be opened — a missing /etc/pam.d file, or a
        // module that will not load. Nothing was decided about the secret.
        return Verdict::Unavailable;
    };
    // DISALLOW_NULL_AUTHTOK: never let an empty token satisfy the stack.
    if context.authenticate(Flag::DISALLOW_NULL_AUTHTOK).is_err() {
        return Verdict::Denied;
    }
    // The account phase still matters: an expired or disabled account must not
    // open a screen just because its secret is still correct.
    if context.acct_mgmt(Flag::DISALLOW_NULL_AUTHTOK).is_err() {
        return Verdict::Denied;
    }
    Verdict::Ok
}

/// The answer, in the framing the request arrived in: a length frame, or
/// one JSON line.
fn write_response(
    writer: &mut dyn Write,
    framing: Framing,
    verdict: Verdict,
    ticket: Option<String>,
) -> io::Result<()> {
    let mut body = Zeroizing::new(
        serde_json::to_vec(&VerifyResponse::with_ticket(verdict, ticket))
            .map_err(|_| io::Error::other("response serialization failed"))?,
    );
    match framing {
        Framing::Length => {
            let len =
                u32::try_from(body.len()).map_err(|_| io::Error::other("response too large"))?;
            writer.write_all(&len.to_le_bytes())?;
            writer.write_all(&body)?;
        }
        Framing::Line => {
            body.push(b'\n');
            writer.write_all(&body)?;
        }
    }
    writer.flush()
}

#[cfg(test)]
mod tests {
    use punar_common::trusted_time::ManualClock;

    use super::*;

    fn framed(body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    const ACTION: &str = "policy.set";
    const SPENDER: Spender = Spender {
        pid: 4242,
        start: 98_765,
    };

    /// A ticket body minted at `clock`'s reading, as a staging file holds it.
    fn body_at(clock: &ManualClock) -> Vec<u8> {
        serde_json::to_vec(&TicketBody {
            minted: clock.now().unwrap(),
            action: ACTION.to_string(),
            spender: SPENDER,
        })
        .unwrap()
    }

    /// A fake `/proc` with one process of `uids` that started at `start`.
    fn fake_proc(tag: &str, pid: u32, uids: [u32; 4], start: u64) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("punar-auth-proc-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join(pid.to_string())).unwrap();
        fs::write(
            root.join(pid.to_string()).join("stat"),
            format!("{pid} (punarctl) S 1 {pid} {pid} 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {start} 0 0\n"),
        )
        .unwrap();
        fs::write(
            root.join(pid.to_string()).join("status"),
            format!(
                "Name:\tpunarctl\nUid:\t{}\t{}\t{}\t{}\n",
                uids[0], uids[1], uids[2], uids[3]
            ),
        )
        .unwrap();
        root
    }

    /// A line request is read as one line, answered as one line, and is
    /// understood exactly like its length-framed twin.
    #[test]
    fn a_line_request_is_understood_and_answered_as_a_line() {
        // uid 999 is refused before PAM, so no stack is needed.
        let mut unlock = io::Cursor::new(b"{\"v\":1,\"password\":\"x\"}\ntrailing".to_vec());
        let decided = decide(999, &mut unlock);
        assert_eq!(decided.framing, Framing::Line);
        assert_eq!(decided.verdict, Verdict::Denied);
        assert_eq!(decided.purpose, Purpose::Unlock);
        assert_eq!(decided.binding, None);
        // Nothing past the newline was consumed.
        let mut rest = String::new();
        unlock.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "trailing");

        let mut admin = io::Cursor::new(
            b"{\"v\":1,\"password\":\"x\",\"purpose\":\"admin\",\"action\":\"approvals.resolve\",\"for_pid\":4242}\n"
                .to_vec(),
        );
        let decided = decide(999, &mut admin);
        assert_eq!(decided.framing, Framing::Line);
        assert_eq!(decided.purpose, Purpose::Admin);
        assert_eq!(
            decided.binding,
            Some(Binding {
                action: "approvals.resolve".to_string(),
                for_pid: Some(4242),
            })
        );

        let mut out = Vec::new();
        write_response(&mut out, Framing::Line, Verdict::Ok, Some("ab".repeat(32))).unwrap();
        assert_eq!(out.last(), Some(&b'\n'));
        assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 1);
        let answer: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(answer["verdict"], "ok");
        assert_eq!(answer["ticket"], "ab".repeat(32));

        let mut framed_out = Vec::new();
        write_response(&mut framed_out, Framing::Length, Verdict::Denied, None).unwrap();
        assert_eq!(&framed_out[4..], br#"{"v":1,"verdict":"denied"}"#);
    }

    #[test]
    fn a_line_cut_short_or_too_long_is_refused_in_line_framing() {
        let mut cut = io::Cursor::new(b"{\"v\":1,\"password\":\"x\"}".to_vec());
        let decided = decide(1000, &mut cut);
        assert_eq!(
            (decided.verdict, decided.framing),
            (Verdict::Unavailable, Framing::Line)
        );

        let mut long = b"{\"v\":1,\"password\":\"".to_vec();
        long.extend(std::iter::repeat_n(b'x', MAX_REQUEST_BYTES));
        long.extend_from_slice(b"\"}\n");
        let decided = decide(1000, &mut io::Cursor::new(long));
        assert_eq!(
            (decided.verdict, decided.framing),
            (Verdict::Denied, Framing::Line)
        );
    }

    /// An administrative ticket is always bound to a call: a request that
    /// does not name one, or names something that is not a method, is
    /// malformed and refused before the stack is asked.
    #[test]
    fn an_admin_request_without_a_method_is_refused_before_pam() {
        for body in [
            br#"{"v":1,"password":"x","purpose":"admin"}"#.as_slice(),
            br#"{"v":1,"password":"x","purpose":"admin","action":"*"}"#.as_slice(),
            br#"{"v":1,"password":"x","purpose":"admin","action":"Policy.Set"}"#.as_slice(),
        ] {
            let decided = decide(1000, &mut io::Cursor::new(framed(body)));
            assert_eq!(
                decided.verdict,
                Verdict::Denied,
                "{}",
                String::from_utf8_lossy(body)
            );
            assert_eq!(decided.purpose, Purpose::Unlock);
            assert_eq!(decided.binding, None);
        }
    }

    /// The spender is the caller, or a process the caller names that runs
    /// entirely as the caller's uid — never another person's process.
    #[test]
    fn a_ticket_names_only_a_process_of_the_callers_own() {
        let root = fake_proc("own", 4242, [1000; 4], 98_765);
        assert_eq!(resolve_spender(&root, 1000, 4242, None), Some(SPENDER));
        assert_eq!(resolve_spender(&root, 1000, 1, Some(4242)), Some(SPENDER));
        // Someone else's process, a gone one, or one whose saved uid differs.
        assert_eq!(resolve_spender(&root, 1001, 1, Some(4242)), None);
        assert_eq!(resolve_spender(&root, 1000, 1, Some(4343)), None);
        let setuid = fake_proc("setuid", 4242, [1000, 0, 0, 0], 98_765);
        assert_eq!(resolve_spender(&setuid, 1000, 4242, None), None);
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(setuid);
    }

    #[test]
    fn system_uids_are_refused_before_any_lookup() {
        assert_eq!(verify_for_uid(0, "anything"), Verdict::Denied);
        assert_eq!(verify_for_uid(999, "anything"), Verdict::Denied);
    }

    #[test]
    fn an_empty_secret_is_refused() {
        assert_eq!(verify_for_uid(1000, ""), Verdict::Denied);
    }

    /// The property that must survive every later edit: for a fixed peer, the
    /// answer may vary between ok and denied, but the SECRET must never decide
    /// whether the device claims it could not ask. Both of these are refused
    /// before PAM is reached, so the test needs no stack and no account.
    #[test]
    fn the_secret_never_decides_whether_the_device_says_unavailable() {
        for secret in ["", "wrong", "another-wrong", "x".repeat(200).as_str()] {
            assert_ne!(
                verify_for_uid(0, secret),
                Verdict::Unavailable,
                "a system uid must be denied, never reported as a device fault"
            );
        }
    }

    #[test]
    fn a_truncated_frame_is_a_device_fault_and_not_a_denial() {
        // A peer that vanishes mid-request has said nothing about a password,
        // so the surface must not be able to render it as a wrong one.
        let mut short = io::Cursor::new(vec![4_u8, 0, 0]);
        assert_eq!(decide(1000, &mut short).verdict, Verdict::Unavailable);
    }

    #[test]
    fn a_malformed_or_oversized_request_is_denied_without_allocating() {
        let mut huge = io::Cursor::new((MAX_REQUEST_BYTES as u32 + 1).to_le_bytes().to_vec());
        assert_eq!(decide(1000, &mut huge).verdict, Verdict::Denied);

        let mut junk = io::Cursor::new(framed(b"not json"));
        assert_eq!(decide(1000, &mut junk).verdict, Verdict::Denied);

        let mut wrong_version = io::Cursor::new(framed(br#"{"v":99,"password":"x"}"#));
        assert_eq!(decide(1000, &mut wrong_version).verdict, Verdict::Denied);
    }

    #[test]
    fn a_username_on_the_wire_is_refused_rather_than_honoured() {
        let mut named = io::Cursor::new(framed(br#"{"v":1,"username":"root","password":"x"}"#));
        assert_eq!(decide(1000, &mut named).verdict, Verdict::Denied);
    }

    /// A request that never gets far enough to be understood must not be
    /// treated as an administrative one. Every early return says Unlock, and
    /// this asserts it for the shapes that take those returns.
    #[test]
    fn a_request_that_was_never_understood_is_never_an_admin_request() {
        for body in [
            framed(b"not json").as_slice(),
            framed(br#"{"v":99,"password":"x","purpose":"admin"}"#).as_slice(),
        ] {
            let mut cursor = io::Cursor::new(body.to_vec());
            assert_eq!(decide(1000, &mut cursor).purpose, Purpose::Unlock);
        }
    }

    const BOOT: &str = "0f2a6c1e-7d3b-4a59-9c8e-1b2d3e4f5a6b";
    const NEXT_BOOT: &str = "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b";

    #[test]
    fn a_minted_ticket_is_a_root_only_file_named_by_its_own_secret() {
        let dir = std::env::temp_dir().join(format!("punar-auth-tickets-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let clock = ManualClock::new(BOOT, 7_000);
        let name = mint_ticket(&dir, 1000, &clock, ACTION, SPENDER).expect("mint");
        assert_eq!(name.len(), 64, "256 bits, hex");
        assert!(name.chars().all(|c| c.is_ascii_hexdigit()));

        let per_uid = dir.join("1000");
        assert_eq!(
            fs::metadata(&per_uid).unwrap().permissions().mode() & 0o777,
            0o700,
            "the directory an unprivileged process must not be able to write"
        );
        let ticket = per_uid.join(&name);
        assert_eq!(
            fs::metadata(&ticket).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // The contents are WHEN (on the boot clock), FOR WHICH CALL and BY
        // WHICH PROCESS: no uid, no name, no secret, and nothing a wall
        // clock could move.
        let body = TicketBody::parse(&fs::read(&ticket).unwrap()).expect("a ticket body");
        assert_eq!(
            body,
            TicketBody {
                minted: BootStamp {
                    boot_id: BOOT.to_string(),
                    raw_bt_ms: 7_000,
                    sleep_ms: 0,
                    suspends: 0,
                },
                action: ACTION.to_string(),
                spender: SPENDER,
            }
        );

        // A second mint is a different secret, in the same place.
        let second = mint_ticket(&dir, 1000, &clock, ACTION, SPENDER).expect("mint again");
        assert_ne!(second, name);
        assert!(per_uid.join(&second).exists());
        assert!(ticket.exists(), "and it did not disturb the first");

        // A different uid cannot reach it: the uid is the directory.
        let other = mint_ticket(&dir, 1001, &clock, ACTION, SPENDER).expect("mint for another uid");
        assert!(dir.join("1001").join(&other).exists());
        assert!(!dir.join("1001").join(&name).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A clock that cannot be read mints nothing, rather than a ticket that
    /// could not be dated.
    #[test]
    fn no_readable_clock_mints_no_ticket() {
        let dir = std::env::temp_dir().join(format!("punar-auth-noclock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let clock = ManualClock::new(BOOT, 7_000);
        clock.set(None);
        assert_eq!(mint_ticket(&dir, 1000, &clock, ACTION, SPENDER), None);
        let left = fs::read_dir(dir.join("1000"))
            .map(|entries| entries.count())
            .unwrap_or(0);
        assert_eq!(left, 0, "no empty ticket was left behind");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn minting_sweeps_a_ticket_that_has_outlived_its_window() {
        let dir = std::env::temp_dir().join(format!("punar-auth-sweep-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let clock = ManualClock::new(BOOT, 7_000);
        let stale = mint_ticket(&dir, 1000, &clock, ACTION, SPENDER).expect("mint");
        let per_uid = dir.join("1000");
        let path = per_uid.join(&stale);
        // An empty ticket, as an older punar-authd minted them, and one from
        // the previous boot: neither can be dated here.
        let legacy = per_uid.join("00".repeat(32));
        fs::write(&legacy, b"").unwrap();
        let previous_boot = per_uid.join("11".repeat(32));
        fs::write(
            &previous_boot,
            format!(r#"{{"boot_id":"{NEXT_BOOT}","raw_bt_ms":7000,"sleep_ms":0,"suspends":0}}"#),
        )
        .unwrap();

        // Age the first past its window on the boot clock. Its mtime is left
        // alone on purpose: the sweep does not read it.
        clock.advance_secs(crate::protocol::TICKET_MAX_AGE_SECS);
        let fresh = mint_ticket(&dir, 1000, &clock, ACTION, SPENDER).expect("mint again");
        assert!(!path.exists(), "the stale ticket did not survive the sweep");
        assert!(!legacy.exists(), "an undatable ticket is not kept");
        assert!(
            !previous_boot.exists(),
            "a ticket from another boot is not kept"
        );
        assert!(per_uid.join(&fresh).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// Another punar-authd may be minting in the same directory at the same
    /// moment. Its staging file is empty until it is linked into place, and
    /// the sweep must not mistake it for an undatable ticket; nor may a
    /// minted ticket ever be visible empty.
    #[test]
    fn minting_never_sweeps_a_ticket_still_being_written() {
        let dir = std::env::temp_dir().join(format!("punar-auth-staging-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let clock = ManualClock::new(BOOT, 7_000);
        let first = mint_ticket(&dir, 1000, &clock, ACTION, SPENDER).expect("mint");
        let per_uid = dir.join("1000");
        let staging = per_uid.join(format!(".{}.minting", "22".repeat(32)));
        fs::write(&staging, b"").unwrap();
        mint_ticket(&dir, 1000, &clock, ACTION, SPENDER).expect("mint again");
        assert!(
            staging.exists(),
            "a concurrent mint's staging file was swept"
        );
        // No staging file of our own is left behind, and every ticket holds
        // its stamp.
        let names: Vec<String> = fs::read_dir(&per_uid)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names.iter().filter(|n| n.starts_with('.')).count(), 1);
        assert!(ticket_is_live(&per_uid.join(&first), &clock.now().unwrap()));
        let _ = fs::remove_dir_all(&dir);
    }

    /// A clock that answers once and then cannot be read.
    #[derive(Debug)]
    struct OneReading(std::sync::Mutex<Option<BootStamp>>);

    impl TrustedClock for OneReading {
        fn now(&self) -> Option<BootStamp> {
            self.0.lock().unwrap().take()
        }
    }

    /// The sweep judges every other ticket on the reading that dated the new
    /// one. A clock that fails after that reading must not make a live
    /// ticket — another session's, minted a moment ago — look expired and
    /// delete it.
    #[test]
    fn a_clock_that_fails_after_the_mint_reading_sweeps_nothing_live() {
        let dir = std::env::temp_dir().join(format!("punar-auth-onceread-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let clock = ManualClock::new(BOOT, 7_000);
        let first = mint_ticket(&dir, 1000, &clock, ACTION, SPENDER).expect("mint");
        clock.advance_secs(10);
        let flaky = OneReading(std::sync::Mutex::new(clock.now()));
        let second = mint_ticket(&dir, 1000, &flaky, ACTION, SPENDER).expect("mint on one reading");
        assert!(
            dir.join("1000").join(&first).exists(),
            "a live ticket was swept over a failed clock read"
        );
        assert!(dir.join("1000").join(&second).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A mint killed after writing its staging file leaves it behind. The
    /// sweep removes it once the stamp inside has aged out, like a ticket;
    /// an empty one (a concurrent mint not yet written) and any other dot
    /// file are left alone.
    #[test]
    fn a_staging_file_a_killed_mint_left_is_swept_once_it_ages_out() {
        let dir = std::env::temp_dir().join(format!("punar-auth-litter-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let clock = ManualClock::new(BOOT, 7_000);
        mint_ticket(&dir, 1000, &clock, ACTION, SPENDER).expect("mint");
        let per_uid = dir.join("1000");
        let left = per_uid.join(staging_name(&"33".repeat(32)));
        fs::write(&left, body_at(&clock)).unwrap();
        let empty = per_uid.join(staging_name(&"44".repeat(32)));
        fs::write(&empty, b"").unwrap();
        let other = per_uid.join(".not-a-staging-file");
        fs::write(&other, body_at(&clock)).unwrap();

        mint_ticket(&dir, 1000, &clock, ACTION, SPENDER).expect("mint inside the window");
        assert!(
            left.exists(),
            "a staging file still inside the window is kept"
        );

        clock.advance_secs(crate::protocol::TICKET_MAX_AGE_SECS);
        mint_ticket(&dir, 1000, &clock, ACTION, SPENDER).expect("mint after the window");
        assert!(!left.exists(), "an aged-out staging file is litter");
        assert!(empty.exists(), "an empty one may be a mint in progress");
        assert!(other.exists(), "the sweep touches only names it writes");

        assert!(is_staging_name(&staging_name(&"ab".repeat(32))));
        assert!(!is_staging_name(".short.minting"));
        assert!(!is_staging_name(&"ab".repeat(32)));
        let _ = fs::remove_dir_all(&dir);
    }

    /// The sweep keeps a ticket that is still inside its window.
    #[test]
    fn minting_keeps_a_ticket_that_is_still_live() {
        let dir = std::env::temp_dir().join(format!("punar-auth-keep-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let clock = ManualClock::new(BOOT, 7_000);
        let first = mint_ticket(&dir, 1000, &clock, ACTION, SPENDER).expect("mint");
        clock.advance_secs(60);
        let second = mint_ticket(&dir, 1000, &clock, ACTION, SPENDER).expect("mint again");
        assert!(dir.join("1000").join(&first).exists());
        assert!(dir.join("1000").join(&second).exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
