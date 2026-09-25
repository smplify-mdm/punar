#![forbid(unsafe_code)]
//! `punar-reauth` — the one client library for a person's password (F0-S4;
//! PLAN.md section 2.1; docs/api/ipc.md section 23.5).
//!
//! It turns a password into a `punar-authd` ticket, and it takes the password
//! from exactly two kinds of place:
//!
//! 1. **the controlling terminal**, with echo off ([`read_terminal_line`]);
//! 2. **a descriptor that `fstat` proves is a socket** — one the caller passes
//!    by number ([`password_from_fd`]), or the private rendezvous a graphical
//!    parent answers ([`ParentHandoff`]).
//!
//! PIPES, STDIN AND ARGV ARE REFUSED, and the reason is one property of Linux.
//! Any process running as the same uid can open `/proc/<pid>/fd/<n>` of a
//! dumpable process, and for a pipe that open *succeeds*: it hands back a new
//! reader on the same pipe, which can take the password before the intended
//! reader sees it. For a socket the same open fails with `ENXIO`. argv and the
//! environment are readable in `/proc/<pid>/cmdline` and `environ` outright.
//! So a secret that crosses a pipe is a secret every program of that person
//! can race for; one that crosses a socket is not. The test
//! `a_pipe_reopens_through_proc_and_a_socket_does_not` pins the property this
//! rests on.
//!
//! HOLDERS ARE NOT DUMPABLE. [`harden`] sets `PR_SET_DUMPABLE=0` and
//! `RLIMIT_CORE=0`. Every process that holds a password, a ticket or an
//! unlocked connection calls it before it reads one: a non-dumpable process's
//! `/proc/<pid>/fd`, `/proc/<pid>/mem` and `environ` are closed to other
//! processes of the same uid, and it leaves no core file with a secret in it.
//!
//! EVERYTHING SECRET IS `Zeroizing`: the line buffer, the request body, the
//! returned password and the ticket.
//!
//! THE TICKET COMES FROM `punar-authd` DIRECTLY, over its socket. This crate
//! does not link `punar-auth` (which links libpam) and does not spawn its
//! relay, whose stdin is a pipe: the wire contract is small, and
//! `the_wire_contract_is_punar_auths` pins it to the relay's own source.

use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use zeroize::Zeroizing;

/// `punar-authd`'s socket (`crates/punar-auth/src/bin/punar-auth.rs`).
pub const AUTHD_SOCKET: &str = "/run/punar-authd/auth.sock";

/// The longest secret line accepted. `punar-authd` bounds its whole request
/// at 4096 bytes, so nothing longer could be verified anyway.
pub const MAX_SECRET_BYTES: usize = 4096;

/// `punar-authd`'s wire version and response bound.
const PROTOCOL_VERSION: u32 = 1;
const MAX_RESPONSE_BYTES: usize = 4096;

/// A ticket is 256 bits of lowercase hex, exactly as punard checks it.
pub const TICKET_LEN: usize = 64;

/// How long a descriptor or rendezvous peer may take to deliver one line.
/// The graphical parent already holds the password when it starts the
/// command, so this bounds a stuck peer, not a person typing.
pub const DELIVERY_TIMEOUT: Duration = Duration::from_secs(30);

/// A password, wiped when it is dropped.
pub type Password = Zeroizing<String>;

/// A single-use `punar-authd` ticket. Never printed: `Debug` says only that
/// it exists.
pub struct Ticket(Zeroizing<String>);

impl Ticket {
    /// The ticket, to put in one request's `ticket` field and nowhere else.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `Some` for 64 lowercase hex characters — the only shape punard spends
    /// — and `None` for everything else, including uppercase hex.
    pub fn parse(text: &str) -> Option<Ticket> {
        (text.len() == TICKET_LEN
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .then(|| Ticket(Zeroizing::new(text.to_string())))
    }
}

impl fmt::Debug for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ticket([redacted])")
    }
}

/// Why a password or ticket could not be taken from where it was offered.
/// Every message says what to do instead; none contains the secret.
#[derive(Debug)]
pub enum SourceError {
    /// Descriptor 0, 1 or 2: shared with whatever started the program.
    StandardStream(i32),
    /// Nothing is open at that number in this process.
    NotOpen(i32),
    /// Something other than a socket: a pipe, a file, a terminal.
    NotASocket { fd: i32, kind: &'static str },
    /// The descriptor closed before a line arrived.
    Empty,
    /// The line was longer than any password this device accepts.
    TooLong,
    /// The line was not a ticket (`--ticket-fd` only).
    NotATicket,
    /// Nothing arrived in time.
    Timeout,
    /// The rendezvous was answered by a process that did not start this one.
    NotTheParent,
    /// Nothing arrived, and the rendezvous name no longer names this
    /// process's socket: another program removed or replaced it, and the
    /// parent may have sent the password there instead.
    Intercepted(PathBuf),
    /// The private rendezvous directory is not private.
    UnsafeDirectory(PathBuf),
    /// This process may not take over its own descriptors: `pidfd_getfd` is
    /// filtered, as a seccomp sandbox can do.
    Unsupported(i32),
    /// Any other I/O failure.
    Io(io::Error),
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceError::StandardStream(fd) => write!(
                f,
                "descriptor {fd} is a standard stream, which is shared with whatever started \
                 this program; pass a socket on descriptor 3 or above"
            ),
            SourceError::NotOpen(fd) => write!(f, "nothing is open on descriptor {fd}"),
            SourceError::NotASocket { fd, kind } => write!(
                f,
                "descriptor {fd} is {kind}, not a socket. A pipe or file can be reopened by \
                 any program running as you, through /proc, and read before this one reads \
                 it; a socket cannot. Pass a Unix socket (for example one end of a \
                 socketpair)"
            ),
            SourceError::Empty => f.write_str("nothing arrived before the other end closed"),
            SourceError::TooLong => {
                f.write_str("the line is longer than any password this device accepts")
            }
            SourceError::NotATicket => f.write_str(
                "what arrived is not a confirmation ticket: expected `ok <ticket>` or the \
                 64-character ticket itself",
            ),
            SourceError::Timeout => f.write_str("nothing arrived in time"),
            SourceError::NotTheParent => f.write_str(
                "a program other than the one that started this command tried to answer its \
                 password prompt, so nothing was read",
            ),
            SourceError::Intercepted(path) => write!(
                f,
                "the private socket at {} was removed or replaced by another program before \
                 your password arrived, so it may have been sent to that program instead. \
                 Nothing was changed. Treat your account password as known to that \
                 program: change it, and look for a program you did not start",
                path.display()
            ),
            SourceError::UnsafeDirectory(dir) => write!(
                f,
                "{} is not a private directory of yours, so no password is received there",
                dir.display()
            ),
            SourceError::Unsupported(fd) => write!(
                f,
                "this program is not allowed to take over its own descriptor {fd} here (a \
                 seccomp filter refuses pidfd_getfd); run the command in a terminal, which \
                 asks for the password itself"
            ),
            SourceError::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SourceError {}

impl From<io::Error> for SourceError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => SourceError::Timeout,
            _ => SourceError::Io(error),
        }
    }
}

impl From<rustix::io::Errno> for SourceError {
    fn from(errno: rustix::io::Errno) -> Self {
        SourceError::from(io::Error::from(errno))
    }
}

// ---------------------------------------------------------------------------
// Hardening
// ---------------------------------------------------------------------------

/// Make this process a safe holder of a secret: not dumpable
/// (`PR_SET_DUMPABLE=0`), and no core file (`RLIMIT_CORE=0`, soft and hard).
///
/// Not dumpable is what closes `/proc/<pid>/fd`, `/proc/<pid>/mem` and
/// `/proc/<pid>/environ` to other processes of the same uid (the kernel's
/// ptrace access check refuses a non-dumpable target without
/// `CAP_SYS_PTRACE`). Call it before the first secret is read; it cannot be
/// undone by the process itself, which is the point.
pub fn harden() -> io::Result<()> {
    use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};
    set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;
    Ok(())
}

/// Whether [`harden`] is in effect for this process.
pub fn is_hardened() -> bool {
    use rustix::process::{DumpableBehavior, Resource, dumpable_behavior, getrlimit};
    let core = getrlimit(Resource::Core);
    matches!(dumpable_behavior(), Ok(DumpableBehavior::NotDumpable))
        && core.current == Some(0)
        && core.maximum == Some(0)
}

// ---------------------------------------------------------------------------
// Source 1: the controlling terminal
// ---------------------------------------------------------------------------

/// Ask on the controlling terminal with echo off and read one line. `None`
/// when there is no terminal to ask on — which is never stdin: a pipe on
/// stdin is not a terminal, and this never reads stdin.
///
/// Whatever state the terminal was left in, it is put in canonical mode with
/// echo off, and suspend (Ctrl-Z) is disabled for the duration: bash resumes
/// a stopped job with echo back on, so the rest of a secret typed after `fg`
/// would be shown. Interrupt (Ctrl-C) still works.
pub fn read_terminal_line(prompt: &str) -> Option<io::Result<Zeroizing<String>>> {
    use rustix::termios::{LocalModes, OptionalActions, SpecialCodeIndex, tcgetattr, tcsetattr};
    let mut tty = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;
    let _ = write!(tty, "{prompt}");
    let _ = tty.flush();
    let saved = tcgetattr(&tty).ok();
    if let Some(saved) = &saved {
        let mut quiet = saved.clone();
        quiet.local_modes.remove(LocalModes::ECHO);
        quiet.local_modes.insert(LocalModes::ICANON);
        // _POSIX_VDISABLE is 0 on Linux: no key suspends the prompt.
        quiet.special_codes[SpecialCodeIndex::VSUSP] = 0;
        let _ = tcsetattr(&tty, OptionalActions::Flush, &quiet);
    }
    let read = read_secret_line(&mut tty);
    if let Some(saved) = &saved {
        let _ = tcsetattr(&tty, OptionalActions::Flush, saved);
    }
    let _ = writeln!(tty);
    Some(read)
}

/// Read up to the first newline straight into a buffer that is wiped on drop
/// and never grows, so no reallocation or buffered reader leaves a copy
/// behind. Loops until the newline rather than trusting one `read` to be one
/// line. A trailing CR is dropped; end of input ends the line.
pub fn read_secret_line(input: &mut impl Read) -> io::Result<Zeroizing<String>> {
    let mut buffer = Zeroizing::new(vec![0u8; MAX_SECRET_BYTES + 1]);
    let mut len = 0;
    while !buffer[..len].contains(&b'\n') {
        if len == buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the line is longer than any password this device accepts",
            ));
        }
        match input.read(&mut buffer[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    let line = &buffer[..len];
    let line = &line[..line.iter().position(|&b| b == b'\n').unwrap_or(len)];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    Ok(Zeroizing::new(String::from_utf8_lossy(line).into_owned()))
}

// ---------------------------------------------------------------------------
// Source 2: a socket, by descriptor number or by rendezvous with the parent
// ---------------------------------------------------------------------------

/// Take one line — a password — from inherited descriptor `fd`, which must be
/// a socket (`--password-fd N`).
pub fn password_from_fd(fd: i32) -> Result<Password, SourceError> {
    password_from_owned(fd, own_descriptor(fd)?)
}

/// [`password_from_fd`] once the descriptor is owned: refused unless it is a
/// socket, then one bounded line.
fn password_from_owned(fd: i32, owned: OwnedFd) -> Result<Password, SourceError> {
    let mut stream = socket_only(fd, owned)?;
    read_delivered_line(&mut stream)
}

/// Take a ticket from inherited descriptor `fd`, which must be a socket
/// (`--ticket-fd N`): `punar-auth --admin`'s answer as it prints it
/// (`ok <ticket>`) or the bare ticket.
pub fn ticket_from_fd(fd: i32) -> Result<Ticket, SourceError> {
    ticket_from_owned(fd, own_descriptor(fd)?)
}

fn ticket_from_owned(fd: i32, owned: OwnedFd) -> Result<Ticket, SourceError> {
    let mut stream = socket_only(fd, owned)?;
    let line = read_delivered_line(&mut stream)?;
    let text = line.strip_prefix("ok ").unwrap_or(line.as_str());
    Ticket::parse(text).ok_or(SourceError::NotATicket)
}

/// A private copy of inherited descriptor `fd`.
///
/// The copy comes from `pidfd_getfd` on this process's own pidfd, which is
/// how a descriptor number becomes an owned descriptor without `unsafe`. The
/// kernel always lets a process take its own descriptors, Yama included; a
/// seccomp filter can still refuse the call (Docker's default profile does),
/// and that is said as such rather than as an I/O error.
fn own_descriptor(fd: i32) -> Result<OwnedFd, SourceError> {
    use rustix::io::Errno;
    use rustix::process::{PidfdFlags, PidfdGetfdFlags, getpid, pidfd_getfd, pidfd_open};

    if (0..=2).contains(&fd) {
        return Err(SourceError::StandardStream(fd));
    }
    if fd < 0 {
        return Err(SourceError::NotOpen(fd));
    }
    let refused = |errno: Errno| match errno {
        Errno::BADF => SourceError::NotOpen(fd),
        Errno::PERM | Errno::ACCESS | Errno::NOSYS => SourceError::Unsupported(fd),
        other => SourceError::from(other),
    };
    let me = pidfd_open(getpid(), PidfdFlags::empty()).map_err(refused)?;
    pidfd_getfd(&me, fd, PidfdGetfdFlags::empty()).map_err(refused)
}

/// `owned` as a socket stream, or the refusal naming what it is instead.
fn socket_only(fd: i32, owned: OwnedFd) -> Result<UnixStream, SourceError> {
    use rustix::fs::{FileType, fstat};

    let kind = match FileType::from_raw_mode(fstat(&owned)?.st_mode) {
        FileType::Socket => return Ok(UnixStream::from(owned)),
        FileType::Fifo => "a pipe",
        FileType::RegularFile => "a file",
        FileType::CharacterDevice => "a terminal or device",
        FileType::Directory => "a directory",
        _ => "not a socket",
    };
    Err(SourceError::NotASocket { fd, kind })
}

/// One line from a socket, bounded in size and in time. The far end is
/// shut down afterwards, so a peer cannot keep feeding it.
fn read_delivered_line(stream: &mut UnixStream) -> Result<Password, SourceError> {
    stream.set_read_timeout(Some(DELIVERY_TIMEOUT))?;
    let line = read_secret_line(stream).map_err(|error| match error.kind() {
        io::ErrorKind::InvalidData => SourceError::TooLong,
        _ => SourceError::from(error),
    })?;
    let _ = stream.shutdown(std::net::Shutdown::Both);
    if line.is_empty() {
        return Err(SourceError::Empty);
    }
    Ok(line)
}

/// A private rendezvous that exactly one process may answer: the one that
/// started this command (`--password-from-parent`).
///
/// A graphical surface cannot hand a child a socket descriptor — Quickshell's
/// `Process` offers a stdin pipe and nothing else — but it can connect to a
/// socket by path. So the command opens a listening socket in a fresh name
/// inside `$XDG_RUNTIME_DIR/punar-reauth` (`0700`, checked), prints the path,
/// and accepts one connection. The connection is kept only if the kernel says
/// it came from this process's parent, running as this uid; anything else is
/// refused and nothing is read. The name is removed the moment a connection
/// is accepted, and again when this is dropped.
///
/// WHAT THIS DOES NOT STOP, stated rather than implied: another program of
/// the same person that watches the directory can race to replace the socket
/// between the moment its path is printed and the moment the parent connects,
/// and receive what the parent sends. It cannot do so unseen: the name is
/// bound to one inode, and a wait that ends with no connection checks it —
/// a name that is gone or names another socket is reported as
/// [`SourceError::Intercepted`], telling the person to change their password.
/// Closing the race itself needs the prompt to move into a trusted process
/// (docs/api/ipc.md section 23.5).
pub struct ParentHandoff {
    listener: UnixListener,
    path: PathBuf,
    /// `(st_dev, st_ino)` of the socket this process bound at `path`.
    bound: (u64, u64),
}

impl ParentHandoff {
    /// A rendezvous in this user's runtime directory.
    pub fn open() -> Result<ParentHandoff, SourceError> {
        ParentHandoff::open_in(&runtime_dir())
    }

    /// A rendezvous in `dir`, which is created `0700` if it is missing and
    /// must otherwise be a real directory of this uid that nobody else can
    /// enter.
    pub fn open_in(dir: &Path) -> Result<ParentHandoff, SourceError> {
        ensure_private_dir(dir)?;
        let path = dir.join(format!("{}.sock", random_name()?));
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let meta = fs::symlink_metadata(&path)?;
        Ok(ParentHandoff {
            listener,
            path,
            bound: (meta.dev(), meta.ino()),
        })
    }

    /// Where the parent connects.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Wait for the parent (`expected_pid`) and read the one line it sends.
    ///
    /// A connection from anyone else is closed unread and the wait goes on,
    /// so a stranger that connects first cannot use up the rendezvous; if
    /// the parent never arrives, the answer says a stranger tried. The name
    /// is removed the moment the parent's connection is in.
    pub fn receive(self, expected_pid: i32, timeout: Duration) -> Result<Password, SourceError> {
        use rustix::event::{PollFd, PollFlags, Timespec, poll};
        let deadline = std::time::Instant::now() + timeout;
        let mut stranger = false;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(if !self.name_is_still_ours() {
                    SourceError::Intercepted(self.path.clone())
                } else if stranger {
                    SourceError::NotTheParent
                } else {
                    SourceError::Timeout
                });
            }
            let spec = Timespec {
                tv_sec: remaining.as_secs() as _,
                tv_nsec: remaining.subsec_nanos() as _,
            };
            let mut fds = [PollFd::new(&self.listener, PollFlags::IN)];
            match poll(&mut fds, Some(&spec)) {
                Ok(0) => continue,
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(errno) => return Err(SourceError::from(errno)),
            }
            let mut stream = match self.listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(SourceError::Io(error)),
            };
            let peer = rustix::net::sockopt::socket_peercred(stream.as_fd())?;
            if peer.uid != rustix::process::getuid()
                || peer.pid.as_raw_nonzero().get() != expected_pid
            {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                stranger = true;
                continue;
            }
            // The parent is in: nobody else may even try from here on.
            if self.name_is_still_ours() {
                let _ = fs::remove_file(&self.path);
            }
            stream.set_nonblocking(false)?;
            return read_delivered_line(&mut stream);
        }
    }
}

impl ParentHandoff {
    /// Whether `path` still names the socket this process bound.
    fn name_is_still_ours(&self) -> bool {
        fs::symlink_metadata(&self.path).is_ok_and(|meta| {
            meta.file_type().is_socket() && (meta.dev(), meta.ino()) == self.bound
        })
    }
}

impl Drop for ParentHandoff {
    fn drop(&mut self) {
        // Only ever this process's own name: a replacement is evidence, and
        // is left where it is for the person to find.
        if self.name_is_still_ours() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// This process's parent, the only process a [`ParentHandoff`] accepts.
pub fn parent_pid() -> Option<i32> {
    rustix::process::getppid().map(|pid| pid.as_raw_nonzero().get())
}

/// `$XDG_RUNTIME_DIR/punar-reauth` when that is an absolute directory of
/// this uid that nobody else can enter, and `/run/user/<uid>/punar-reauth`
/// otherwise. The environment can choose among this person's own private
/// directories and nothing else: a path somebody else owns, or one others can
/// enter, is ignored, and [`ParentHandoff::open_in`] checks the leaf again.
pub fn runtime_dir() -> PathBuf {
    let uid = rustix::process::getuid().as_raw();
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|dir| {
            dir.is_absolute()
                && fs::symlink_metadata(dir).is_ok_and(|meta| {
                    meta.file_type().is_dir() && meta.uid() == uid && meta.mode() & 0o077 == 0
                })
        })
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{uid}")))
        .join("punar-reauth")
}

fn ensure_private_dir(dir: &Path) -> Result<(), SourceError> {
    match fs::symlink_metadata(dir) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new().mode(0o700).create(dir)?;
        }
        Err(error) => return Err(SourceError::Io(error)),
    }
    let meta = fs::symlink_metadata(dir)?;
    if !meta.file_type().is_dir()
        || meta.uid() != rustix::process::getuid().as_raw()
        || meta.mode() & 0o077 != 0
    {
        return Err(SourceError::UnsafeDirectory(dir.to_path_buf()));
    }
    Ok(())
}

fn random_name() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

// ---------------------------------------------------------------------------
// punar-authd
// ---------------------------------------------------------------------------

/// What `punar-authd` said.
#[derive(Debug)]
pub enum Verdict {
    /// The password was accepted and this ticket was minted for the caller.
    Ticket(Ticket),
    /// The password was refused — a wrong one, or a paused account. Never
    /// "wrong password": faillock refuses the right one too while it pauses.
    Denied,
    /// The device could not ask. Never a statement about the password.
    Unavailable,
}

/// Exchange a password for a ticket at the device's `punar-authd`.
pub fn request_ticket(password: &str) -> Verdict {
    request_ticket_at(Path::new(AUTHD_SOCKET), password)
}

/// [`request_ticket`] against a named socket (tests).
///
/// The request body is serialized straight into a wiped buffer sized so it
/// never reallocates (JSON escaping at most sextuples a byte), and the
/// account is whatever `SO_PEERCRED` says this process is: the request has
/// no username field to fill.
pub fn request_ticket_at(socket: &Path, password: &str) -> Verdict {
    #[derive(Serialize)]
    struct Request<'a> {
        v: u32,
        password: &'a str,
        purpose: &'static str,
    }
    if password.is_empty() || password.len() > MAX_SECRET_BYTES {
        return Verdict::Unavailable;
    }
    let mut body = Zeroizing::new(Vec::with_capacity(password.len() * 6 + 64));
    if serde_json::to_writer(
        &mut *body,
        &Request {
            v: PROTOCOL_VERSION,
            password,
            purpose: "admin",
        },
    )
    .is_err()
    {
        return Verdict::Unavailable;
    }
    exchange(socket, &body).unwrap_or(Verdict::Unavailable)
}

fn exchange(socket: &Path, body: &[u8]) -> Option<Verdict> {
    #[derive(serde::Deserialize)]
    struct Response {
        verdict: String,
        #[serde(default)]
        ticket: Option<String>,
    }
    let mut stream = UnixStream::connect(socket).ok()?;
    // Generous, because the far side runs a real PAM stack whose modules may
    // deliberately delay a failure.
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let len = u32::try_from(body.len()).ok()?;
    stream.write_all(&len.to_le_bytes()).ok()?;
    stream.write_all(body).ok()?;
    stream.flush().ok()?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).ok()?;
    let len = u32::from_le_bytes(header) as usize;
    if len == 0 || len > MAX_RESPONSE_BYTES {
        return None;
    }
    let mut response = Zeroizing::new(vec![0u8; len]);
    stream.read_exact(&mut response).ok()?;
    let parsed: Response = serde_json::from_slice(&response).ok()?;
    // Mapped through a closed set: whatever the far side says, the answer is
    // one of three, and a ticket is only ever one punard could spend.
    match parsed.verdict.as_str() {
        "ok" => {
            let ticket = Zeroizing::new(parsed.ticket?);
            Ticket::parse(&ticket).map(Verdict::Ticket)
        }
        "denied" => Some(Verdict::Denied),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SEQ: AtomicU32 = AtomicU32::new(0);

    const TICKET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn scratch(tag: &str) -> PathBuf {
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("punar-reauth-{tag}-{}-{seq}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        dir
    }

    /// The property the whole library rests on (F-REAUTH): a pipe can be
    /// reopened through /proc by any process of the same uid, a socket
    /// cannot.
    #[test]
    fn a_pipe_reopens_through_proc_and_a_socket_does_not() {
        let (reader, _writer) = std::io::pipe().unwrap();
        let pipe = format!("/proc/self/fd/{}", reader.as_raw_fd());
        assert!(
            fs::File::open(&pipe).is_ok(),
            "a pipe reopens through {pipe}"
        );
        let (one, _two) = UnixStream::pair().unwrap();
        let socket = format!("/proc/self/fd/{}", one.as_raw_fd());
        let error = fs::File::open(&socket).expect_err("a socket must not reopen");
        assert_eq!(error.raw_os_error(), Some(6), "ENXIO, not {error}");
    }

    /// Whether this process may take over its own descriptors. A seccomp
    /// filter can forbid `pidfd_getfd` — Docker's default profile does, for
    /// any process without CAP_SYS_PTRACE — and then only that one step is
    /// untestable here; it is refused in words ([`SourceError::Unsupported`]),
    /// and the kernel's own verdict is asserted so a skip can never hide
    /// anything else.
    fn descriptors_can_be_taken() -> bool {
        let (probe, _peer) = UnixStream::pair().unwrap();
        match own_descriptor(probe.as_raw_fd()) {
            Ok(_) => true,
            Err(SourceError::Unsupported(_)) => {
                let status = fs::read_to_string("/proc/self/status").unwrap();
                assert!(
                    status
                        .lines()
                        .any(|l| l.starts_with("Seccomp:") && !l.ends_with('0')),
                    "pidfd_getfd is refused with no seccomp filter in place: {status}"
                );
                eprintln!(
                    "note: a seccomp filter refuses pidfd_getfd here; that one step is skipped"
                );
                false
            }
            Err(other) => panic!("taking a descriptor failed: {other:?}"),
        }
    }

    #[test]
    fn a_socket_is_accepted_and_the_line_is_the_password() {
        let (mine, mut theirs) = UnixStream::pair().unwrap();
        theirs.write_all(b"three amber rivers\nleftover").unwrap();
        let password = password_from_owned(3, OwnedFd::from(mine)).unwrap();
        assert_eq!(password.as_str(), "three amber rivers");

        if descriptors_can_be_taken() {
            let (mine, mut theirs) = UnixStream::pair().unwrap();
            theirs.write_all(b"seven copper lanterns\n").unwrap();
            let password = password_from_fd(mine.as_raw_fd()).unwrap();
            assert_eq!(password.as_str(), "seven copper lanterns");
        }
    }

    #[test]
    fn a_pipe_a_file_and_the_standard_streams_are_refused() {
        let (reader, mut writer) = std::io::pipe().unwrap();
        writer.write_all(b"secret\n").unwrap();
        match password_from_owned(3, OwnedFd::from(reader)) {
            Err(SourceError::NotASocket { kind, .. }) => assert_eq!(kind, "a pipe"),
            other => panic!("a pipe was not refused: {other:?}"),
        }
        let dir = scratch("file");
        let path = dir.join("password.txt");
        fs::write(&path, "secret\n").unwrap();
        match password_from_owned(3, OwnedFd::from(fs::File::open(&path).unwrap())) {
            Err(SourceError::NotASocket { kind, .. }) => assert_eq!(kind, "a file"),
            other => panic!("a file was not refused: {other:?}"),
        }
        // Standard streams and negative numbers are refused before any
        // system call; so is a number nothing is open on.
        for fd in 0..=2 {
            assert!(matches!(
                password_from_fd(fd),
                Err(SourceError::StandardStream(n)) if n == fd
            ));
            assert!(matches!(
                ticket_from_fd(fd),
                Err(SourceError::StandardStream(n)) if n == fd
            ));
        }
        assert!(matches!(
            password_from_fd(-1),
            Err(SourceError::NotOpen(-1))
        ));
        if descriptors_can_be_taken() {
            let (reader, _writer) = std::io::pipe().unwrap();
            match password_from_fd(reader.as_raw_fd()) {
                Err(SourceError::NotASocket { kind, .. }) => assert_eq!(kind, "a pipe"),
                other => panic!("a pipe was not refused: {other:?}"),
            }
            assert!(matches!(
                password_from_fd(9_999),
                Err(SourceError::NotOpen(9_999))
            ));
        }
        let refusal = SourceError::NotASocket {
            fd: 3,
            kind: "a pipe",
        }
        .to_string();
        assert!(refusal.contains("/proc"), "{refusal}");
        assert!(SourceError::Unsupported(3).to_string().contains("terminal"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn an_empty_or_overlong_delivery_is_refused() {
        let (mine, theirs) = UnixStream::pair().unwrap();
        drop(theirs);
        assert!(matches!(
            password_from_owned(3, OwnedFd::from(mine)),
            Err(SourceError::Empty)
        ));
        let (mine, mut theirs) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            let _ = theirs.write_all(&vec![b'a'; MAX_SECRET_BYTES + 10]);
        });
        assert!(matches!(
            password_from_owned(3, OwnedFd::from(mine)),
            Err(SourceError::TooLong)
        ));
        writer.join().unwrap();
    }

    #[test]
    fn a_ticket_descriptor_takes_the_relays_answer_or_the_bare_ticket() {
        for line in [format!("ok {TICKET}\n"), format!("{TICKET}\n")] {
            let (mine, mut theirs) = UnixStream::pair().unwrap();
            theirs.write_all(line.as_bytes()).unwrap();
            assert_eq!(
                ticket_from_owned(3, OwnedFd::from(mine)).unwrap().as_str(),
                TICKET
            );
        }
        for line in [
            "denied\n",
            "unavailable\n",
            "ok short\n",
            &TICKET.to_uppercase(),
        ] {
            let (mine, mut theirs) = UnixStream::pair().unwrap();
            theirs.write_all(line.as_bytes()).unwrap();
            theirs.write_all(b"\n").unwrap();
            assert!(
                matches!(
                    ticket_from_owned(3, OwnedFd::from(mine)),
                    Err(SourceError::NotATicket)
                ),
                "{line:?}"
            );
        }
        assert_eq!(
            format!("{:?}", Ticket::parse(TICKET).unwrap()),
            "Ticket([redacted])"
        );
    }

    /// The rendezvous takes the password from the process it names, and
    /// from nobody else. In a test the connecting thread's process is this
    /// one, so "the parent" is this pid.
    #[test]
    fn the_rendezvous_answers_only_the_parent_and_leaves_no_name_behind() {
        let dir = scratch("rendezvous").join("punar-reauth");
        let me = std::process::id() as i32;

        let handoff = ParentHandoff::open_in(&dir).unwrap();
        let path = handoff.path().to_path_buf();
        assert_eq!(
            fs::metadata(&dir).unwrap().mode() & 0o777,
            0o700,
            "the directory is private"
        );
        let sender = {
            let path = path.clone();
            std::thread::spawn(move || {
                let mut stream = UnixStream::connect(path).unwrap();
                stream.write_all(b"seven copper lanterns\n").unwrap();
            })
        };
        let password = handoff.receive(me, Duration::from_secs(10)).unwrap();
        sender.join().unwrap();
        assert_eq!(password.as_str(), "seven copper lanterns");
        assert!(!path.exists(), "the name is gone once it has been used");

        // Anyone but the parent is refused, and nothing is read.
        let handoff = ParentHandoff::open_in(&dir).unwrap();
        let path = handoff.path().to_path_buf();
        let sender = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(path).unwrap();
            let _ = stream.write_all(b"not yours\n");
        });
        assert!(matches!(
            handoff.receive(me + 1, Duration::from_millis(500)),
            Err(SourceError::NotTheParent)
        ));
        sender.join().unwrap();

        // A stranger that connects first does not use the rendezvous up: it
        // is closed unread, and the parent that follows is still heard. The
        // stranger is another process (this test binary, re-run as the
        // helper below), so the kernel reports a pid that is not ours.
        let handoff = ParentHandoff::open_in(&dir).unwrap();
        let path = handoff.path().to_path_buf();
        let stranger = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::rendezvous_stranger_helper",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(STRANGER_ENV, &path)
            .status()
            .unwrap();
        assert!(stranger.success());
        let sender = {
            let path = path.clone();
            std::thread::spawn(move || {
                let mut stream = UnixStream::connect(path).unwrap();
                stream.write_all(b"three amber rivers\n").unwrap();
            })
        };
        let password = handoff.receive(me, Duration::from_secs(10)).unwrap();
        sender.join().unwrap();
        assert_eq!(
            password.as_str(),
            "three amber rivers",
            "the parent's line is read, and the stranger's never is"
        );

        // A name another program replaced is reported as an interception,
        // and the replacement is left for the person to find.
        let handoff = ParentHandoff::open_in(&dir).unwrap();
        let path = handoff.path().to_path_buf();
        fs::remove_file(&path).unwrap();
        let _impostor = UnixListener::bind(&path).unwrap();
        assert!(matches!(
            handoff.receive(me, Duration::from_millis(100)),
            Err(SourceError::Intercepted(_))
        ));
        assert!(
            path.exists(),
            "the impostor's socket is evidence, not cleaned up"
        );
        fs::remove_file(&path).unwrap();

        // Nobody at all: a bounded wait, then the name is removed.
        let handoff = ParentHandoff::open_in(&dir).unwrap();
        let path = handoff.path().to_path_buf();
        assert!(matches!(
            handoff.receive(me, Duration::from_millis(50)),
            Err(SourceError::Timeout)
        ));
        assert!(!path.exists());
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    /// Where the stranger helper connects, when it is run as one.
    const STRANGER_ENV: &str = "PUNAR_REAUTH_TEST_STRANGER";

    /// Not a test on its own: re-run by
    /// `the_rendezvous_answers_only_the_parent_and_leaves_no_name_behind` as
    /// a separate process, it connects to the rendezvous and offers a line
    /// that must never be read. Without the variable it does nothing.
    #[test]
    fn rendezvous_stranger_helper() {
        if let Some(path) = std::env::var_os(STRANGER_ENV) {
            let mut stream = UnixStream::connect(path).unwrap();
            let _ = stream.write_all(b"from a stranger\n");
        }
    }

    #[test]
    fn a_rendezvous_directory_others_can_enter_is_refused() {
        let dir = scratch("open-dir").join("punar-reauth");
        fs::DirBuilder::new().mode(0o755).create(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            ParentHandoff::open_in(&dir),
            Err(SourceError::UnsafeDirectory(_))
        ));
        let link = dir.parent().unwrap().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(matches!(
            ParentHandoff::open_in(&link),
            Err(SourceError::UnsafeDirectory(_))
        ));
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    /// A fake punar-authd that checks the request bytes and answers `reply`.
    fn fake_authd(dir: &Path, reply: &'static str) -> (PathBuf, std::thread::JoinHandle<String>) {
        let path = dir.join("auth.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut header = [0u8; 4];
            stream.read_exact(&mut header).unwrap();
            let mut body = vec![0u8; u32::from_le_bytes(header) as usize];
            stream.read_exact(&mut body).unwrap();
            let reply = reply.as_bytes();
            stream
                .write_all(&(reply.len() as u32).to_le_bytes())
                .unwrap();
            stream.write_all(reply).unwrap();
            String::from_utf8(body).unwrap()
        });
        (path, handle)
    }

    #[test]
    fn a_password_becomes_a_ticket_at_punar_authd_and_nothing_else_does() {
        let dir = scratch("authd");
        let reply: &'static str = r#"{"v":1,"verdict":"ok","ticket":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#;
        let (socket, authd) = fake_authd(&dir, reply);
        match request_ticket_at(&socket, "three \"amber\" rivers") {
            Verdict::Ticket(ticket) => assert_eq!(ticket.as_str(), TICKET),
            other => panic!("{other:?}"),
        }
        let sent: serde_json::Value = serde_json::from_str(&authd.join().unwrap()).unwrap();
        assert_eq!(
            sent,
            serde_json::json!({"v": 1, "password": "three \"amber\" rivers", "purpose": "admin"}),
            "no username, ever: the account is SO_PEERCRED's"
        );
        fs::remove_file(&socket).unwrap();

        let (socket, authd) = fake_authd(&dir, r#"{"v":1,"verdict":"denied"}"#);
        assert!(matches!(request_ticket_at(&socket, "x"), Verdict::Denied));
        authd.join().unwrap();
        fs::remove_file(&socket).unwrap();

        // An "ok" without a spendable ticket is the device failing to
        // answer, never a success.
        let (socket, authd) = fake_authd(&dir, r#"{"v":1,"verdict":"ok","ticket":"ABC"}"#);
        assert!(matches!(
            request_ticket_at(&socket, "x"),
            Verdict::Unavailable
        ));
        authd.join().unwrap();
        fs::remove_file(&socket).unwrap();

        assert!(matches!(
            request_ticket_at(&dir.join("absent.sock"), "x"),
            Verdict::Unavailable
        ));
        assert!(matches!(
            request_ticket_at(&socket, ""),
            Verdict::Unavailable
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn the_wire_contract_is_punar_auths() {
        let relay = include_str!("../../punar-auth/src/bin/punar-auth.rs");
        assert!(relay.contains(&format!("const SOCKET: &str = \"{AUTHD_SOCKET}\";")));
        let protocol = include_str!("../../punar-auth/src/protocol.rs");
        assert!(protocol.contains(&format!(
            "pub const PROTOCOL_VERSION: u32 = {PROTOCOL_VERSION};"
        )));
        assert!(protocol.contains(&format!(
            "pub const MAX_REQUEST_BYTES: usize = {MAX_SECRET_BYTES};"
        )));
        assert!(protocol.contains(&format!(
            "pub const MAX_RESPONSE_BYTES: usize = {MAX_RESPONSE_BYTES};"
        )));
    }

    /// Hardening is one-way and observable, and it takes /proc/<pid>/fd away
    /// from other processes of this uid (the kernel check is the ptrace
    /// access check; its effect on another process is what F-REAUTH proves
    /// in the VM).
    #[test]
    fn harden_makes_this_process_non_dumpable_with_no_core() {
        harden().unwrap();
        assert!(is_hardened());
        let status = fs::read_to_string("/proc/self/status").unwrap();
        assert!(
            status.contains("Name:"),
            "the process still reads its own /proc"
        );
    }
}
