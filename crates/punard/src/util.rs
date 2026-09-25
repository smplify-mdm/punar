//! Small std-only helpers: atomic writes, bounded subprocess execution,
//! passwd/group lookups, and random identifiers.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Atomically write `bytes` to `path` with `mode`: temp file in the same
/// directory, then `rename(2)`. No fsync — crash-loss of the last write is an
/// accepted M3 tradeoff (docs/development/milestone-3.md section 5).
///
/// The temp file is opened with `O_CREAT|O_EXCL` (`create_new`), never
/// `O_CREAT`-follow: since M5 this helper also writes the section 9 status
/// file into `/run/punar`, a directory owned by the unprivileged session
/// root (tmpfiles.d: `0755 root:root`), where a predictable tmp name
/// opened without `O_EXCL` would let that user plant a symlink and have
/// root truncate an arbitrary file (spec section 61). A pre-existing tmp
/// (stale crash leftover or a planted link) is unlinked and the exclusive
/// create retried once; a second collision fails loudly rather than follow.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = parent.join(format!(".{file_name}.punard-tmp.{}", std::process::id()));
    let open_excl = || {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
    };
    {
        let mut f = match open_excl() {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // remove_file unlinks a symlink itself, not its target.
                fs::remove_file(&tmp)?;
                open_excl()?
            }
            Err(e) => return Err(e),
        };
        f.write_all(bytes)?;
        f.flush()?;
    }
    match fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// [`write_atomic`], plus `fsync` of the file **and** of the parent
/// directory before the rename is considered done.
///
/// Milestone 9 uses this for approvals and privilege grants, where the M3
/// tradeoff does not hold. The M3 stores are desired state: losing the last
/// write means re-observing and re-applying. A grant is different — it is a
/// *live authorization*, and the dangerous direction is asymmetric. Losing
/// the creation of an approval is harmless (nothing executes); losing the
/// **revocation** of a grant would resurrect privilege the user handed back,
/// which is a fail-open. Two `fsync`s per human-paced action is a price
/// worth paying for that, and the write volume is unchanged
/// (PERFORMANCE_BUDGETS.md section 6.4: these writes are user-paced, not
/// periodic).
pub fn write_atomic_synced(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = parent.join(format!(".{file_name}.punard-tmp.{}", std::process::id()));
    let open_excl = || {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
    };
    {
        let mut f = match open_excl() {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                fs::remove_file(&tmp)?;
                open_excl()?
            }
            Err(e) => return Err(e),
        };
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    match fs::rename(&tmp, path) {
        Ok(()) => {
            // Directory fsync: without it the rename itself can be lost.
            // Best-effort — a filesystem that refuses to open a directory
            // read-only must not fail an otherwise-completed write.
            if let Ok(dir) = File::open(&parent) {
                let _ = dir.sync_all();
            }
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// [`write_atomic_synced`] for a file root owns and exactly one other uid,
/// `reader`, may read: created `0600`, given the POSIX access ACL
/// `user::rw-, user:<reader>:r--, group::---, mask::r--, other::---` before it
/// is renamed into place, so there is no moment at which the name points at
/// a file anyone else can read (F0 review: the per-person approval views).
///
/// Not a group: a person's primary group is not guaranteed to be theirs
/// alone. Not the person as owner: an owner can chmod and rewrite a file, and
/// the files this writes are what a person reads before they consent. A
/// filesystem without POSIX ACLs refuses, and the error is returned with
/// nothing renamed into place: the reader then sees no view — closed, not
/// open.
pub fn write_atomic_synced_for_reader(path: &Path, bytes: &[u8], reader: u32) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = parent.join(format!(".{file_name}.punard-tmp.{}", std::process::id()));
    let open_excl = || {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
    };
    let written = (|| {
        let mut f = match open_excl() {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                fs::remove_file(&tmp)?;
                open_excl()?
            }
            Err(e) => return Err(e),
        };
        f.write_all(bytes)?;
        grant_read_to_one_uid(&f, reader)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    match written {
        Ok(()) => {
            if let Ok(dir) = File::open(&parent) {
                let _ = dir.sync_all();
            }
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// The name of the POSIX access ACL extended attribute.
const POSIX_ACL_ACCESS: &str = "system.posix_acl_access";

/// The access ACL that lets root read and write `file` and exactly one other
/// uid, `reader`, read it — nobody else (see
/// [`write_atomic_synced_for_reader`]). The kernel's xattr form
/// (`linux/posix_acl_xattr.h`): a little-endian version 2 header, then
/// `(tag: u16, perm: u16, id: u32)` entries in tag order.
pub fn one_reader_acl(reader: u32) -> Vec<u8> {
    const VERSION: u32 = 2;
    const UNDEFINED_ID: u32 = u32::MAX;
    const USER_OBJ: u16 = 0x01;
    const USER: u16 = 0x02;
    const GROUP_OBJ: u16 = 0x04;
    const MASK: u16 = 0x10;
    const OTHER: u16 = 0x20;
    const READ: u16 = 4;
    const WRITE: u16 = 2;
    let mut blob = VERSION.to_le_bytes().to_vec();
    for (tag, perm, id) in [
        (USER_OBJ, READ | WRITE, UNDEFINED_ID),
        (USER, READ, reader),
        (GROUP_OBJ, 0, UNDEFINED_ID),
        (MASK, READ, UNDEFINED_ID),
        (OTHER, 0, UNDEFINED_ID),
    ] {
        blob.extend_from_slice(&tag.to_le_bytes());
        blob.extend_from_slice(&perm.to_le_bytes());
        blob.extend_from_slice(&id.to_le_bytes());
    }
    blob
}

/// Set [`one_reader_acl`] on `file`.
pub fn grant_read_to_one_uid(file: &File, reader: u32) -> io::Result<()> {
    rustix::fs::fsetxattr(
        file,
        POSIX_ACL_ACCESS,
        &one_reader_acl(reader),
        rustix::fs::XattrFlags::empty(),
    )
    .map_err(io::Error::from)
}

/// Remove `path` and `fsync` the parent directory, so an unlink that means
/// "this authorization is over" survives a crash (see
/// [`write_atomic_synced`]). A missing file is success.
pub fn remove_synced(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// `ETXTBSY` from `execve`: the target was still open for writing somewhere
/// (a just-published fixture in a multithreaded test binary, or a package
/// update racing a launch). It is transient by definition, so a bounded
/// retry is the correct response; anything else is returned unchanged.
const EXECUTABLE_FILE_BUSY_ERRNO: i32 = 26;
const SPAWN_BUSY_ATTEMPTS: usize = 8;
const SPAWN_BUSY_BACKOFF: Duration = Duration::from_millis(10);

pub trait SpawnBusyRetry {
    /// [`Command::spawn`] with a bounded retry on `ETXTBSY` only.
    fn spawn_busy_retry(&mut self) -> io::Result<std::process::Child>;
}

impl SpawnBusyRetry for Command {
    fn spawn_busy_retry(&mut self) -> io::Result<std::process::Child> {
        for attempt in 0..SPAWN_BUSY_ATTEMPTS {
            match self.spawn() {
                Ok(child) => return Ok(child),
                Err(error)
                    if error.raw_os_error() == Some(EXECUTABLE_FILE_BUSY_ERRNO)
                        && attempt + 1 < SPAWN_BUSY_ATTEMPTS =>
                {
                    std::thread::sleep(SPAWN_BUSY_BACKOFF);
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("the bounded spawn loop always returns on its final attempt")
    }
}

/// Outcome of a bounded subprocess run.
#[derive(Debug)]
pub struct CommandResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Each stream of a [`run_with_timeout`] child is kept up to this many bytes.
/// No caller expects anything near it; past it the output is not one a caller
/// can use whole, and holding more would let a runaway child grow punard.
pub const MAX_COMMAND_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// How long a child's pipes may stay open after it exited, for a reader that
/// has not handed its bytes over yet, when the deadline has already passed.
const OUTPUT_GRACE: Duration = Duration::from_millis(200);

/// Run `bin` with a **fixed argv** (never a shell — SPEC section 10) and a
/// wall-clock deadline; on expiry the child is killed and an error returned.
/// Output is capped at [`MAX_COMMAND_OUTPUT_BYTES`] per stream
/// ([`run_bounded`]).
pub fn run_with_timeout(bin: &Path, args: &[&str], timeout: Duration) -> io::Result<CommandResult> {
    run_bounded(bin, args, timeout, MAX_COMMAND_OUTPUT_BYTES)
}

/// [`run_with_timeout`] with the caller's own cap on each stream.
///
/// Both pipes are drained WHILE the child runs, each by its own thread. A
/// pipe holds 64 KiB on Linux, and a child that fills one blocks on its next
/// write until someone reads: reading only after exit turned any output past
/// that into a hang, killed at the deadline and reported as a timeout.
///
/// Past `max_output_bytes` on either stream the child is killed and the run
/// fails with [`io::ErrorKind::FileTooLarge`] — never a timeout, and never a
/// truncated `stdout` a caller would parse as if it were whole.
pub fn run_bounded(
    bin: &Path,
    args: &[&str],
    timeout: Duration,
    max_output_bytes: usize,
) -> io::Result<CommandResult> {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn_busy_retry()?;
    let start = Instant::now();
    let deadline = start + timeout;
    let overflow = Arc::new(AtomicBool::new(false));
    let (sender, received) = mpsc::channel();
    if let Some(stdout) = child.stdout.take() {
        drain_in_background(stdout, Stream::Out, max_output_bytes, &overflow, &sender);
    }
    if let Some(stderr) = child.stderr.take() {
        drain_in_background(stderr, Stream::Err, max_output_bytes, &overflow, &sender);
    }
    drop(sender);

    let too_large = || {
        io::Error::new(
            io::ErrorKind::FileTooLarge,
            format!("{} wrote more than {max_output_bytes} bytes", bin.display()),
        )
    };
    let timed_out = || {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("{} timed out after {timeout:?}", bin.display()),
        )
    };
    let status = loop {
        if overflow.load(Ordering::SeqCst) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(too_large());
        }
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(timed_out());
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    // The pipes close when the child exits, unless something it started
    // still holds them; that waits no longer than the deadline allows. A
    // reader left behind ends when the last holder exits.
    let (mut stdout, mut stderr) = (None, None);
    while stdout.is_none() || stderr.is_none() {
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .max(OUTPUT_GRACE);
        match received.recv_timeout(wait) {
            Ok((Stream::Out, bytes)) => stdout = Some(bytes),
            Ok((Stream::Err, bytes)) => stderr = Some(bytes),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => return Err(timed_out()),
        }
    }
    if overflow.load(Ordering::SeqCst) {
        return Err(too_large());
    }
    let text =
        |bytes: Option<Vec<u8>>| String::from_utf8_lossy(&bytes.unwrap_or_default()).into_owned();
    Ok(CommandResult {
        success: status.success(),
        stdout: text(stdout),
        stderr: text(stderr),
    })
}

#[derive(Clone, Copy)]
enum Stream {
    Out,
    Err,
}

/// Read `pipe` to its end on a thread of its own, keeping at most `cap`
/// bytes. Past the cap it flags `overflow` and goes on reading, discarding,
/// so the child is never left blocked on a full pipe while it is stopped.
fn drain_in_background(
    mut pipe: impl Read + Send + 'static,
    stream: Stream,
    cap: usize,
    overflow: &Arc<AtomicBool>,
    sender: &mpsc::Sender<(Stream, Vec<u8>)>,
) {
    let overflow = Arc::clone(overflow);
    let sender = sender.clone();
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) if kept.len() + read <= cap => kept.extend_from_slice(&chunk[..read]),
                Ok(_) => overflow.store(true, Ordering::SeqCst),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        let _ = sender.send((stream, kept));
    });
}

/// Look up a group's gid by name in an `/etc/group`-format file.
pub fn lookup_gid(group_file: &Path, name: &str) -> Option<u32> {
    let content = fs::read_to_string(group_file).ok()?;
    for line in content.lines() {
        let mut fields = line.split(':');
        if fields.next() == Some(name) {
            let _passwd = fields.next();
            return fields.next()?.parse().ok();
        }
    }
    None
}

/// Look up a username by uid in an `/etc/passwd`-format file.
pub fn lookup_username(passwd_file: &Path, uid: u32) -> Option<String> {
    let content = fs::read_to_string(passwd_file).ok()?;
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 && fields[2].parse() == Ok(uid) {
            return Some(fields[0].to_string());
        }
    }
    None
}

/// `n_bytes` random bytes from `/dev/urandom`, hex-encoded (no bias — a
/// straight byte-to-hex mapping, suitable for the M5 enrollment bootstrap
/// secret; docs/development/milestone-5.md section 5.1).
pub fn random_hex(n_bytes: usize) -> io::Result<String> {
    let mut bytes = vec![0u8; n_bytes];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex(&bytes))
}

/// Lowercase hex encoding.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// SHA-256 (FIPS 180-4), std-only — used for the M5 inventory hash gate
/// (docs/development/milestone-5.md section 6). A content fingerprint for
/// change detection, not an authentication primitive; implementing the
/// public algorithm here keeps the dependency tree unchanged
/// (PERFORMANCE_BUDGETS.md section 6.2).
pub fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut message = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in message.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut digest = Vec::with_capacity(32);
    for word in h {
        digest.extend_from_slice(&word.to_be_bytes());
    }
    hex(&digest)
}

/// `len` random ASCII alphanumerics from `/dev/urandom`. The tiny modulo
/// bias is irrelevant for identifiers (not keys or secrets).
pub fn random_alnum(len: usize) -> io::Result<String> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut bytes = vec![0u8; len];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes
        .iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("punard-util-{tag}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn write_atomic_replaces_content() {
        let dir = tmp_dir("atomic");
        let path = dir.join("f");
        write_atomic(&path, b"one\n", 0o600).unwrap();
        write_atomic(&path, b"two\n", 0o600).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "two\n");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Spec section 61: a symlink planted at the predictable tmp path must
    /// never be followed — the exclusive create unlinks the link itself and
    /// writes a fresh file; the link's target is untouched.
    #[test]
    fn write_atomic_never_follows_a_planted_tmp_symlink() {
        let dir = tmp_dir("symlink");
        let victim = dir.join("victim");
        fs::write(&victim, b"untouched\n").unwrap();
        let path = dir.join("f");
        let planted = dir.join(format!(".f.punard-tmp.{}", std::process::id()));
        std::os::unix::fs::symlink(&victim, &planted).unwrap();

        write_atomic(&path, b"payload\n", 0o600).unwrap();
        assert_eq!(
            fs::read_to_string(&victim).unwrap(),
            "untouched\n",
            "the symlink target must never receive the write"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "payload\n");
        assert!(!planted.exists(), "the planted link is gone, not followed");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn group_and_passwd_lookup_parse_the_format() {
        let dir = tmp_dir("nss");
        let group = dir.join("group");
        fs::write(&group, "root:x:0:\npunar:x:1000:alice\n").unwrap();
        assert_eq!(lookup_gid(&group, "punar"), Some(1000));
        assert_eq!(lookup_gid(&group, "absent"), None);

        let passwd = dir.join("passwd");
        fs::write(
            &passwd,
            "root:x:0:0::/root:/bin/bash\npunar:x:1000:1000::/home/punar:/bin/bash\n",
        )
        .unwrap();
        assert_eq!(lookup_username(&passwd, 0).as_deref(), Some("root"));
        assert_eq!(lookup_username(&passwd, 4242), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sha256_matches_the_fips_test_vectors() {
        // FIPS 180-4 / NIST CAVP vectors.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn random_hex_is_lowercase_hex_of_twice_the_byte_length() {
        let s = random_hex(32).unwrap();
        assert_eq!(s.len(), 64);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
    }

    #[test]
    fn random_alnum_is_alnum_of_requested_length() {
        let s = random_alnum(10).unwrap();
        assert_eq!(s.len(), 10);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn run_with_timeout_kills_slow_children() {
        let err = run_with_timeout(Path::new("/bin/sleep"), &["5"], Duration::from_millis(100))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn run_with_timeout_captures_output() {
        let res =
            run_with_timeout(Path::new("/bin/echo"), &["hi"], Duration::from_secs(5)).unwrap();
        assert!(res.success);
        assert_eq!(res.stdout.trim(), "hi");
    }

    /// More output than a pipe holds, on both streams at once: read only
    /// after exit, the child blocks on its write and is killed as "hung".
    #[test]
    fn run_with_timeout_drains_output_larger_than_a_pipe() {
        let started = Instant::now();
        let res = run_with_timeout(
            Path::new("/bin/sh"),
            &[
                "-c",
                "head -c 300000 /dev/zero | tr '\\0' o; head -c 200000 /dev/zero | tr '\\0' e >&2",
            ],
            Duration::from_secs(10),
        )
        .unwrap();
        assert!(res.success);
        assert_eq!(res.stdout.len(), 300_000);
        assert!(res.stdout.bytes().all(|b| b == b'o'));
        assert_eq!(res.stderr.len(), 200_000);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// Past the cap the run fails as too large, promptly — not as a
    /// timeout, and never with a shortened stdout.
    #[test]
    fn output_past_the_cap_is_too_large_never_truncated() {
        let started = Instant::now();
        let error = run_bounded(
            Path::new("/bin/sh"),
            &["-c", "while :; do echo row; done"],
            Duration::from_secs(20),
            64 * 1024,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::FileTooLarge);
        assert!(started.elapsed() < Duration::from_secs(5));
        // Exactly at the cap is whole output.
        let res = run_bounded(
            Path::new("/bin/sh"),
            &["-c", "head -c 65536 /dev/zero"],
            Duration::from_secs(10),
            64 * 1024,
        )
        .unwrap();
        assert_eq!(res.stdout.len(), 65_536);
    }

    /// F0 review: a per-person view is readable by root and by the one uid it
    /// is for, through an ACL set before the name exists — never by a group,
    /// never by the person as owner. The kernel is the judge: it refuses a
    /// malformed ACL, and it reports back exactly the entries set.
    #[test]
    fn a_view_is_written_readable_by_one_uid_alone() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("punard-acl-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("1234.json");
        match write_atomic_synced_for_reader(&path, b"{}", 1234) {
            Ok(()) => {}
            // A filesystem without POSIX ACLs refuses, and nothing is left
            // behind to read.
            Err(e) if e.raw_os_error() == Some(95) => {
                eprintln!("note: this filesystem has no POSIX ACLs; the ACL leg is skipped");
                assert!(!path.exists());
                assert_eq!(fs::read_dir(&dir).unwrap().count(), 0, "no temp file left");
                let _ = fs::remove_dir_all(&dir);
                return;
            }
            Err(e) => panic!("{e}"),
        }
        assert_eq!(fs::read(&path).unwrap(), b"{}");
        let file = File::open(&path).unwrap();
        let mut buf = [0u8; 256];
        let len = rustix::fs::fgetxattr(&file, POSIX_ACL_ACCESS, &mut buf).unwrap();
        let acl = &buf[..len];
        assert_eq!(
            acl,
            one_reader_acl(1234),
            "the kernel kept exactly this ACL"
        );
        // With an ACL the group bits show the mask: r for the named reader,
        // and nothing for the owning group or anyone else.
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "{mode:o}");
        // The blob names exactly one other uid.
        let named: Vec<u32> = acl[4..]
            .chunks(8)
            .filter(|entry| u16::from_le_bytes([entry[0], entry[1]]) == 0x02)
            .map(|entry| u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]))
            .collect();
        assert_eq!(named, [1234]);
        let _ = fs::remove_dir_all(&dir);
    }
}
