//! Small std-only helpers: atomic writes, bounded subprocess execution,
//! passwd/group lookups, and random identifiers.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Atomically write `bytes` to `path` with `mode`: temp file in the same
/// directory, then `rename(2)`. No fsync — crash-loss of the last write is an
/// accepted M3 tradeoff (docs/development/milestone-3.md section 5).
///
/// The temp file is opened with `O_CREAT|O_EXCL` (`create_new`), never
/// `O_CREAT`-follow: since M5 this helper also writes the section 9 status
/// file into `/run/punar`, a directory owned by the unprivileged session
/// user (tmpfiles.d: `0755 punar:punar`), where a predictable tmp name
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

/// Outcome of a bounded subprocess run.
#[derive(Debug)]
pub struct CommandResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Run `bin` with a **fixed argv** (never a shell — SPEC section 10) and a
/// wall-clock deadline; on expiry the child is killed and an error returned.
/// Output is read after exit — fine for the small outputs of `nft` (well
/// under the 64 KiB pipe buffer, so the child never blocks on write).
pub fn run_with_timeout(bin: &Path, args: &[&str], timeout: Duration) -> io::Result<CommandResult> {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{} timed out after {timeout:?}", bin.display()),
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut stdout);
    }
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut stderr);
    }
    Ok(CommandResult {
        success: status.success(),
        stdout,
        stderr,
    })
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
}
