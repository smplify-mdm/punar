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
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
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
