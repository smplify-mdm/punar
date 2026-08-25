//! Small filesystem/identity helpers for `punar-agentd`.
//!
//! Deliberately a copy of the `punard` originals (`crates/punard/src/util.rs`)
//! rather than a shared crate: the two daemons are separate binaries with
//! separate lifetimes, and lifting four short functions into `punar-common`
//! would widen a *contract* crate for convenience. The behavior — including
//! the `O_EXCL` temp-file rule that keeps root from following a planted
//! symlink in the user-writable `/run/punar` (spec section 61) — is
//! identical, and the tests below re-prove it here.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Write `bytes` to `path` atomically: exclusive-create a sibling temp
/// file, write, rename over the target. Readers see either the old file or
/// the new one, never a partial write.
///
/// The temp file is opened `O_CREAT|O_EXCL` because this helper also writes
/// `/run/punar/agents.json` into a directory owned by the unprivileged
/// session user (tmpfiles: `0755 punar:punar`), where a predictable temp
/// name opened without `O_EXCL` would let that user plant a symlink and
/// have root truncate an arbitrary file (spec section 61). A pre-existing
/// temp file (stale leftover or planted link) is unlinked — `remove_file`
/// unlinks the link itself, not its target — and the exclusive create is
/// retried once; a second collision fails loudly rather than follow.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    write_atomic_inner(path, bytes, mode, false)
}

/// [`write_atomic`] plus an `fsync` of the temp file before the rename
/// (milestone-10.md section 5.3).
///
/// Used for the two files M10 adds whose *absence after a crash* would be
/// a lie rather than a nuisance: `/run/punar-agentd/alerts.json`, which
/// tells a human what to believe, and the detection index, which is the
/// sibling half of a schema-exact record already on disk. A summary file
/// the panel re-derives on the next pass does not need this; a card
/// asserting "unknown AI suspected" does, because the alternative is
/// showing yesterday's card as if it were today's.
pub fn write_atomic_synced(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    write_atomic_inner(path, bytes, mode, true)
}

fn write_atomic_inner(path: &Path, bytes: &[u8], mode: u32, sync: bool) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = parent.join(format!(
        ".{file_name}.punar-agentd-tmp.{}",
        std::process::id()
    ));
    let open_excl = || {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
    };
    {
        let mut file = match open_excl() {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                fs::remove_file(&tmp)?;
                open_excl()?
            }
            Err(e) => return Err(e),
        };
        file.write_all(bytes)?;
        file.flush()?;
        if sync {
            file.sync_all()?;
        }
    }
    // Mode is asserted after create in case of a restrictive umask.
    fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(mode))?;
    fs::rename(&tmp, path)
}

/// Look up a gid by group name in an `/etc/group`-format file.
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

/// Look up a uid by username in an `/etc/passwd`-format file (the inverse
/// of [`lookup_username`], used to re-derive the owner of a session
/// replayed from `registry.jsonl`, which records the *name*).
pub fn lookup_uid(passwd_file: &Path, name: &str) -> Option<u32> {
    let content = fs::read_to_string(passwd_file).ok()?;
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 && fields[0] == name {
            return fields[2].parse().ok();
        }
    }
    None
}

/// Look up a home directory by uid in an `/etc/passwd`-format file.
///
/// M10's provenance rules are written with `~/Downloads/` prefixes
/// (milestone-10.md section 3.5), and `~` means *the home of the user who
/// owns the process*, resolved here. A uid with no account resolves to
/// `None`, and a `~/` prefix then matches **nothing** — never `/`, which
/// would turn one rule into a filesystem-wide one.
pub fn lookup_home(passwd_file: &Path, uid: u32) -> Option<String> {
    let content = fs::read_to_string(passwd_file).ok()?;
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 6 && fields[2].parse() == Ok(uid) {
            let home = fields[5].trim();
            return (!home.is_empty()).then(|| home.to_string());
        }
    }
    None
}

/// The peer's username, or the `uid:<n>` fallback the audit trail uses
/// when the uid resolves to no account (`punar_common::audit::AuditActor`'s
/// convention, mirrored here).
pub fn username_or_uid(passwd_file: &Path, uid: u32) -> String {
    lookup_username(passwd_file, uid).unwrap_or_else(|| format!("uid:{uid}"))
}

// # Where detection identity used to live
//
// M7 minted a detection's `agt_` id here, from FNV-1a over
// `(executable, pid)`. M10 replaced it with `crate::identity`: the M7
// construction could not survive **pid reuse** — a recycled pid running
// the same binary produced the *same* id, which would have let a new
// process silently inherit a dead detection's persisted record and its
// ledger. The replacement adds the kernel's `starttime` ticks and the
// boot id and is SHA-256, and it is now the only place a detection
// identity is minted. The old function was removed rather than
// deprecated: two competing identity constructions inside one daemon is
// the bug, not the migration.

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("punar-agentd-util-{tag}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn write_atomic_replaces_content_and_sets_mode() {
        let dir = tmp_dir("atomic");
        let path = dir.join("agents.json");
        write_atomic(&path, b"one\n", 0o644).unwrap();
        write_atomic(&path, b"two\n", 0o644).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "two\n");
        let mode =
            std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&path).unwrap().permissions());
        assert_eq!(mode & 0o777, 0o644);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Spec section 61 again, on the second daemon: `/run/punar` is
    /// user-writable, so the predictable temp name must never be followed.
    #[test]
    fn write_atomic_never_follows_a_planted_tmp_symlink() {
        let dir = tmp_dir("symlink");
        let victim = dir.join("victim");
        fs::write(&victim, b"untouched\n").unwrap();
        let path = dir.join("agents.json");
        let planted = dir.join(format!(
            ".agents.json.punar-agentd-tmp.{}",
            std::process::id()
        ));
        std::os::unix::fs::symlink(&victim, &planted).unwrap();

        write_atomic(&path, b"payload\n", 0o644).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "untouched\n");
        assert_eq!(fs::read_to_string(&path).unwrap(), "payload\n");
        assert!(!planted.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn nss_lookups_parse_the_format_both_ways() {
        let dir = tmp_dir("nss");
        let group = dir.join("group");
        fs::write(&group, "root:x:0:\npunar:x:970:\n").unwrap();
        assert_eq!(lookup_gid(&group, "punar"), Some(970));
        assert_eq!(lookup_gid(&group, "absent"), None);

        let passwd = dir.join("passwd");
        fs::write(
            &passwd,
            "root:x:0:0::/root:/bin/bash\npunar:x:1000:1000::/home/punar:/bin/bash\n",
        )
        .unwrap();
        assert_eq!(lookup_username(&passwd, 1000).as_deref(), Some("punar"));
        assert_eq!(lookup_uid(&passwd, "punar"), Some(1000));
        assert_eq!(lookup_username(&passwd, 4242), None);
        assert_eq!(username_or_uid(&passwd, 4242), "uid:4242");
        assert_eq!(lookup_home(&passwd, 1000).as_deref(), Some("/home/punar"));
        assert_eq!(lookup_home(&passwd, 0).as_deref(), Some("/root"));
        assert_eq!(
            lookup_home(&passwd, 4242),
            None,
            "an unknown uid has no home, so a ~/ rule matches nothing"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_synced_produces_the_same_file_and_mode() {
        let dir = tmp_dir("atomic-sync");
        let path = dir.join("alerts.json");
        write_atomic_synced(&path, b"{\"v\":1}\n", 0o640).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"v\":1}\n");
        let mode =
            std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&path).unwrap().permissions());
        assert_eq!(mode & 0o777, 0o640, "alerts.json is 0640 root:punar");
        let _ = fs::remove_dir_all(&dir);
    }
}
