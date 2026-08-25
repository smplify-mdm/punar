//! Small identity helpers for `punar-secrets`.
//!
//! Deliberately a copy of the `punard`/`punar-agentd` originals rather than
//! a shared crate — the reason `punar-agentd`'s `util.rs` gives, applied a
//! third time: these are three separate binaries with separate lifetimes,
//! and lifting two `/etc/passwd` line splitters into a *contract* crate
//! would widen it for convenience. What the M9 design does promote to
//! `punar_common` is the thing where two implementations could **disagree
//! about a privilege boundary** (agent attribution, plan section 3.4) —
//! not this.
//!
//! `punar-secrets` writes no state file, so there is no `write_atomic`
//! here. That absence is the point (ipc.md section 16.4).

use std::fs;
use std::path::Path;

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

/// The peer's username, or the `uid:<n>` fallback the audit trail uses when
/// the uid resolves to no account.
pub fn username_or_uid(passwd_file: &Path, uid: u32) -> String {
    lookup_username(passwd_file, uid).unwrap_or_else(|| format!("uid:{uid}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("punar-secrets-util-{tag}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn nss_lookups_parse_the_format_and_fall_back_honestly() {
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
        assert_eq!(username_or_uid(&passwd, 0), "root");
        assert_eq!(username_or_uid(&passwd, 4242), "uid:4242");
        let _ = fs::remove_dir_all(&dir);
    }
}
