use std::fs;
use std::path::Path;

pub fn lookup_gid(group_file: &Path, wanted: &str) -> Option<u32> {
    fs::read_to_string(group_file)
        .ok()?
        .lines()
        .find_map(|line| {
            let mut fields = line.split(':');
            (fields.next()? == wanted)
                .then(|| fields.nth(1)?.parse::<u32>().ok())
                .flatten()
        })
}

pub fn username_or_uid(passwd_file: &Path, uid: u32) -> String {
    fs::read_to_string(passwd_file)
        .ok()
        .and_then(|body| {
            body.lines().find_map(|line| {
                let mut fields = line.split(':');
                let name = fields.next()?;
                fields.next()?;
                (fields.next()?.parse::<u32>().ok()? == uid).then(|| name.to_string())
            })
        })
        .unwrap_or_else(|| format!("uid:{uid}"))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn local_identity_files_are_parsed_without_commands() {
        let root = std::env::temp_dir().join(format!(
            "punar-netd-util-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let group = root.join("group");
        let passwd = root.join("passwd");
        fs::write(&group, "punar:x:998:punar\n").unwrap();
        fs::write(&passwd, "punar:x:1000:1000:Punar:/home/punar:/bin/bash\n").unwrap();
        assert_eq!(lookup_gid(&group, "punar"), Some(998));
        assert_eq!(username_or_uid(&passwd, 1000), "punar");
        assert_eq!(username_or_uid(&passwd, 42), "uid:42");
        fs::remove_dir_all(root).unwrap();
    }
}
