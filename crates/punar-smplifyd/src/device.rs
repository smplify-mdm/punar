//! The five facts about this device that leave it at enrollment, and nothing
//! else. The stock Smplify agent ships the whole os-release map; Punar ships
//! exactly the keys the registry resolves on.
use std::collections::BTreeMap;
use std::path::Path;

pub const OS_RELEASE_KEYS: [&str; 5] = [
    "ID",
    "VERSION_ID",
    "PRETTY_NAME",
    "IMAGE_ID",
    "IMAGE_VERSION",
];

/// Punar's own canonical identifier on the Smplify registry when the
/// substrate row does not resolve (SPEC section 49: the organisation manages
/// Punar, not the substrate it was built from).
pub const CANONICAL_OS_IDENTIFIER: &str = "punar";

pub fn os_release(path: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return out;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if !OS_RELEASE_KEYS.contains(&key) {
            continue;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);
        out.insert(key.to_string(), value.to_string());
    }
    out
}

pub fn hostname() -> String {
    for path in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(contents) = std::fs::read_to_string(path) {
            let name = contents.trim();
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    "punar".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_the_five_keys_and_strips_quotes() {
        let dir = std::env::temp_dir().join(format!("punar-smplifyd-osr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("os-release");
        std::fs::write(
            &file,
            "ID=arch\nPRETTY_NAME=\"Punar OS\"\nHOME_URL='https://x'\nIMAGE_ID=punar-desktop\n# c\nBUILD_ID=rolling\n",
        )
        .unwrap();
        let map = os_release(&file);
        assert_eq!(map.get("ID").unwrap(), "arch");
        assert_eq!(map.get("PRETTY_NAME").unwrap(), "Punar OS");
        assert_eq!(map.get("IMAGE_ID").unwrap(), "punar-desktop");
        assert!(!map.contains_key("HOME_URL"));
        assert!(!map.contains_key("BUILD_ID"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
