//! Device administrators (F0-S1; docs/api/ipc.md section 23).
//!
//! WHAT THE ROLE IS. Membership in the system group `punar-admin`. Onboarding
//! puts the first account in it, and on every boot the account materializer
//! (`punar-onboard materialize`) makes sure an upgraded device that predates
//! the role ends up with its owner in it, so no update leaves a device with
//! no administrator. This module is punard's view of that membership and the
//! one writer that changes it afterwards (`admins.set`).
//!
//! WHERE MEMBERSHIP LIVES, and why this reads two places. A Punar account is
//! a systemd userdb record: its persistent truth is
//! `/var/lib/punar/identity/accounts/<id>/account.json` (its `groups` array),
//! and the materializer publishes each group edge as a drop-in,
//! `/run/userdb/<user>:<group>.membership`, which is what nss-systemd — and so
//! every login — sees. An account an image ships in `/etc/group` (the dev
//! image's fixed `punar` user) is a member through that file instead. The
//! runtime view is the union of the two, exactly what `getent` would report,
//! and it is what a role check reads. `admins.set` changes the persistent
//! record first and the drop-in second, so a crash between the two is healed
//! by the next boot's materialization rather than lost.
//!
//! WHY NOT THE CALLER'S PROCESS GROUPS. A process keeps the supplementary
//! groups it logged in with. Reading them would let a person whose role was
//! just taken away keep acting until they logged out, and a revocation that
//! waits for the revoked person's cooperation is not one.
//!
//! The account-record format is onboarding's (`crates/punar-onboard/src/
//! identity.rs`, `AccountRecord`; docs/design/onboarding.md). It is edited as
//! a JSON value so every field this module does not own survives untouched,
//! and the group name is a constant on both sides that a test pins.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;

use crate::util::{lookup_username, write_atomic};

/// The group whose members administer the device. The same string is
/// `punar_onboard::identity::ADMIN_GROUP`; punard does not link the
/// onboarding crate (it holds the account creation transaction and has no
/// business in the control plane's address space), so each side names it and
/// `the_group_name_matches_onboarding` holds them together.
pub const ADMIN_GROUP: &str = "punar-admin";

/// Where the role is read and written. Every path is injectable so the whole
/// module runs inside a tempdir in tests.
#[derive(Debug, Clone)]
pub struct AdminSources {
    /// `/var/lib/punar/identity/accounts` — onboarding's persistent records.
    pub identity_accounts: PathBuf,
    /// `/run/userdb` — the drop-ins nss-systemd serves.
    pub userdb_dir: PathBuf,
    /// `/etc/group` — accounts an image ships.
    pub group_file: PathBuf,
    /// `/etc/passwd` — the names of accounts an image ships.
    pub passwd_file: PathBuf,
}

/// Where an account came from, which decides whether `admins.set` may change
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// Created by onboarding; its role lives in its account record.
    Onboarded,
    /// Shipped by the image in `/etc/group` (development images only). Its
    /// membership is part of the image and changes with the image.
    Image,
}

/// One account and whether it holds the role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Account {
    pub user: String,
    pub uid: u32,
    pub administrator: bool,
    pub origin: Origin,
}

/// Why `admins.set` could not change a role. Every variant is a fact about
/// the device, never about the caller; the caller's authority is decided
/// before this module is reached.
#[derive(Debug)]
pub enum SetError {
    /// No account on this device has that name.
    NoSuchAccount,
    /// The account's membership is part of the image, not a record punard
    /// may edit.
    ImageManaged,
    /// The record could not be read or written.
    Storage(io::Error),
}

impl AdminSources {
    /// Production paths.
    pub fn production() -> AdminSources {
        AdminSources {
            identity_accounts: PathBuf::from("/var/lib/punar/identity/accounts"),
            userdb_dir: PathBuf::from("/run/userdb"),
            group_file: PathBuf::from("/etc/group"),
            passwd_file: PathBuf::from("/etc/passwd"),
        }
    }

    /// The name of the account with this uid: the image's passwd file first,
    /// then the onboarded records. `None` for a uid no account has.
    pub fn username_of(&self, uid: u32) -> Option<String> {
        lookup_username(&self.passwd_file, uid).or_else(|| {
            self.onboarded()
                .into_iter()
                .find(|(_, record)| record_uid(record) == Some(uid))
                .and_then(|(_, record)| record_user(&record))
        })
    }

    /// Whether `user` holds the role right now, as a login would see it.
    pub fn is_member(&self, user: &str) -> bool {
        if !name_ok(user) {
            return false;
        }
        self.static_members().iter().any(|member| member == user)
            || self.membership_path(user).is_file()
    }

    /// Every account on the device, onboarded first, then image accounts that
    /// hold the role, sorted by uid. Accounts an image ships without the role
    /// are not listed: they are service identities, not people.
    pub fn accounts(&self) -> Vec<Account> {
        let mut accounts: Vec<Account> = self
            .onboarded()
            .into_iter()
            .filter_map(|(_, record)| {
                let user = record_user(&record)?;
                Some(Account {
                    administrator: self.is_member(&user),
                    uid: record_uid(&record)?,
                    user,
                    origin: Origin::Onboarded,
                })
            })
            .collect();
        for member in self.static_members() {
            if accounts.iter().any(|account| account.user == member) {
                continue;
            }
            let uid = uid_of_name(&self.passwd_file, &member).unwrap_or(u32::MAX);
            accounts.push(Account {
                user: member,
                uid,
                administrator: true,
                origin: Origin::Image,
            });
        }
        accounts.sort_by(|a, b| a.uid.cmp(&b.uid).then_with(|| a.user.cmp(&b.user)));
        accounts
    }

    /// Give `user` the role or take it away. `Ok(true)` when something
    /// changed, `Ok(false)` when the account already stood as asked.
    ///
    /// ORDER: the persistent record, then the runtime drop-in. A crash
    /// between the two leaves the record right and the drop-in one boot
    /// stale, and the materializer republishes from the record on the next
    /// boot. The reverse order could leave a drop-in the record does not back.
    pub fn set_member(&self, user: &str, member: bool) -> Result<bool, SetError> {
        let Some((path, mut record)) = self
            .onboarded()
            .into_iter()
            .find(|(_, record)| record_user(record).as_deref() == Some(user))
        else {
            return Err(if self.static_members().iter().any(|m| m == user) {
                SetError::ImageManaged
            } else {
                SetError::NoSuchAccount
            });
        };
        let mut groups: Vec<String> = record
            .get("groups")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let recorded = groups.iter().any(|group| group == ADMIN_GROUP);
        let published = self.membership_path(user).is_file();
        if recorded == member && published == member {
            return Ok(false);
        }
        if recorded != member {
            if member {
                groups.push(ADMIN_GROUP.to_string());
            } else {
                groups.retain(|group| group != ADMIN_GROUP);
            }
            record["groups"] = Value::from(groups);
            let mut bytes = serde_json::to_vec_pretty(&record)
                .map_err(|e| SetError::Storage(io::Error::other(e)))?;
            bytes.push(b'\n');
            write_atomic(&path, &bytes, 0o600).map_err(SetError::Storage)?;
        }
        let drop_in = self.membership_path(user);
        if member {
            fs::create_dir_all(&self.userdb_dir).map_err(SetError::Storage)?;
            write_atomic(&drop_in, b"{}\n", 0o644).map_err(SetError::Storage)?;
        } else {
            match fs::remove_file(&drop_in) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(SetError::Storage(e)),
            }
        }
        Ok(true)
    }

    /// `/run/userdb/<user>:punar-admin.membership`. Only ever built from a
    /// name that passed [`name_ok`], so no traversal shape reaches the join.
    fn membership_path(&self, user: &str) -> PathBuf {
        self.userdb_dir
            .join(format!("{user}:{ADMIN_GROUP}.membership"))
    }

    /// Members of the role listed in the image's `/etc/group`.
    fn static_members(&self) -> Vec<String> {
        let Ok(content) = fs::read_to_string(&self.group_file) else {
            return Vec::new();
        };
        content
            .lines()
            .filter_map(|line| {
                let mut fields = line.split(':');
                (fields.next() == Some(ADMIN_GROUP)).then(|| fields.nth(2))?
            })
            .flat_map(|members| members.split(','))
            .map(str::trim)
            .filter(|member| name_ok(member))
            .map(str::to_string)
            .collect()
    }

    /// Every readable onboarded record, with the path it was read from. A
    /// corrupt record is skipped rather than fatal: one damaged file must not
    /// hide every other account's role.
    fn onboarded(&self) -> Vec<(PathBuf, Value)> {
        let Ok(entries) = fs::read_dir(&self.identity_accounts) else {
            return Vec::new();
        };
        let mut records: Vec<(PathBuf, Value)> = entries
            .flatten()
            .filter(|entry| {
                // `.txn-<id>` is an onboarding transaction in flight, not an
                // account.
                !entry.file_name().to_string_lossy().starts_with('.')
            })
            .filter_map(|entry| {
                let path = entry.path().join("account.json");
                let record: Value = serde_json::from_slice(&fs::read(&path).ok()?).ok()?;
                (record_user(&record).is_some() && record_uid(&record).is_some())
                    .then_some((path, record))
            })
            .collect();
        records.sort_by(|a, b| a.0.cmp(&b.0));
        records
    }
}

fn record_user(record: &Value) -> Option<String> {
    record
        .get("username")
        .and_then(Value::as_str)
        .filter(|name| name_ok(name))
        .map(str::to_string)
}

fn record_uid(record: &Value) -> Option<u32> {
    record
        .get("uid")
        .and_then(Value::as_u64)
        .and_then(|uid| u32::try_from(uid).ok())
}

fn uid_of_name(passwd_file: &Path, name: &str) -> Option<u32> {
    let content = fs::read_to_string(passwd_file).ok()?;
    content.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        (fields.len() >= 3 && fields[0] == name)
            .then(|| fields[2].parse().ok())
            .flatten()
    })
}

/// The account-name shape onboarding accepts, and the only names this module
/// will ever join to a path.
pub fn name_ok(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'_'))
        && name.len() <= 32
        && bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("punard-admins-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sources(dir: &Path) -> AdminSources {
        fs::write(
            dir.join("group"),
            "root:x:0:\npunar:x:970:\npunar-admin:x:971:\n",
        )
        .unwrap();
        fs::write(dir.join("passwd"), "root:x:0:0::/root:/bin/bash\n").unwrap();
        AdminSources {
            identity_accounts: dir.join("accounts"),
            userdb_dir: dir.join("userdb"),
            group_file: dir.join("group"),
            passwd_file: dir.join("passwd"),
        }
    }

    /// An onboarded account exactly as onboarding writes it, and its
    /// materialized drop-ins.
    fn onboard(src: &AdminSources, id: &str, user: &str, uid: u32, groups: &[&str]) {
        let dir = src.identity_accounts.join(id);
        fs::create_dir_all(&dir).unwrap();
        let record = serde_json::json!({
            "v": 1, "accountId": id, "username": user, "uid": uid, "gid": uid,
            "uidSource": "local", "realName": null, "realNameSource": "local",
            "groups": groups, "home": format!("/home/{user}"), "shell": "/bin/bash",
            "identity": null, "auth": {"kinds": ["password"]}
        });
        fs::write(dir.join("account.json"), record.to_string()).unwrap();
        fs::create_dir_all(&src.userdb_dir).unwrap();
        for group in groups {
            fs::write(
                src.userdb_dir.join(format!("{user}:{group}.membership")),
                "{}",
            )
            .unwrap();
        }
    }

    #[test]
    fn the_group_name_matches_onboarding() {
        let onboarding = include_str!("../../punar-onboard/src/identity.rs");
        assert!(
            onboarding.contains(&format!("pub const ADMIN_GROUP: &str = \"{ADMIN_GROUP}\";")),
            "punar-onboard and punard must name the same administrator group"
        );
    }

    #[test]
    fn membership_is_what_a_login_would_see_and_nothing_else() {
        let dir = scratch("view");
        let src = sources(&dir);
        onboard(
            &src,
            "acct_0000000000000001",
            "alice",
            1000,
            &["punar", ADMIN_GROUP],
        );
        onboard(&src, "acct_0000000000000002", "bob", 1001, &["punar"]);
        assert!(src.is_member("alice"));
        assert!(!src.is_member("bob"));
        assert!(!src.is_member("nobody"));
        // A name that is not an account name is never joined to a path.
        assert!(!src.is_member("../alice"));
        assert_eq!(src.username_of(1001).as_deref(), Some("bob"));
        assert_eq!(src.username_of(4242), None);

        // A record that says admin with no published drop-in is not a
        // member yet: the role is what a login would see.
        onboard(&src, "acct_0000000000000003", "carol", 1002, &["punar"]);
        let path = src
            .identity_accounts
            .join("acct_0000000000000003/account.json");
        let mut record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        record["groups"] = serde_json::json!(["punar", ADMIN_GROUP]);
        fs::write(&path, record.to_string()).unwrap();
        assert!(!src.is_member("carol"));

        let listed: Vec<(String, bool)> = src
            .accounts()
            .into_iter()
            .map(|a| (a.user, a.administrator))
            .collect();
        assert_eq!(
            listed,
            [
                ("alice".to_string(), true),
                ("bob".to_string(), false),
                ("carol".to_string(), false)
            ]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_image_member_is_listed_and_cannot_be_edited_here() {
        let dir = scratch("image");
        let src = sources(&dir);
        fs::write(
            &src.group_file,
            "root:x:0:\npunar:x:970:\npunar-admin:x:971:punar\n",
        )
        .unwrap();
        fs::write(
            &src.passwd_file,
            "root:x:0:0::/root:/bin/bash\npunar:x:1000:1000::/home/punar:/bin/bash\n",
        )
        .unwrap();
        assert!(src.is_member("punar"));
        assert_eq!(
            src.accounts(),
            [Account {
                user: "punar".into(),
                uid: 1000,
                administrator: true,
                origin: Origin::Image,
            }]
        );
        assert!(matches!(
            src.set_member("punar", false),
            Err(SetError::ImageManaged)
        ));
        assert!(matches!(
            src.set_member("mallory", true),
            Err(SetError::NoSuchAccount)
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn setting_the_role_changes_the_record_and_the_drop_in_and_keeps_every_other_field() {
        let dir = scratch("set");
        let src = sources(&dir);
        onboard(
            &src,
            "acct_0000000000000002",
            "bob",
            1001,
            &["punar", "video"],
        );
        let path = src
            .identity_accounts
            .join("acct_0000000000000002/account.json");

        assert!(src.set_member("bob", true).unwrap());
        assert!(src.is_member("bob"));
        let record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            record["groups"],
            serde_json::json!(["punar", "video", ADMIN_GROUP])
        );
        assert_eq!(record["home"], "/home/bob", "no other field is touched");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // Asking again changes nothing and says so.
        assert!(!src.set_member("bob", true).unwrap());

        assert!(src.set_member("bob", false).unwrap());
        assert!(!src.is_member("bob"));
        let record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(record["groups"], serde_json::json!(["punar", "video"]));
        assert!(!src.set_member("bob", false).unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stale_drop_in_is_repaired_even_when_the_record_already_agrees() {
        let dir = scratch("heal");
        let src = sources(&dir);
        onboard(&src, "acct_0000000000000002", "bob", 1001, &["punar"]);
        // A drop-in the record does not back (a crash, or a hand edit).
        fs::write(
            src.userdb_dir.join(format!("bob:{ADMIN_GROUP}.membership")),
            "{}",
        )
        .unwrap();
        assert!(src.is_member("bob"));
        assert!(src.set_member("bob", false).unwrap());
        assert!(!src.is_member("bob"));
        let _ = fs::remove_dir_all(&dir);
    }
}
