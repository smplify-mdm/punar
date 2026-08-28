//! Persistent local identity on shared `/var`, materialized into the
//! `nss-systemd` runtime drop-in database before greetd starts.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use rustix::rand::{GetRandomFlags, getrandom};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::protocol::{ValidatedAccount, ValidationError, validate_account};
use crate::secret::{HashError, yescrypt};

const UID_MIN: u32 = 1000;
const UID_MAX_EXCLUSIVE: u32 = 60_000;
const SUBID_START: u32 = 100_000;
const SUBID_COUNT: u32 = 65_536;

#[derive(Clone, Debug)]
pub struct IdentityPaths {
    pub state_dir: PathBuf,
    pub onboarding_dir: PathBuf,
    pub runtime_userdb: PathBuf,
    pub runtime_projection: PathBuf,
    pub runtime_onboarding: PathBuf,
    pub runtime_subuid: PathBuf,
    pub runtime_subgid: PathBuf,
    pub first_login_dir: PathBuf,
    pub home_root: PathBuf,
}

impl IdentityPaths {
    pub fn production() -> Self {
        Self {
            state_dir: PathBuf::from("/var/lib/punar/identity"),
            onboarding_dir: PathBuf::from("/var/lib/punar/onboarding"),
            runtime_userdb: PathBuf::from("/run/userdb"),
            runtime_projection: PathBuf::from("/run/punar/greeter.json"),
            runtime_onboarding: PathBuf::from("/run/punar/onboarding.json"),
            runtime_subuid: PathBuf::from("/run/punar/subuid"),
            runtime_subgid: PathBuf::from("/run/punar/subgid"),
            first_login_dir: PathBuf::from("/run/punar-first-login"),
            home_root: PathBuf::from("/home"),
        }
    }

    fn marker(&self) -> PathBuf {
        self.onboarding_dir.join("completed.json")
    }

    fn journal(&self) -> PathBuf {
        self.onboarding_dir.join("transaction.json")
    }

    fn accounts_dir(&self) -> PathBuf {
        self.state_dir.join("accounts")
    }
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("validation failed")]
    Validation(ValidationError),
    #[error("that username is already in use")]
    UsernameTaken,
    #[error("first run is already complete")]
    AlreadyComplete,
    #[error("no regular uid/gid pair is available")]
    NoUid,
    #[error("the Punar admission group is unavailable")]
    AdmissionGroup,
    #[error("password hashing failed")]
    Hash(#[from] HashError),
    #[error("identity storage failed")]
    Storage(#[source] io::Error),
    #[error("hostname update failed")]
    Hostname,
    #[error("home directory setup failed")]
    Home,
    #[error("runtime account materialization failed")]
    Materialize,
    #[error("stored identity record is invalid")]
    Corrupt,
}

/// The small boundary between the identity transaction and substrate-owned
/// facilities. Keeping it explicit makes failure at every destructive stage
/// testable without creating real host accounts or changing the test host's
/// name. Production still has exactly one implementation below.
trait IdentityPlatform {
    fn hash(&self, secret: &str) -> Result<Zeroizing<String>, IdentityError>;
    fn lookup(&self, database: &str, key: &str) -> Result<Option<String>, IdentityError>;
    fn current_hostname(&self) -> String;
    fn set_hostname(&self, hostname: &str) -> Result<(), IdentityError>;
    fn create_home(&self, path: &Path, uid: u32, gid: u32) -> Result<(), IdentityError>;
    fn finalize_home(&self, path: &Path, uid: u32, gid: u32) -> Result<(), IdentityError>;

    /// Fault-injection seam used by the transaction tests. The system
    /// implementation is a no-op and there is no runtime switch or env var.
    fn after_runtime_materialized(&self) -> Result<(), IdentityError> {
        Ok(())
    }
}

struct SystemPlatform;

impl IdentityPlatform for SystemPlatform {
    fn hash(&self, secret: &str) -> Result<Zeroizing<String>, IdentityError> {
        yescrypt(secret).map_err(IdentityError::from)
    }

    fn lookup(&self, database: &str, key: &str) -> Result<Option<String>, IdentityError> {
        system_lookup(database, key)
    }

    fn current_hostname(&self) -> String {
        read_trimmed(Path::new("/proc/sys/kernel/hostname"))
            .unwrap_or_else(|_| "localhost".to_string())
    }

    fn set_hostname(&self, hostname: &str) -> Result<(), IdentityError> {
        system_set_hostname(hostname)
    }

    fn create_home(&self, path: &Path, uid: u32, gid: u32) -> Result<(), IdentityError> {
        system_create_home(path, uid, gid)
    }

    fn finalize_home(&self, path: &Path, uid: u32, gid: u32) -> Result<(), IdentityError> {
        system_finalize_home(path, uid, gid)
    }
}

impl From<ValidationError> for IdentityError {
    fn from(value: ValidationError) -> Self {
        Self::Validation(value)
    }
}

#[derive(Debug)]
pub struct CreatedAccount {
    pub username: String,
    pub hostname: String,
    pub recovery_code: Zeroizing<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountRecord {
    v: u32,
    account_id: String,
    username: String,
    uid: u32,
    gid: u32,
    uid_source: String,
    real_name: Option<String>,
    real_name_source: String,
    groups: Vec<String>,
    home: String,
    shell: String,
    identity: Option<String>,
    auth: AuthSummary,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthSummary {
    kinds: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CompletionMarker {
    v: u32,
    account_id: String,
    username: String,
    uid: u32,
    hostname: String,
    mode: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionJournal {
    v: u32,
    account_id: String,
    username: String,
    uid: u32,
    gid: u32,
    account_dir: String,
    home_dir: String,
    original_hostname: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceRecord<'a> {
    v: u32,
    display_name: &'a str,
    hostname: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryRecord<'a> {
    v: u32,
    account_id: &'a str,
    username: &'a str,
    algorithm: &'static str,
    hash: &'a str,
    attempts: u32,
    used: bool,
}

pub struct IdentityStore {
    paths: IdentityPaths,
    platform: Box<dyn IdentityPlatform>,
}

impl IdentityStore {
    pub fn new(paths: IdentityPaths) -> Self {
        Self {
            paths,
            platform: Box::new(SystemPlatform),
        }
    }

    pub fn production() -> Self {
        Self::new(IdentityPaths::production())
    }

    #[cfg(test)]
    fn with_platform(paths: IdentityPaths, platform: Box<dyn IdentityPlatform>) -> Self {
        Self { paths, platform }
    }

    /// Create the first account as one rollback-aware transaction. The only
    /// plaintext returned is the one-time recovery code.
    pub fn create_first_account(
        &self,
        username: &str,
        password: &str,
        device_name: &str,
    ) -> Result<CreatedAccount, IdentityError> {
        let validated = validate_account(username, password, device_name)?;
        self.prepare_dirs()?;
        self.recover_incomplete()?;
        if self.paths.marker().exists() {
            return Err(IdentityError::AlreadyComplete);
        }
        if self
            .platform
            .lookup("passwd", &validated.username)?
            .is_some()
        {
            return Err(IdentityError::UsernameTaken);
        }
        let admission_gid =
            lookup_gid(self.platform.as_ref(), "punar")?.ok_or(IdentityError::AdmissionGroup)?;
        let (uid, gid) = allocate_uid_gid(self.platform.as_ref())?;
        let account_id = format!("acct_{}", random_hex(8)?);
        let recovery_code = Zeroizing::new(random_recovery_code()?);
        let password_hash = self.platform.hash(password)?;
        let recovery_hash = self.platform.hash(&recovery_code)?;
        let original_hostname = self.platform.current_hostname();

        let account_dir = self.paths.accounts_dir().join(&account_id);
        let home_dir = self.paths.home_root.join(&validated.username);
        let stage_dir = self.paths.accounts_dir().join(format!(".txn-{account_id}"));
        let home_stage = self.paths.home_root.join(format!(".punar-{account_id}"));
        let journal = TransactionJournal {
            v: 1,
            account_id: account_id.clone(),
            username: validated.username.clone(),
            uid,
            gid,
            account_dir: account_dir.to_string_lossy().into_owned(),
            home_dir: home_dir.to_string_lossy().into_owned(),
            original_hostname: original_hostname.clone(),
        };
        write_json_atomic(&self.paths.journal(), &journal, 0o600)?;

        let result = self.commit_account(
            &validated,
            uid,
            gid,
            admission_gid,
            &account_id,
            &password_hash,
            &recovery_hash,
            &stage_dir,
            &account_dir,
            &home_stage,
            &home_dir,
        );
        if let Err(error) = result {
            let _ = self.rollback(&journal);
            return Err(error);
        }

        if let Err(error) = self.platform.after_runtime_materialized() {
            let _ = self.rollback(&journal);
            return Err(error);
        }

        let marker = CompletionMarker {
            v: 1,
            account_id: account_id.clone(),
            username: validated.username.clone(),
            uid,
            hostname: validated.hostname.clone(),
            mode: "personal".to_string(),
        };
        if let Err(error) = write_json_atomic(&self.paths.marker(), &marker, 0o600) {
            let _ = self.rollback(&journal);
            return Err(error);
        }
        let _ = fs::remove_file(self.paths.journal());

        Ok(CreatedAccount {
            username: validated.username,
            hostname: validated.hostname,
            recovery_code,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_account(
        &self,
        validated: &ValidatedAccount,
        uid: u32,
        gid: u32,
        admission_gid: u32,
        account_id: &str,
        password_hash: &str,
        recovery_hash: &str,
        stage_dir: &Path,
        account_dir: &Path,
        home_stage: &Path,
        home_dir: &Path,
    ) -> Result<(), IdentityError> {
        if account_dir.exists() || home_dir.exists() {
            return Err(IdentityError::UsernameTaken);
        }
        create_private_dir(stage_dir)?;

        let groups =
            existing_supplementary_groups(self.platform.as_ref(), ["punar", "video", "input"])?;
        if !groups.iter().any(|group| group == "punar") || admission_gid == gid {
            // A per-user primary group may not reuse the stable admission gid.
            return Err(IdentityError::AdmissionGroup);
        }
        let home = home_dir.to_string_lossy().into_owned();
        let account = AccountRecord {
            v: 1,
            account_id: account_id.to_string(),
            username: validated.username.clone(),
            uid,
            gid,
            uid_source: "local".to_string(),
            real_name: None,
            real_name_source: "local".to_string(),
            groups,
            home: home.clone(),
            shell: "/bin/bash".to_string(),
            identity: None,
            auth: AuthSummary {
                kinds: vec!["password".to_string()],
            },
        };
        write_json_atomic(&stage_dir.join("account.json"), &account, 0o600)?;
        write_json_atomic(
            &stage_dir.join(format!("{}.user", validated.username)),
            &json!({
                "userName": validated.username,
                "uid": uid,
                "gid": gid,
                "disposition": "regular",
                "homeDirectory": home,
                "shell": "/bin/bash",
                "locked": false,
                "lastChangeUSec": now_usec(),
                "lastPasswordChangeUSec": now_usec()
            }),
            0o600,
        )?;
        write_json_atomic(
            &stage_dir.join(format!("{}.user-privileged", validated.username)),
            &json!({"privileged": {"hashedPassword": [password_hash]}}),
            0o600,
        )?;
        write_json_atomic(
            &stage_dir.join(format!("{}.group", validated.username)),
            &json!({
                "groupName": validated.username,
                "gid": gid,
                "disposition": "regular"
            }),
            0o600,
        )?;
        write_json_atomic(
            &stage_dir.join("recovery.json"),
            &RecoveryRecord {
                v: 1,
                account_id,
                username: &validated.username,
                algorithm: "yescrypt",
                hash: recovery_hash,
                attempts: 0,
                used: false,
            },
            0o600,
        )?;

        self.platform.create_home(home_stage, uid, gid)?;
        // The durable per-user marker is staged inside the private home before
        // either directory is published. This is user-owned state, not the
        // authority for whether onboarding completed; the root-owned marker
        // below remains authoritative. Keeping the copy here satisfies the
        // desktop's first-boot contract without letting a failed transaction
        // leave a half-created account behind.
        let local_dir = home_stage.join(".local");
        let state_dir = local_dir.join("state");
        let punar_state_dir = state_dir.join("punar");
        for directory in [&local_dir, &state_dir, &punar_state_dir] {
            create_private_dir(directory)?;
        }
        write_json_atomic(
            &punar_state_dir.join("first-boot.json"),
            &CompletionMarker {
                v: 1,
                account_id: account_id.to_string(),
                username: validated.username.clone(),
                uid,
                hostname: validated.hostname.clone(),
                mode: "personal".to_string(),
            },
            0o600,
        )?;
        // The marker and its parents were created by the root transaction
        // after the skeleton was copied. Re-apply ownership once, then set the
        // privacy boundary last: GNU cp -a /etc/skel/. otherwise copies the
        // skeleton directory's 0755 mode onto the existing staging directory.
        self.platform.finalize_home(home_stage, uid, gid)?;
        fs::rename(stage_dir, account_dir).map_err(storage)?;
        fs::rename(home_stage, home_dir).map_err(storage)?;
        write_json_atomic(
            &self.paths.state_dir.join("device.json"),
            &DeviceRecord {
                v: 1,
                display_name: &validated.device_name,
                hostname: &validated.hostname,
            },
            0o644,
        )?;

        self.platform.set_hostname(&validated.hostname)?;
        self.materialize_account(account, &validated.device_name)?;
        create_first_login_token(&self.paths, &validated.username, account_id)?;
        Ok(())
    }

    pub fn materialize(&self) -> Result<(), IdentityError> {
        self.prepare_runtime_dirs()?;
        if self.paths.journal().exists() && !self.paths.marker().exists() {
            self.recover_incomplete()?;
        } else if self.paths.journal().exists() {
            let _ = fs::remove_file(self.paths.journal());
        }

        let marker_path = self.paths.marker();
        if !marker_path.exists() {
            write_json_atomic(
                &self.paths.runtime_onboarding,
                &json!({"v": 1, "complete": false}),
                0o644,
            )?;
            write_json_atomic(
                &self.paths.runtime_projection,
                &json!({"v": 1, "onboardingComplete": false, "accounts": []}),
                0o644,
            )?;
            return Ok(());
        }

        let marker: CompletionMarker = read_json(&marker_path)?;
        let account_path = self
            .paths
            .accounts_dir()
            .join(&marker.account_id)
            .join("account.json");
        let account: AccountRecord = read_json(&account_path)?;
        if account.account_id != marker.account_id
            || account.username != marker.username
            || account.uid != marker.uid
        {
            return Err(IdentityError::Corrupt);
        }
        let device: serde_json::Value = read_json(&self.paths.state_dir.join("device.json"))?;
        let device_name = device
            .get("displayName")
            .and_then(serde_json::Value::as_str)
            .ok_or(IdentityError::Corrupt)?;
        self.materialize_account(account, device_name)
    }

    fn materialize_account(
        &self,
        account: AccountRecord,
        device_name: &str,
    ) -> Result<(), IdentityError> {
        self.prepare_runtime_dirs()?;
        let source = self.paths.accounts_dir().join(&account.account_id);
        let username = &account.username;
        for (suffix, mode) in [
            ("user", 0o644),
            ("user-privileged", 0o600),
            ("group", 0o644),
        ] {
            let name = format!("{username}.{suffix}");
            copy_atomic(
                &source.join(&name),
                &self.paths.runtime_userdb.join(&name),
                mode,
            )?;
        }
        replace_symlink(
            &format!("{username}.user"),
            &self
                .paths
                .runtime_userdb
                .join(format!("{}.user", account.uid)),
        )?;
        replace_symlink(
            &format!("{username}.user-privileged"),
            &self
                .paths
                .runtime_userdb
                .join(format!("{}.user-privileged", account.uid)),
        )?;
        replace_symlink(
            &format!("{username}.group"),
            &self
                .paths
                .runtime_userdb
                .join(format!("{}.group", account.gid)),
        )?;
        for group in &account.groups {
            write_json_atomic(
                &self
                    .paths
                    .runtime_userdb
                    .join(format!("{username}:{group}.membership")),
                &json!({}),
                0o644,
            )?;
        }

        // Rootless Podman still consumes the classic subordinate-id files.
        // They are generated from the /var authority on every boot, never
        // treated as account truth themselves.
        write_text_atomic(
            &self.paths.runtime_subuid,
            &format!("{username}:{SUBID_START}:{SUBID_COUNT}\n"),
            0o644,
        )?;
        write_text_atomic(
            &self.paths.runtime_subgid,
            &format!("{username}:{SUBID_START}:{SUBID_COUNT}\n"),
            0o644,
        )?;

        write_json_atomic(
            &self.paths.runtime_projection,
            &json!({
                "v": 1,
                "onboardingComplete": true,
                "deviceName": device_name,
                "accounts": [{
                    "accountId": account.account_id,
                    "username": username,
                    "displayName": username,
                    "initials": username.chars().next().map(|c| c.to_uppercase().to_string()).unwrap_or_else(|| "·".to_string())
                }]
            }),
            0o644,
        )?;
        write_json_atomic(
            &self.paths.runtime_onboarding,
            &json!({"v": 1, "complete": true, "username": username}),
            0o644,
        )?;
        Ok(())
    }

    fn prepare_dirs(&self) -> Result<(), IdentityError> {
        create_private_dir(&self.paths.state_dir)?;
        create_private_dir(&self.paths.accounts_dir())?;
        create_private_dir(&self.paths.onboarding_dir)?;
        self.prepare_runtime_dirs()
    }

    fn prepare_runtime_dirs(&self) -> Result<(), IdentityError> {
        fs::create_dir_all(&self.paths.runtime_userdb).map_err(storage)?;
        fs::set_permissions(
            &self.paths.runtime_userdb,
            fs::Permissions::from_mode(0o755),
        )
        .map_err(storage)?;
        if let Some(parent) = self.paths.runtime_projection.parent() {
            fs::create_dir_all(parent).map_err(storage)?;
        }
        create_private_dir(&self.paths.first_login_dir)
    }

    fn recover_incomplete(&self) -> Result<(), IdentityError> {
        if !self.paths.journal().exists() {
            return Ok(());
        }
        let journal: TransactionJournal = read_json(&self.paths.journal())?;
        self.rollback(&journal)
    }

    fn rollback(&self, journal: &TransactionJournal) -> Result<(), IdentityError> {
        let account_id_valid = journal.account_id.len() == 21
            && journal.account_id.starts_with("acct_")
            && journal.account_id[5..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit());
        let ids_valid = (UID_MIN..UID_MAX_EXCLUSIVE).contains(&journal.uid)
            && (UID_MIN..UID_MAX_EXCLUSIVE).contains(&journal.gid);
        if !account_id_valid
            || !ids_valid
            || crate::protocol::validate_username(&journal.username).is_err()
        {
            return Err(IdentityError::Corrupt);
        }
        let account_dir = PathBuf::from(&journal.account_dir);
        let home_dir = PathBuf::from(&journal.home_dir);
        let account_parent_ok = account_dir.parent() == Some(self.paths.accounts_dir().as_path())
            && account_dir.file_name().and_then(|name| name.to_str())
                == Some(journal.account_id.as_str());
        let home_parent_ok = home_dir.parent() == Some(self.paths.home_root.as_path())
            && home_dir.file_name().and_then(|name| name.to_str())
                == Some(journal.username.as_str())
            && crate::protocol::validate_username(&journal.username).is_ok();
        if account_parent_ok {
            let _ = fs::remove_dir_all(&account_dir);
        }
        if home_parent_ok {
            let _ = fs::remove_dir_all(&home_dir);
        }
        let _ = fs::remove_dir_all(
            self.paths
                .accounts_dir()
                .join(format!(".txn-{}", journal.account_id)),
        );
        let _ = fs::remove_dir_all(
            self.paths
                .home_root
                .join(format!(".punar-{}", journal.account_id)),
        );
        let _ = fs::remove_file(self.paths.state_dir.join("device.json"));
        let _ = fs::remove_file(self.paths.first_login_dir.join(&journal.username));
        let _ = fs::remove_file(self.paths.marker());

        // A failure can land after the runtime drop-ins were published but
        // before the completion marker was committed. Remove every exact name
        // that transaction could have materialized, including numeric aliases
        // and supplementary-group edges. Without this, getent would keep
        // seeing a ghost account until reboot and the same username could not
        // be retried even though persistent state had been rolled back.
        for path in self.runtime_paths_for(journal) {
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    let _ = fs::remove_file(path);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => {}
            }
        }
        let _ = write_json_atomic(
            &self.paths.runtime_projection,
            &json!({"v": 1, "onboardingComplete": false, "accounts": []}),
            0o644,
        );
        let _ = write_json_atomic(
            &self.paths.runtime_onboarding,
            &json!({"v": 1, "complete": false}),
            0o644,
        );
        if !journal.original_hostname.is_empty() {
            let _ = self.platform.set_hostname(&journal.original_hostname);
        }
        let _ = fs::remove_file(self.paths.journal());
        Ok(())
    }

    fn runtime_paths_for(&self, journal: &TransactionJournal) -> Vec<PathBuf> {
        let mut paths = Vec::with_capacity(12);
        for (suffix, id) in [
            ("user", journal.uid),
            ("user-privileged", journal.uid),
            ("group", journal.gid),
        ] {
            paths.push(
                self.paths
                    .runtime_userdb
                    .join(format!("{}.{}", journal.username, suffix)),
            );
            paths.push(self.paths.runtime_userdb.join(format!("{id}.{suffix}")));
        }
        for group in ["punar", "video", "input"] {
            paths.push(
                self.paths
                    .runtime_userdb
                    .join(format!("{}:{group}.membership", journal.username)),
            );
        }
        paths.push(self.paths.runtime_subuid.clone());
        paths.push(self.paths.runtime_subgid.clone());
        paths
    }
}

fn existing_supplementary_groups<const N: usize>(
    platform: &dyn IdentityPlatform,
    names: [&str; N],
) -> Result<Vec<String>, IdentityError> {
    let mut groups = Vec::new();
    for name in names {
        if platform.lookup("group", name)?.is_some() {
            groups.push(name.to_string());
        }
    }
    Ok(groups)
}

fn allocate_uid_gid(platform: &dyn IdentityPlatform) -> Result<(u32, u32), IdentityError> {
    for id in UID_MIN..UID_MAX_EXCLUSIVE {
        if platform.lookup("passwd", &id.to_string())?.is_none()
            && platform.lookup("group", &id.to_string())?.is_none()
        {
            return Ok((id, id));
        }
    }
    Err(IdentityError::NoUid)
}

fn system_lookup(database: &str, key: &str) -> Result<Option<String>, IdentityError> {
    let output = Command::new("/usr/bin/getent")
        .args([database, key])
        .env_clear()
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(storage)?;
    if output.status.success() {
        String::from_utf8(output.stdout)
            .map(Some)
            .map_err(|_| IdentityError::Corrupt)
    } else if output.status.code() == Some(2) {
        Ok(None)
    } else {
        Err(IdentityError::Corrupt)
    }
}

fn lookup_gid(platform: &dyn IdentityPlatform, group: &str) -> Result<Option<u32>, IdentityError> {
    let Some(line) = platform.lookup("group", group)? else {
        return Ok(None);
    };
    Ok(line
        .split(':')
        .nth(2)
        .and_then(|gid| gid.trim().parse().ok()))
}

fn system_create_home(path: &Path, uid: u32, gid: u32) -> Result<(), IdentityError> {
    system_create_home_from(path, uid, gid, Path::new("/etc/skel"))
}

fn system_create_home_from(
    path: &Path,
    uid: u32,
    gid: u32,
    skeleton: &Path,
) -> Result<(), IdentityError> {
    if path.exists() {
        return Err(IdentityError::Home);
    }
    fs::create_dir(path).map_err(|_| IdentityError::Home)?;
    if skeleton.is_dir() {
        let status = Command::new("/usr/bin/cp")
            .args(["-a", "--"])
            .arg(skeleton.join("."))
            .arg(path)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| IdentityError::Home)?;
        if !status.success() {
            return Err(IdentityError::Home);
        }
    }
    system_finalize_home(path, uid, gid)
}

fn system_finalize_home(path: &Path, uid: u32, gid: u32) -> Result<(), IdentityError> {
    let status = Command::new("/usr/bin/chown")
        .args(["-R", "--", &format!("{uid}:{gid}")])
        .arg(path)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| IdentityError::Home)?;
    if !status.success() {
        return Err(IdentityError::Home);
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| IdentityError::Home)
}

fn system_set_hostname(hostname: &str) -> Result<(), IdentityError> {
    let status = Command::new("/usr/bin/punarctl")
        .args(["--json", "capabilities", "set", "system.hostname", hostname])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| IdentityError::Hostname)?;
    status
        .success()
        .then_some(())
        .ok_or(IdentityError::Hostname)
}

fn create_first_login_token(
    paths: &IdentityPaths,
    username: &str,
    account_id: &str,
) -> Result<(), IdentityError> {
    create_private_dir(&paths.first_login_dir)?;
    write_text_atomic(
        &paths.first_login_dir.join(username),
        &format!("v=1 account={account_id}\n"),
        0o600,
    )
}

pub fn consume_first_login(paths: &IdentityPaths, username: &str) -> bool {
    if crate::protocol::validate_username(username).is_err() {
        return false;
    }
    let token = paths.first_login_dir.join(username);
    let consumed = paths.first_login_dir.join(format!(
        ".consumed-{}",
        random_hex(4).unwrap_or_else(|_| "once".to_string())
    ));
    if fs::rename(&token, &consumed).is_err() {
        return false;
    }
    let secure = fs::metadata(&consumed)
        .map(|meta| meta.is_file() && meta.permissions().mode() & 0o777 == 0o600)
        .unwrap_or(false);
    let _ = fs::remove_file(consumed);
    secure
}

fn random_hex(bytes: usize) -> Result<String, IdentityError> {
    let mut raw = vec![0_u8; bytes];
    fill_random(&mut raw)?;
    let mut out = String::with_capacity(bytes * 2);
    for byte in raw {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("String writes do not fail");
    }
    Ok(out)
}

fn random_recovery_code() -> Result<String, IdentityError> {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
    let mut raw = Zeroizing::new([0_u8; 19]);
    fill_random(raw.as_mut())?;
    let mut out = String::with_capacity(35);
    let mut accumulator: u32 = 0;
    let mut bits = 0_u8;
    let mut emitted = 0_usize;
    for byte in raw.iter().copied() {
        accumulator = (accumulator << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 && emitted < 30 {
            bits -= 5;
            let index = ((accumulator >> bits) & 0x1f) as usize;
            if emitted > 0 && emitted % 5 == 0 {
                out.push('-');
            }
            out.push(ALPHABET[index] as char);
            emitted += 1;
        }
    }
    raw.zeroize();
    Ok(out)
}

fn fill_random(raw: &mut [u8]) -> Result<(), IdentityError> {
    let mut filled = 0;
    while filled < raw.len() {
        let count = getrandom(&mut raw[filled..], GetRandomFlags::empty())
            .map_err(|error| storage(io::Error::from_raw_os_error(error.raw_os_error())))?;
        if count == 0 {
            return Err(storage(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "getrandom",
            )));
        }
        filled += count;
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<(), IdentityError> {
    fs::create_dir_all(path).map_err(storage)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(storage)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T, mode: u32) -> Result<(), IdentityError> {
    let body = serde_json::to_vec_pretty(value).map_err(|_| IdentityError::Corrupt)?;
    write_bytes_atomic(path, &body, mode)
}

fn write_text_atomic(path: &Path, body: &str, mode: u32) -> Result<(), IdentityError> {
    write_bytes_atomic(path, body.as_bytes(), mode)
}

fn write_bytes_atomic(path: &Path, body: &[u8], mode: u32) -> Result<(), IdentityError> {
    let parent = path.parent().ok_or(IdentityError::Corrupt)?;
    fs::create_dir_all(parent).map_err(storage)?;
    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("record"),
        random_hex(4)?
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(&tmp)
        .map_err(storage)?;
    file.write_all(body).map_err(storage)?;
    file.write_all(b"\n").map_err(storage)?;
    file.sync_all().map_err(storage)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode)).map_err(storage)?;
    fs::rename(&tmp, path).map_err(storage)?;
    File::open(parent)
        .and_then(|dir| dir.sync_all())
        .map_err(storage)
}

fn copy_atomic(source: &Path, destination: &Path, mode: u32) -> Result<(), IdentityError> {
    let body = fs::read(source).map_err(storage)?;
    write_bytes_atomic(destination, &body, mode)
}

fn replace_symlink(target: &str, link: &Path) -> Result<(), IdentityError> {
    match fs::symlink_metadata(link) {
        Ok(_) => fs::remove_file(link).map_err(storage)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(storage(error)),
    }
    symlink(target, link).map_err(storage)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, IdentityError> {
    let file = File::open(path).map_err(storage)?;
    let mut body = Vec::new();
    file.take(128 * 1024 + 1)
        .read_to_end(&mut body)
        .map_err(storage)?;
    if body.len() > 128 * 1024 {
        return Err(IdentityError::Corrupt);
    }
    serde_json::from_slice(&body).map_err(|_| IdentityError::Corrupt)
}

fn read_trimmed(path: &Path) -> io::Result<String> {
    fs::read_to_string(path).map(|body| body.trim().to_string())
}

fn now_usec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn storage(error: io::Error) -> IdentityError {
    IdentityError::Storage(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use tempfile::TempDir;

    #[derive(Clone)]
    struct FakePlatform {
        hostname: Rc<RefCell<String>>,
        fail_after_materialize: Rc<Cell<bool>>,
    }

    impl FakePlatform {
        fn new(fail_after_materialize: bool) -> Self {
            Self {
                hostname: Rc::new(RefCell::new("original-host".to_string())),
                fail_after_materialize: Rc::new(Cell::new(fail_after_materialize)),
            }
        }
    }

    impl IdentityPlatform for FakePlatform {
        fn hash(&self, _secret: &str) -> Result<Zeroizing<String>, IdentityError> {
            Ok(Zeroizing::new("$y$j9T$testsalt$testhashvalue".to_string()))
        }

        fn lookup(&self, database: &str, key: &str) -> Result<Option<String>, IdentityError> {
            let value = match (database, key) {
                ("group", "punar") => Some("punar:x:900:".to_string()),
                ("group", "video") => Some("video:x:901:".to_string()),
                ("group", "input") => Some("input:x:902:".to_string()),
                ("passwd" | "group", _) => None,
                _ => return Err(IdentityError::Corrupt),
            };
            Ok(value)
        }

        fn current_hostname(&self) -> String {
            self.hostname.borrow().clone()
        }

        fn set_hostname(&self, hostname: &str) -> Result<(), IdentityError> {
            *self.hostname.borrow_mut() = hostname.to_string();
            Ok(())
        }

        fn create_home(&self, path: &Path, _uid: u32, _gid: u32) -> Result<(), IdentityError> {
            fs::create_dir(path).map_err(|_| IdentityError::Home)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| IdentityError::Home)
        }

        fn finalize_home(&self, path: &Path, _uid: u32, _gid: u32) -> Result<(), IdentityError> {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| IdentityError::Home)
        }

        fn after_runtime_materialized(&self) -> Result<(), IdentityError> {
            if self.fail_after_materialize.replace(false) {
                Err(storage(io::Error::other(
                    "injected post-materialize failure",
                )))
            } else {
                Ok(())
            }
        }
    }

    fn paths(temp: &TempDir) -> IdentityPaths {
        let root = temp.path();
        IdentityPaths {
            state_dir: root.join("var/identity"),
            onboarding_dir: root.join("var/onboarding"),
            runtime_userdb: root.join("run/userdb"),
            runtime_projection: root.join("run/punar/greeter.json"),
            runtime_onboarding: root.join("run/punar/onboarding.json"),
            runtime_subuid: root.join("run/punar/subuid"),
            runtime_subgid: root.join("run/punar/subgid"),
            first_login_dir: root.join("run/first-login"),
            home_root: root.join("home"),
        }
    }

    #[test]
    fn incomplete_first_run_exposes_no_account() {
        let temp = TempDir::new().unwrap();
        let store = IdentityStore::new(paths(&temp));
        store.materialize().unwrap();
        assert_eq!(
            fs::read_dir(temp.path().join("run/userdb"))
                .unwrap()
                .count(),
            0
        );
        let state: serde_json::Value =
            read_json(&temp.path().join("run/punar/onboarding.json")).unwrap();
        assert_eq!(state["complete"], false);
    }

    #[test]
    fn rollback_removes_runtime_account_and_preserves_unrelated_records() {
        let temp = TempDir::new().unwrap();
        let paths = paths(&temp);
        let store = IdentityStore::new(paths.clone());
        store.prepare_dirs().unwrap();
        let account_dir = paths.accounts_dir().join("acct_0011223344556677");
        let home_dir = paths.home_root.join("alice");
        fs::create_dir_all(&account_dir).unwrap();
        fs::create_dir_all(&home_dir).unwrap();
        for name in [
            "alice.user",
            "alice.user-privileged",
            "alice.group",
            "1000.user",
            "1000.user-privileged",
            "1000.group",
            "alice:punar.membership",
            "alice:video.membership",
            "alice:input.membership",
        ] {
            write_text_atomic(&paths.runtime_userdb.join(name), "{}", 0o600).unwrap();
        }
        write_text_atomic(&paths.runtime_userdb.join("daemon.user"), "{}", 0o644).unwrap();
        write_text_atomic(&paths.runtime_subuid, "alice:100000:65536", 0o644).unwrap();
        write_text_atomic(&paths.runtime_subgid, "alice:100000:65536", 0o644).unwrap();
        write_text_atomic(&paths.marker(), "{}", 0o600).unwrap();

        let journal = TransactionJournal {
            v: 1,
            account_id: "acct_0011223344556677".to_string(),
            username: "alice".to_string(),
            uid: 1000,
            gid: 1000,
            account_dir: account_dir.to_string_lossy().into_owned(),
            home_dir: home_dir.to_string_lossy().into_owned(),
            original_hostname: String::new(),
        };
        write_json_atomic(&paths.journal(), &journal, 0o600).unwrap();
        store.rollback(&journal).unwrap();

        assert!(!account_dir.exists());
        assert!(!home_dir.exists());
        assert!(!paths.marker().exists());
        assert!(paths.runtime_userdb.join("daemon.user").exists());
        assert_eq!(fs::read_dir(&paths.runtime_userdb).unwrap().count(), 1);
        assert!(!paths.runtime_subuid.exists());
        assert!(!paths.runtime_subgid.exists());
        let state: serde_json::Value = read_json(&paths.runtime_onboarding).unwrap();
        assert_eq!(state["complete"], false);
    }

    #[test]
    fn failure_after_materialization_is_atomic_and_retryable() {
        let temp = TempDir::new().unwrap();
        let paths = paths(&temp);
        fs::create_dir_all(&paths.home_root).unwrap();
        let platform = FakePlatform::new(true);
        let observer = platform.clone();
        let store = IdentityStore::with_platform(paths.clone(), Box::new(platform));

        let failed = store.create_first_account("alice", "three amber rivers", "Alice Workstation");
        assert!(failed.is_err());
        assert_eq!(observer.hostname.borrow().as_str(), "original-host");
        assert!(!paths.marker().exists());
        assert!(!paths.home_root.join("alice").exists());
        assert_eq!(
            fs::read_dir(paths.accounts_dir()).unwrap().count(),
            0,
            "no staged or committed account may survive"
        );
        assert_eq!(
            fs::read_dir(&paths.runtime_userdb).unwrap().count(),
            0,
            "no NSS-visible ghost may survive"
        );
        assert!(!paths.runtime_subuid.exists());
        assert!(!paths.runtime_subgid.exists());
        let state: serde_json::Value = read_json(&paths.runtime_onboarding).unwrap();
        assert_eq!(state["complete"], false);

        let created = store
            .create_first_account("alice", "three amber rivers", "Alice Workstation")
            .unwrap();
        assert_eq!(created.username, "alice");
        assert_eq!(observer.hostname.borrow().as_str(), "alice-workstation");
        assert!(paths.marker().exists());
        let home = paths.home_root.join("alice");
        assert!(home.is_dir());
        assert_eq!(
            fs::metadata(&home).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let home_marker = home.join(".local/state/punar/first-boot.json");
        let marker: CompletionMarker = read_json(&home_marker).unwrap();
        assert_eq!(marker.username, "alice");
        assert_eq!(marker.mode, "personal");
        assert_eq!(
            fs::metadata(home_marker).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(paths.runtime_userdb.join("alice.user").exists());
        assert!(paths.runtime_userdb.join("1000.user").is_symlink());
    }

    #[test]
    fn skeleton_metadata_cannot_reopen_the_home_directory() {
        use std::os::unix::fs::MetadataExt;

        let temp = TempDir::new().unwrap();
        let skeleton = temp.path().join("skel");
        fs::create_dir(&skeleton).unwrap();
        fs::set_permissions(&skeleton, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(skeleton.join("profile"), "private defaults\n").unwrap();

        let owner = fs::metadata(temp.path()).unwrap();
        let home = temp.path().join("alice");
        system_create_home_from(&home, owner.uid(), owner.gid(), &skeleton).unwrap();

        assert_eq!(
            fs::metadata(&home).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::read_to_string(home.join("profile")).unwrap(),
            "private defaults\n"
        );
    }

    #[test]
    fn first_login_token_is_single_use() {
        let temp = TempDir::new().unwrap();
        let paths = paths(&temp);
        create_first_login_token(&paths, "alice", "acct_0011").unwrap();
        assert!(consume_first_login(&paths, "alice"));
        assert!(!consume_first_login(&paths, "alice"));
        assert!(!consume_first_login(&paths, "../alice"));
    }

    #[test]
    fn recovery_code_has_six_unambiguous_groups() {
        let code = random_recovery_code().unwrap();
        let groups: Vec<_> = code.split('-').collect();
        assert_eq!(groups.len(), 6);
        assert!(groups.iter().all(|group| group.len() == 5));
        assert!(
            code.chars()
                .all(|ch| ch == '-' || "0123456789abcdefghjkmnpqrstvwxyz".contains(ch))
        );
    }
}
