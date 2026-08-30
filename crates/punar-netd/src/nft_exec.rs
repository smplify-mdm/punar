//! Bounded, fixed-argument execution of nftables transactions.
//!
//! Generated rules are handed to `/usr/bin/nft -f <file>` through a
//! root-owned `0600` file. There is no shell, user-controlled argv, stdin
//! program, or shared temporary directory at this privilege boundary.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;

static NEXT_TRANSACTION: AtomicU64 = AtomicU64::new(1);
const OUTPUT_LIMIT: u64 = 64 * 1024;
const PROBE_TABLE: &str = "punar-net-probe";
// Linux may briefly return ETXTBSY (errno 26) while an executable is being
// atomically replaced. Keep the retry deliberately short and bounded so an
// update cannot turn a policy operation into an unbounded wait.
const EXECUTABLE_FILE_BUSY_ERRNO: i32 = 26;
const SPAWN_BUSY_ATTEMPTS: usize = 8;
const SPAWN_BUSY_BACKOFF: Duration = Duration::from_millis(10);

#[derive(Debug, Error)]
pub enum ExecError {
    #[error("nft binary path {0:?} is not absolute")]
    RelativeBinary(PathBuf),
    #[error("transaction directory {0:?} is not a real directory")]
    UnsafeDirectory(PathBuf),
    #[error("transaction directory {path:?} is owned by uid {actual}, expected {expected}")]
    WrongOwner {
        path: PathBuf,
        actual: u32,
        expected: u32,
    },
    #[error("transaction directory {path:?} is writable by group or others (mode {mode:o})")]
    UnsafeMode { path: PathBuf, mode: u32 },
    #[error("transaction file operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("nft transaction timed out after {0:?}")]
    Timeout(Duration),
    #[error("nft rejected the transaction: {0}")]
    Rejected(String),
    #[error("nft returned an invalid counter document: {0}")]
    InvalidCounterDocument(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementCapability {
    Available,
    Unavailable { reason: String },
}

#[derive(Debug, Clone)]
pub struct NftExecutor {
    nft_bin: PathBuf,
    transaction_dir: PathBuf,
    trusted_uid: u32,
    timeout: Duration,
}

impl NftExecutor {
    /// Production executor. `/var/lib/punar/network` is provisioned
    /// `0750 root:punar`; every transaction file is additionally `0600`.
    pub fn production() -> Self {
        Self {
            nft_bin: PathBuf::from("/usr/bin/nft"),
            transaction_dir: PathBuf::from("/var/lib/punar/network"),
            trusted_uid: 0,
            timeout: Duration::from_secs(8),
        }
    }

    pub fn new(
        nft_bin: PathBuf,
        transaction_dir: PathBuf,
        trusted_uid: u32,
        timeout: Duration,
    ) -> Self {
        Self {
            nft_bin,
            transaction_dir,
            trusted_uid,
            timeout,
        }
    }

    pub fn apply(&self, ruleset: &str) -> Result<CommandResult, ExecError> {
        if !self.nft_bin.is_absolute() {
            return Err(ExecError::RelativeBinary(self.nft_bin.clone()));
        }
        validate_directory(&self.transaction_dir, self.trusted_uid)?;
        let files = TransactionFiles::create(&self.transaction_dir)?;
        {
            let mut input = files.open_input()?;
            input.write_all(ruleset.as_bytes())?;
            input.flush()?;
        }
        let stdout = files.open_stdout()?;
        let stderr = files.open_stderr()?;
        let mut child = spawn_with_executable_busy_retry(|| {
            Command::new(&self.nft_bin)
                .arg("-f")
                .arg(&files.input)
                .stdin(Stdio::null())
                .stdout(Stdio::from(stdout.try_clone()?))
                .stderr(Stdio::from(stderr.try_clone()?))
                .spawn()
        })?;
        let status = wait_bounded(&mut child, self.timeout)?;
        let result = CommandResult {
            success: status.success(),
            stdout: read_bounded(&files.stdout)?,
            stderr: read_bounded(&files.stderr)?,
        };
        Ok(result)
    }

    pub fn apply_checked(&self, ruleset: &str) -> Result<(), ExecError> {
        let result = self.apply(ruleset)?;
        if result.success {
            Ok(())
        } else {
            let reason = result.stderr.trim();
            Err(ExecError::Rejected(if reason.is_empty() {
                "nft exited nonzero without an error message".to_string()
            } else {
                reason.to_string()
            }))
        }
    }

    /// Read only the named counters from netd's own table. The argv is
    /// fixed, output is bounded by the same private-file mechanism as a
    /// transaction, and unknown nft JSON objects are never interpreted as
    /// policy state.
    pub fn query_named_counters(&self) -> Result<BTreeMap<String, u64>, ExecError> {
        if !self.nft_bin.is_absolute() {
            return Err(ExecError::RelativeBinary(self.nft_bin.clone()));
        }
        validate_directory(&self.transaction_dir, self.trusted_uid)?;
        let files = TransactionFiles::create(&self.transaction_dir)?;
        let stdout = files.open_stdout()?;
        let stderr = files.open_stderr()?;
        let mut child = spawn_with_executable_busy_retry(|| {
            Command::new(&self.nft_bin)
                .args(["-j", "list", "table", "inet", "punar-net"])
                .stdin(Stdio::null())
                .stdout(Stdio::from(stdout.try_clone()?))
                .stderr(Stdio::from(stderr.try_clone()?))
                .spawn()
        })?;
        let status = wait_bounded(&mut child, self.timeout)?;
        let stdout = read_bounded(&files.stdout)?;
        let stderr = read_bounded(&files.stderr)?;
        if !status.success() {
            // The table does not exist before the first successful apply.
            // That is an empty observation, not an enforcement failure.
            if stderr.contains("No such file") || stderr.contains("does not exist") {
                return Ok(BTreeMap::new());
            }
            return Err(ExecError::Rejected(if stderr.trim().is_empty() {
                "nft counter query exited nonzero without an error message".to_string()
            } else {
                stderr.trim().to_string()
            }));
        }
        parse_named_counters(&stdout)
    }

    /// Whether netd's owned table currently exists. This is a fixed-argv,
    /// bounded health read used by on-demand connection passes to repair a
    /// table removed behind the daemon's back. It never inspects or touches
    /// punard's `punar-base` table.
    pub fn table_exists(&self) -> Result<bool, ExecError> {
        if !self.nft_bin.is_absolute() {
            return Err(ExecError::RelativeBinary(self.nft_bin.clone()));
        }
        validate_directory(&self.transaction_dir, self.trusted_uid)?;
        let files = TransactionFiles::create(&self.transaction_dir)?;
        let stdout = files.open_stdout()?;
        let stderr = files.open_stderr()?;
        let mut child = spawn_with_executable_busy_retry(|| {
            Command::new(&self.nft_bin)
                .args(["-j", "list", "table", "inet", "punar-net"])
                .stdin(Stdio::null())
                .stdout(Stdio::from(stdout.try_clone()?))
                .stderr(Stdio::from(stderr.try_clone()?))
                .spawn()
        })?;
        let status = wait_bounded(&mut child, self.timeout)?;
        let stderr = read_bounded(&files.stderr)?;
        if status.success() {
            return Ok(true);
        }
        if stderr.contains("No such file") || stderr.contains("does not exist") {
            return Ok(false);
        }
        Err(ExecError::Rejected(if stderr.trim().is_empty() {
            "nft table health query exited nonzero without an error message".to_string()
        } else {
            stderr.trim().to_string()
        }))
    }

    /// Prove that this nft/kernel pair accepts cgroup-v2 socket matching.
    /// The throwaway table is created and destroyed inside one transaction,
    /// so success leaves no live policy behind.
    pub fn probe_cgroup_v2(&self) -> EnforcementCapability {
        let ruleset = format!(
            "destroy table inet {PROBE_TABLE}\n\
             table inet {PROBE_TABLE} {{\n\
               chain probe {{\n\
                 type filter hook output priority filter - 11; policy accept;\n\
                 socket cgroupv2 level 1 \"user.slice\" counter\n\
               }}\n\
             }}\n\
             destroy table inet {PROBE_TABLE}\n"
        );
        match self.apply_checked(&ruleset) {
            Ok(()) => EnforcementCapability::Available,
            Err(error) => EnforcementCapability::Unavailable {
                reason: error.to_string(),
            },
        }
    }
}

fn parse_named_counters(input: &str) -> Result<BTreeMap<String, u64>, ExecError> {
    let document: serde_json::Value = serde_json::from_str(input)
        .map_err(|error| ExecError::InvalidCounterDocument(error.to_string()))?;
    let rows = document
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| ExecError::InvalidCounterDocument("missing nftables array".into()))?;
    let mut counters = BTreeMap::new();
    for row in rows {
        let Some(counter) = row.get("counter").and_then(serde_json::Value::as_object) else {
            continue;
        };
        if counter.get("family").and_then(serde_json::Value::as_str) != Some("inet")
            || counter.get("table").and_then(serde_json::Value::as_str) != Some("punar-net")
        {
            continue;
        }
        let Some(name) = counter.get("name").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if !valid_counter_name(name) {
            return Err(ExecError::InvalidCounterDocument(format!(
                "unsafe named counter {name:?}"
            )));
        }
        let packets = counter
            .get("packets")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ExecError::InvalidCounterDocument(format!(
                    "counter {name:?} has no unsigned packet total"
                ))
            })?;
        counters.insert(name.to_string(), packets);
    }
    Ok(counters)
}

fn valid_counter_name(name: &str) -> bool {
    name.starts_with("c_")
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn validate_directory(path: &Path, trusted_uid: u32) -> Result<(), ExecError> {
    let metadata = fs::symlink_metadata(path).map_err(ExecError::Io)?;
    if !metadata.file_type().is_dir() {
        return Err(ExecError::UnsafeDirectory(path.to_path_buf()));
    }
    if metadata.uid() != trusted_uid {
        return Err(ExecError::WrongOwner {
            path: path.to_path_buf(),
            actual: metadata.uid(),
            expected: trusted_uid,
        });
    }
    let mode = metadata.mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(ExecError::UnsafeMode {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

fn wait_bounded(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<ExitStatus, ExecError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ExecError::Timeout(timeout));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn spawn_with_executable_busy_retry<F>(mut spawn: F) -> io::Result<Child>
where
    F: FnMut() -> io::Result<Child>,
{
    for attempt in 0..SPAWN_BUSY_ATTEMPTS {
        match spawn() {
            Ok(child) => return Ok(child),
            Err(error)
                if error.raw_os_error() == Some(EXECUTABLE_FILE_BUSY_ERRNO)
                    && attempt + 1 < SPAWN_BUSY_ATTEMPTS =>
            {
                thread::sleep(SPAWN_BUSY_BACKOFF);
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("the bounded spawn loop always returns on its final attempt")
}

fn read_bounded(path: &Path) -> io::Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(OUTPUT_LIMIT)
        .read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[derive(Debug)]
struct TransactionFiles {
    input: PathBuf,
    stdout: PathBuf,
    stderr: PathBuf,
}

impl TransactionFiles {
    fn create(directory: &Path) -> io::Result<Self> {
        for _ in 0..8 {
            let id = NEXT_TRANSACTION.fetch_add(1, Ordering::Relaxed);
            let stem = format!(".punar-netd-txn-{}-{id}", std::process::id());
            let files = Self {
                input: directory.join(format!("{stem}.nft")),
                stdout: directory.join(format!("{stem}.stdout")),
                stderr: directory.join(format!("{stem}.stderr")),
            };
            match open_exclusive(&files.input) {
                Ok(file) => {
                    drop(file);
                    return Ok(files);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not reserve a unique nft transaction file",
        ))
    }

    fn open_input(&self) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.input)
    }

    fn open_stdout(&self) -> io::Result<File> {
        open_exclusive(&self.stdout)
    }

    fn open_stderr(&self) -> io::Result<File> {
        open_exclusive(&self.stderr)
    }
}

impl Drop for TransactionFiles {
    fn drop(&mut self) {
        for path in [&self.input, &self.stdout, &self.stderr] {
            let _ = fs::remove_file(path);
        }
    }
}

fn open_exclusive(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn transaction_fixture() -> (PathBuf, u32) {
        let root = std::env::temp_dir().join(format!(
            "punar-netd-nft-exec-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let transaction_dir = root.join("transactions");
        fs::create_dir_all(&transaction_dir).unwrap();
        fs::set_permissions(&transaction_dir, fs::Permissions::from_mode(0o750)).unwrap();
        let uid = fs::symlink_metadata(&transaction_dir).unwrap().uid();
        (transaction_dir, uid)
    }

    fn fixture(script: &str) -> (PathBuf, PathBuf, u32) {
        let (transaction_dir, uid) = transaction_fixture();
        let root = transaction_dir.parent().unwrap();
        let binary = root.join("fake-nft");
        write_executable(&binary, script);
        (binary, transaction_dir, uid)
    }

    // A few ARM overlayfs runners have returned ETXTBSY when a just-closed
    // writable inode is immediately executed. Publish the test double the
    // same safe way production software is updated: fully write and fsync an
    // unreferenced inode, set its final mode, then rename it into place. This
    // also makes the table-health rewrites race-free with process teardown.
    fn write_executable(path: &Path, script: &str) {
        let staged = path.with_extension("staged");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(&staged)
            .unwrap();
        file.write_all(script.as_bytes()).unwrap();
        file.sync_all().unwrap();
        drop(file);
        fs::rename(staged, path).unwrap();
    }

    #[test]
    fn transaction_uses_only_fixed_f_argv_and_root_private_file() {
        let script = r#"#!/bin/sh
printf '%s\n' "$@" > "$0.args"
cp "$2" "$0.rules"
stat -c '%a' "$2" > "$0.mode"
"#;
        let (binary, directory, uid) = fixture(script);
        let executor = NftExecutor::new(
            binary.clone(),
            directory.clone(),
            uid,
            Duration::from_secs(1),
        );
        executor
            .apply_checked("table inet punar-net { chain egress { } }\n")
            .unwrap();
        let args = fs::read_to_string(binary.with_file_name("fake-nft.args")).unwrap();
        let lines: Vec<_> = args.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "-f");
        assert!(lines[1].starts_with(directory.to_str().unwrap()));
        assert_eq!(
            fs::read_to_string(binary.with_file_name("fake-nft.mode"))
                .unwrap()
                .trim(),
            "600"
        );
        assert_eq!(
            fs::read_to_string(binary.with_file_name("fake-nft.rules")).unwrap(),
            "table inet punar-net { chain egress { } }\n"
        );
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        fs::remove_dir_all(binary.parent().unwrap()).unwrap();
    }

    #[test]
    fn nonzero_and_timeout_are_failures_not_successes() {
        // `/bin/sh -f <transaction>` is a stable test double for the fixed
        // `nft -f <transaction>` argv. Keeping the executable immutable
        // removes executable-creation and rewrite timing from this assertion;
        // only this test's transaction contents are shell syntax.
        let (directory, uid) = transaction_fixture();
        let executor = NftExecutor::new(
            PathBuf::from("/bin/sh"),
            directory.clone(),
            uid,
            Duration::from_secs(1),
        );
        assert!(matches!(
            executor.apply_checked("echo refused >&2\nexit 9\n"),
            Err(ExecError::Rejected(reason)) if reason == "refused"
        ));
        assert!(matches!(
            NftExecutor::new(
                PathBuf::from("/bin/sh"),
                directory.clone(),
                uid,
                Duration::from_millis(20),
            )
            .apply_checked("sleep 1\n"),
            Err(ExecError::Timeout(_))
        ));
        fs::remove_dir_all(directory.parent().unwrap()).unwrap();
    }

    #[test]
    fn writable_or_wrong_owner_directory_is_refused_before_spawn() {
        let (binary, directory, uid) = fixture("#!/bin/sh\nexit 0\n");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
        let executor = NftExecutor::new(
            binary.clone(),
            directory.clone(),
            uid,
            Duration::from_secs(1),
        );
        assert!(matches!(
            executor.apply("x"),
            Err(ExecError::UnsafeMode { .. })
        ));
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o750)).unwrap();
        let wrong = NftExecutor::new(binary.clone(), directory, uid + 1, Duration::from_secs(1));
        assert!(matches!(
            wrong.apply("x"),
            Err(ExecError::WrongOwner { .. })
        ));
        fs::remove_dir_all(binary.parent().unwrap()).unwrap();
    }

    #[test]
    fn capability_probe_is_ephemeral_and_reports_failure_honestly() {
        let script = r#"#!/bin/sh
cp "$2" "$0.rules"
"#;
        let (binary, directory, uid) = fixture(script);
        let executor = NftExecutor::new(binary.clone(), directory, uid, Duration::from_secs(1));
        assert_eq!(executor.probe_cgroup_v2(), EnforcementCapability::Available);
        let rules = fs::read_to_string(binary.with_file_name("fake-nft.rules")).unwrap();
        assert!(rules.contains("socket cgroupv2 level 1 \"user.slice\" counter"));
        assert!(rules.ends_with("destroy table inet punar-net-probe\n"));
        let (failure_binary, failure_directory, failure_uid) =
            fixture("#!/bin/sh\necho unsupported >&2\nexit 1\n");
        assert!(matches!(
            NftExecutor::new(
                failure_binary.clone(),
                failure_directory,
                failure_uid,
                Duration::from_secs(1),
            )
            .probe_cgroup_v2(),
            EnforcementCapability::Unavailable { reason } if reason.contains("unsupported")
        ));
        fs::remove_dir_all(binary.parent().unwrap()).unwrap();
        fs::remove_dir_all(failure_binary.parent().unwrap()).unwrap();
    }

    #[test]
    fn counter_query_uses_fixed_argv_and_accepts_only_our_named_counters() {
        let script = r#"#!/bin/sh
printf '%s\n' "$@" > "$0.args"
printf '%s\n' '{"nftables":[{"metainfo":{"json_schema_version":1}},{"counter":{"family":"inet","name":"c_4f21_internet_allow","table":"punar-net","packets":7,"bytes":511}},{"counter":{"family":"inet","name":"ignored","table":"other","packets":99,"bytes":1}}]}'
"#;
        let (binary, directory, uid) = fixture(script);
        let executor = NftExecutor::new(binary.clone(), directory, uid, Duration::from_secs(1));
        assert_eq!(
            executor.query_named_counters().unwrap(),
            BTreeMap::from([("c_4f21_internet_allow".to_string(), 7)])
        );
        assert_eq!(
            fs::read_to_string(binary.with_file_name("fake-nft.args")).unwrap(),
            "-j\nlist\ntable\ninet\npunar-net\n"
        );
        fs::remove_dir_all(binary.parent().unwrap()).unwrap();
    }

    #[test]
    fn executable_busy_spawn_is_retried_then_succeeds() {
        let mut attempts = 0;
        let mut child = spawn_with_executable_busy_retry(|| {
            attempts += 1;
            if attempts < 4 {
                return Err(io::Error::from_raw_os_error(EXECUTABLE_FILE_BUSY_ERRNO));
            }
            Command::new("/bin/true").spawn()
        })
        .unwrap();
        assert!(child.wait().unwrap().success());
        assert_eq!(attempts, 4);
    }

    #[test]
    fn table_health_read_distinguishes_absent_from_query_failure() {
        let (binary, directory, uid) = fixture("#!/bin/sh\nexit 0\n");
        let executor = NftExecutor::new(
            binary.clone(),
            directory.clone(),
            uid,
            Duration::from_secs(1),
        );
        assert!(executor.table_exists().unwrap());
        write_executable(
            &binary,
            "#!/bin/sh\necho 'No such file or directory' >&2\nexit 1\n",
        );
        assert!(!executor.table_exists().unwrap());
        write_executable(&binary, "#!/bin/sh\necho permission-refused >&2\nexit 1\n");
        assert!(matches!(
            executor.table_exists(),
            Err(ExecError::Rejected(reason)) if reason == "permission-refused"
        ));
        fs::remove_dir_all(binary.parent().unwrap()).unwrap();
    }

    #[test]
    fn counter_parser_refuses_statement_material_and_bad_packet_types() {
        for body in [
            r#"{"nftables":[{"counter":{"family":"inet","table":"punar-net","name":"c_ok;flush","packets":1}}]}"#,
            r#"{"nftables":[{"counter":{"family":"inet","table":"punar-net","name":"c_ok","packets":"1"}}]}"#,
        ] {
            assert!(matches!(
                parse_named_counters(body),
                Err(ExecError::InvalidCounterDocument(_))
            ));
        }
    }
}
