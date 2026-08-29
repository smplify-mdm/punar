//! Bounded, cursor-based reads of netd's rate-limited kernel deny records.
//!
//! The journal supplies only a last refused destination for the purgeable
//! live view. Counts and audit transitions come from nftables counters, so a
//! rate-limited log can never weaken enforcement or under-count attempts.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::model::{validate_session_id, validate_zone_name};

const OUTPUT_LIMIT: u64 = 128 * 1024;
const MAX_CURSOR_BYTES: usize = 2048;
const MAX_ROWS: usize = 512;
static NEXT_READ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Error)]
pub enum DenyLogError {
    #[error("journal binary path {0:?} is not absolute")]
    RelativeBinary(PathBuf),
    #[error("journal operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("journal read timed out after {0:?}")]
    Timeout(Duration),
    #[error("journalctl refused the bounded read: {0}")]
    Rejected(String),
    #[error("stored journal cursor is malformed")]
    InvalidCursor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyRecord {
    pub session_id: String,
    pub zone: String,
    pub destination: IpAddr,
}

#[derive(Debug)]
pub struct DenyLogReader {
    journal_bin: PathBuf,
    cursor_file: PathBuf,
    work_dir: PathBuf,
    timeout: Duration,
}

impl DenyLogReader {
    pub fn production() -> Self {
        Self {
            journal_bin: PathBuf::from("/usr/bin/journalctl"),
            cursor_file: PathBuf::from("/var/lib/punar/network/journal-cursor"),
            work_dir: PathBuf::from("/var/lib/punar/network"),
            timeout: Duration::from_secs(8),
        }
    }

    pub fn new(
        journal_bin: PathBuf,
        cursor_file: PathBuf,
        work_dir: PathBuf,
        timeout: Duration,
    ) -> Self {
        Self {
            journal_bin,
            cursor_file,
            work_dir,
            timeout,
        }
    }

    /// Establish the tail cursor before any managed session can emit a deny.
    /// Existing boot history is deliberately not imported as current state.
    pub fn initialize(&self) -> Result<(), DenyLogError> {
        if self.cursor_file.exists() {
            let cursor = fs::read_to_string(&self.cursor_file)?;
            validate_cursor(cursor.trim())?;
            return Ok(());
        }
        let output = self.run(&["-k", "-n", "0", "--show-cursor", "--no-pager"])?;
        let cursor = output
            .lines()
            .find_map(|line| line.trim().strip_prefix("-- cursor: "))
            .ok_or(DenyLogError::InvalidCursor)?;
        validate_cursor(cursor)?;
        write_atomic(&self.cursor_file, cursor.as_bytes(), 0o600)?;
        Ok(())
    }

    pub fn read_new(&self) -> Result<Vec<DenyRecord>, DenyLogError> {
        self.initialize()?;
        let cursor = fs::read_to_string(&self.cursor_file)?;
        let cursor = cursor.trim();
        validate_cursor(cursor)?;
        let after = format!("--after-cursor={cursor}");
        let output = self.run(&["-k", "-o", "json", "--no-pager", "-n", "512", &after])?;
        parse_rows(&output, &self.cursor_file)
    }

    fn run(&self, args: &[&str]) -> Result<String, DenyLogError> {
        if !self.journal_bin.is_absolute() {
            return Err(DenyLogError::RelativeBinary(self.journal_bin.clone()));
        }
        fs::create_dir_all(&self.work_dir)?;
        let id = NEXT_READ.fetch_add(1, Ordering::Relaxed);
        let stem = format!(".punar-netd-journal-{}-{id}", std::process::id());
        let stdout_path = self.work_dir.join(format!("{stem}.stdout"));
        let stderr_path = self.work_dir.join(format!("{stem}.stderr"));
        let cleanup = Cleanup([stdout_path.clone(), stderr_path.clone()]);
        let stdout = create_private(&stdout_path)?;
        let stderr = create_private(&stderr_path)?;
        let mut child = Command::new(&self.journal_bin)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()?;
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(DenyLogError::Timeout(self.timeout));
            }
            thread::sleep(Duration::from_millis(10));
        };
        let stdout = read_bounded(&stdout_path)?;
        let stderr = read_bounded(&stderr_path)?;
        drop(cleanup);
        if !status.success() {
            return Err(DenyLogError::Rejected(if stderr.trim().is_empty() {
                "journalctl exited nonzero without an error message".to_string()
            } else {
                stderr.trim().to_string()
            }));
        }
        Ok(stdout)
    }
}

fn parse_rows(input: &str, cursor_file: &Path) -> Result<Vec<DenyRecord>, DenyLogError> {
    let mut records = Vec::new();
    let mut last_cursor = None;
    for line in input.lines().take(MAX_ROWS) {
        let Ok(row) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if let Some(cursor) = row.get("__CURSOR").and_then(serde_json::Value::as_str)
            && validate_cursor(cursor).is_ok()
        {
            last_cursor = Some(cursor.to_string());
        }
        let Some(message) = row.get("MESSAGE").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if let Some(record) = parse_message(message) {
            records.push(record);
        }
    }
    if let Some(cursor) = last_cursor {
        write_atomic(cursor_file, cursor.as_bytes(), 0o600)?;
    }
    Ok(records)
}

fn parse_message(message: &str) -> Option<DenyRecord> {
    let rest = message.strip_prefix("punar-net deny ")?;
    let mut fields = rest.split_whitespace();
    let zone = fields.next()?;
    let tag = fields.next()?;
    validate_zone_name(zone).ok()?;
    let session_id = format!("agt_{tag}");
    validate_session_id(&session_id).ok()?;
    let destination = fields
        .find_map(|field| field.strip_prefix("DST="))?
        .parse::<IpAddr>()
        .ok()?;
    Some(DenyRecord {
        session_id,
        zone: zone.to_string(),
        destination,
    })
}

fn validate_cursor(cursor: &str) -> Result<(), DenyLogError> {
    if cursor.is_empty()
        || cursor.len() > MAX_CURSOR_BYTES
        || cursor
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(DenyLogError::InvalidCursor);
    }
    Ok(())
}

fn read_bounded(path: &Path) -> io::Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(OUTPUT_LIMIT)
        .read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn create_private(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".journal-cursor.tmp.{}-{}",
        std::process::id(),
        NEXT_READ.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.flush()?;
    drop(file);
    fs::rename(&temporary, path).inspect_err(|_| {
        let _ = fs::remove_file(&temporary);
    })
}

struct Cleanup([PathBuf; 2]);

impl Drop for Cleanup {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn root() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "punar-netd-deny-{}-{}",
            std::process::id(),
            NEXT_READ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn parser_accepts_only_the_closed_prefix_and_destination_field() {
        let record =
            parse_message("punar-net deny corp_prod 4f21c09ab3e1 IN= OUT=lo DST=127.0.0.7 LEN=60")
                .unwrap();
        assert_eq!(record.session_id, "agt_4f21c09ab3e1");
        assert_eq!(record.zone, "corp_prod");
        assert_eq!(record.destination, "127.0.0.7".parse::<IpAddr>().unwrap());
        for bad in [
            "other deny corp_prod tag DST=127.0.0.7",
            "punar-net deny corp-prod tag DST=127.0.0.7",
            "punar-net deny corp_prod tag DST=https://example.com",
        ] {
            assert!(parse_message(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn cursor_read_is_fixed_bounded_and_advances_on_non_deny_rows() {
        let root = root();
        let binary = root.join("journalctl");
        fs::write(
            &binary,
            r#"#!/bin/sh
printf '%s\n' "$@" > "$0.args"
if printf '%s\n' "$@" | grep -q -- '--show-cursor'; then
  printf '%s\n' '-- cursor: s=first;i=1'
else
  printf '%s\n' '{"__CURSOR":"s=next;i=2","MESSAGE":"punar-net deny corp_prod 4f21 IN= OUT=lo DST=127.0.0.7"}'
fi
"#,
        )
        .unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        let reader = DenyLogReader::new(
            binary.clone(),
            root.join("cursor"),
            root.clone(),
            Duration::from_secs(1),
        );
        let rows = reader.read_new().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            fs::read_to_string(root.join("cursor")).unwrap(),
            "s=next;i=2"
        );
        let args = fs::read_to_string(binary.with_file_name("journalctl.args")).unwrap();
        assert!(args.contains("--after-cursor=s=first;i=1"));
        assert!(args.contains("-n\n512"));
        fs::remove_dir_all(root).unwrap();
    }
}
