//! What the mock **received** — the side m5-check asserts directly.
//!
//! `StateDirectory=punar-mock-smplify` → `/var/lib/punar-mock-smplify/`
//! (milestone-5.md section 4.5):
//!
//! - `devices.json` — `{device_id: {device_token, registered_at,
//!   attestation}}`, atomic rewrite (tmp + rename), mode 0600;
//! - `received-compliance.jsonl` / `received-inventory.jsonl` —
//!   append-only, one received report per line with `received_at` and the
//!   token-resolved `device_id`;
//! - `queries.json` — the M10 pending-query queue (milestone-10.md section
//!   13.3), atomic rewrite, mode 0600;
//! - `received-answers.jsonl` — append-only, exactly what each device
//!   returned, verbatim;
//! - `received-recovery-envelopes.jsonl` — tenant-wrapped recovery
//!   envelopes, never plaintext keys;
//! - `recovery-releases.jsonl` — append-only operator/device/reason/outcome
//!   audit for the dev recovery-release proof, never recovery material.
//!
//! The queue is the whole of the M10 "push": there is none. An
//! administrator's question sits here until **the device comes and gets
//! it** on its own sync cadence (milestone-10.md sections 7.2, law 1).
//! Nothing in this file, or anywhere else in this crate, dials a device.
//!
//! State **persists across restarts** deliberately: the m5-check offline
//! stop→start must not invalidate the device token, and the history kept
//! after unenroll is the honest record that M5 unenrollment is local-only.
//! Tokens are persisted in the clear on the *server* side — the mock is the
//! issuer, the directory is root-owned 0700, and `Redacted` protects
//! `punard`'s client-side copy, not the counterparty's ledger.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use punar_common::time::utc_now_rfc3339;
use punar_recovery::RecoveryEnvelope;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The literal attestation value this mock issues — nothing is measured,
/// quoted, or verified, and every surface that stores or renders it says so
/// (milestone-5.md section 3).
pub const ATTESTATION_SIMULATED: &str = "simulated";

/// One registered device, as persisted in `devices.json`.
///
/// `last_sync` / `compliance_state` are the M10 additions the admin surface
/// renders (`admin.devices`, milestone-10.md section 13.3). Both are
/// `#[serde(default)]` so a `devices.json` written by the M5 build still
/// loads — a mock that un-registered every device on upgrade would break
/// the check it exists to serve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRecord {
    pub device_token: String,
    pub registered_at: String,
    pub attestation: String,
    /// When this device last reported anything (compliance or inventory).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sync: Option<String>,
    /// The `overall` value of the last compliance report — a **category
    /// state**, which is all a device ever sends (SPEC sections 24, 54).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance_state: Option<String>,
}

/// The received-state store: registered devices in memory + on disk, and
/// the two append-only report logs.
#[derive(Debug)]
pub struct StateStore {
    dir: PathBuf,
    devices: BTreeMap<String, DeviceRecord>,
    queries: Vec<QueryEntry>,
    query_seq: u64,
}

impl StateStore {
    /// Open (creating if needed) the state directory and load any existing
    /// `devices.json`. A corrupt ledger fails loudly — silently starting
    /// empty would un-register devices behind the check's back.
    pub fn open(dir: &Path) -> io::Result<StateStore> {
        std::fs::create_dir_all(dir)?;
        // 0700: received reports are org-side records; nothing but root
        // (the check) reads them. Best-effort — systemd's StateDirectory
        // already owns the mode in the image.
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        let devices_path = dir.join(DEVICES_FILE);
        let devices = if devices_path.exists() {
            let bytes = std::fs::read(&devices_path)?;
            serde_json::from_slice(&bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: corrupt device ledger: {e}", devices_path.display()),
                )
            })?
        } else {
            BTreeMap::new()
        };
        let queries = load_queries(&dir.join(QUERIES_FILE))?;
        let query_seq = queries.len() as u64;
        Ok(StateStore {
            dir: dir.to_path_buf(),
            devices,
            queries,
            query_seq,
        })
    }

    /// Register (or re-register) a device: mint a fresh token, record it,
    /// persist atomically, and return the token. Re-registering a known
    /// `device_id` **rotates** the token — idempotent re-enroll, and the
    /// old token stops working (milestone-5.md section 4.3).
    pub fn register(&mut self, device_id: &str) -> io::Result<String> {
        let token = generate_device_token()?;
        self.devices.insert(
            device_id.to_string(),
            DeviceRecord {
                device_token: token.clone(),
                registered_at: utc_now_rfc3339(),
                attestation: ATTESTATION_SIMULATED.to_string(),
                last_sync: None,
                compliance_state: None,
            },
        );
        self.save_devices()?;
        Ok(token)
    }

    /// Resolve a presented token to its `device_id`, or `None` when no
    /// registered device carries it. Plain comparison — this mock is not an
    /// authority and does not pretend to constant-time secret handling.
    pub fn device_for_token(&self, token: &str) -> Option<&str> {
        self.devices
            .iter()
            .find(|(_, record)| record.device_token == token)
            .map(|(id, _)| id.as_str())
    }

    /// Number of registered devices (startup log line).
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Append one received compliance report:
    /// `{"received_at", "device_id", "report"}` as a single JSONL line, and
    /// stamp the device row with the report's `overall` **state** (never a
    /// value — SPEC sections 24, 54) so `admin.devices` has something
    /// honest to render.
    pub fn append_compliance(&mut self, device_id: &str, report: &Value) -> io::Result<()> {
        let overall = report
            .get("overall")
            .and_then(Value::as_str)
            .map(str::to_string);
        self.stamp_sync(device_id, overall)?;
        self.append_line(
            COMPLIANCE_FILE,
            json!({
                "received_at": utc_now_rfc3339(),
                "device_id": device_id,
                "report": report,
            }),
        )
    }

    /// Append one received inventory report:
    /// `{"received_at", "device_id", "inventory"}` as a single JSONL line.
    pub fn append_inventory(&mut self, device_id: &str, inventory: &Value) -> io::Result<()> {
        self.stamp_sync(device_id, None)?;
        self.append_line(
            INVENTORY_FILE,
            json!({
                "received_at": utc_now_rfc3339(),
                "device_id": device_id,
                "inventory": inventory,
            }),
        )
    }

    /// Store exactly the tenant-wrapped envelope. The append-only custody
    /// file never receives plaintext; the mock's separate, RBAC-gated release
    /// path unwraps only after loading an envelope from this store.
    pub fn append_recovery_envelope(
        &mut self,
        device_id: &str,
        envelope: &RecoveryEnvelope,
    ) -> io::Result<()> {
        self.append_line(
            RECOVERY_ENVELOPES_FILE,
            json!({
                "received_at": utc_now_rfc3339(),
                "device_id": device_id,
                "envelope": envelope,
            }),
        )
    }

    /// Read the newest wrapped envelope for one device. Corrupt custody
    /// fails loudly; silently skipping a damaged line could release an old
    /// key after rotation.
    pub fn latest_recovery_envelope(
        &self,
        device_id: &str,
    ) -> io::Result<Option<RecoveryEnvelope>> {
        let path = self.dir.join(RECOVERY_ENVELOPES_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&path)?;
        for line in text.lines().rev() {
            let value: Value = serde_json::from_str(line).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: corrupt recovery custody: {e}", path.display()),
                )
            })?;
            if value.get("device_id").and_then(Value::as_str) == Some(device_id) {
                let envelope = value.get("envelope").cloned().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: recovery custody line has no envelope", path.display()),
                    )
                })?;
                return serde_json::from_value(envelope).map(Some).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: malformed recovery envelope: {e}", path.display()),
                    )
                });
            }
        }
        Ok(None)
    }

    /// Append the non-secret audit record before returning from a recovery
    /// release attempt. `reason` is a short validated reason code, not free
    /// text, and `outcome` is chosen by the server.
    pub fn append_recovery_release(
        &self,
        operator: &str,
        device_id: &str,
        reason: &str,
        outcome: &str,
    ) -> io::Result<()> {
        self.append_line(
            RECOVERY_RELEASES_FILE,
            json!({
                "occurred_at": utc_now_rfc3339(),
                "operator": operator,
                "device_id": device_id,
                "reason": reason,
                "outcome": outcome,
                "identity_verified": false,
            }),
        )
    }

    /// Record that this device reported, and optionally its compliance
    /// state. Persisted so the admin surface survives a mock restart.
    fn stamp_sync(&mut self, device_id: &str, overall: Option<String>) -> io::Result<()> {
        if let Some(record) = self.devices.get_mut(device_id) {
            record.last_sync = Some(utc_now_rfc3339());
            if overall.is_some() {
                record.compliance_state = overall;
            }
            self.save_devices()?;
        }
        Ok(())
    }

    /// Every registered device, for `admin.devices`.
    pub fn devices(&self) -> impl Iterator<Item = (&str, &DeviceRecord)> {
        self.devices.iter().map(|(id, r)| (id.as_str(), r))
    }

    /// One device row by id.
    pub fn device(&self, device_id: &str) -> Option<&DeviceRecord> {
        self.devices.get(device_id)
    }

    // -----------------------------------------------------------------
    // The M10 pending-query queue (milestone-10.md sections 7.2, 13.3)
    // -----------------------------------------------------------------

    /// Enqueue one admin question for one device. The RBAC check happens
    /// **before** this call (`crate::rbac`): a query that the asking role
    /// may not ask is never enqueued at all, so it never reaches a device.
    ///
    /// Nothing is sent anywhere. The entry waits until the device fetches
    /// it on its own sync cadence — the whole of law 1 in one sentence.
    pub fn enqueue_query(
        &mut self,
        device_id: &str,
        requesting_admin: &str,
        organization: &str,
        requested_scope: &str,
        session_id: Option<String>,
    ) -> io::Result<QueryEntry> {
        self.query_seq += 1;
        let entry = QueryEntry {
            query_id: format!(
                "qry_{:012x}",
                fnv1a64(&format!(
                    "{device_id}|{requesting_admin}|{requested_scope}|{}|{}",
                    utc_now_rfc3339(),
                    self.query_seq
                ))
            ),
            device_id: device_id.to_string(),
            requesting_admin: requesting_admin.to_string(),
            organization: organization.to_string(),
            requested_scope: requested_scope.to_string(),
            session_id,
            created_at: utc_now_rfc3339(),
            status: QueryStatus::Pending,
            delivered_at: None,
            answered_at: None,
            answer: None,
        };
        self.queries.push(entry.clone());
        self.save_queries()?;
        Ok(entry)
    }

    /// The pending questions addressed to `device_id`, oldest first,
    /// capped. Delivery is recorded but the entry stays **pending** until
    /// an answer arrives: a device that fetched a query and then lost power
    /// must get it again, and a queue that forgets on delivery would answer
    /// the administrator with silence forever.
    pub fn pending_for_device(
        &mut self,
        device_id: &str,
        limit: usize,
    ) -> io::Result<Vec<QueryEntry>> {
        let now = utc_now_rfc3339();
        let mut taken = Vec::new();
        for entry in self.queries.iter_mut() {
            if taken.len() >= limit {
                break;
            }
            if entry.device_id == device_id && entry.status == QueryStatus::Pending {
                entry.delivered_at = Some(now.clone());
                taken.push(entry.clone());
            }
        }
        if !taken.is_empty() {
            self.save_queries()?;
        }
        Ok(taken)
    }

    /// Record a device's answer, verbatim. The answer's own
    /// `result_category` decides the entry's terminal status: the mock does
    /// not second-guess the device, because the device is the authority
    /// about its own data (milestone-10.md section 7.3).
    ///
    /// Returns `Ok(false)` when no pending query with that id belongs to
    /// this device — a device may only answer questions addressed to it.
    pub fn record_answer(
        &mut self,
        device_id: &str,
        query_id: &str,
        answer: &Value,
    ) -> io::Result<bool> {
        let refused = answer
            .get("result_category")
            .and_then(Value::as_str)
            .is_some_and(|c| c == "refused");
        let Some(entry) = self
            .queries
            .iter_mut()
            .find(|e| e.query_id == query_id && e.device_id == device_id)
        else {
            return Ok(false);
        };
        entry.status = if refused {
            QueryStatus::Refused
        } else {
            QueryStatus::Answered
        };
        entry.answered_at = Some(utc_now_rfc3339());
        entry.answer = Some(answer.clone());
        let line = json!({
            "received_at": utc_now_rfc3339(),
            "device_id": device_id,
            "query_id": query_id,
            "answer": answer,
        });
        self.save_queries()?;
        self.append_line(ANSWERS_FILE, line)?;
        Ok(true)
    }

    /// One query by id (for `admin.query_result`).
    pub fn query(&self, query_id: &str) -> Option<&QueryEntry> {
        self.queries.iter().find(|e| e.query_id == query_id)
    }

    /// Every query, oldest first (fleet aggregation, `admin.device`).
    pub fn queries(&self) -> &[QueryEntry] {
        &self.queries
    }

    /// Atomic rewrite of `queries.json`: tmp file (0600) + rename.
    fn save_queries(&self) -> io::Result<()> {
        let tmp = self.dir.join("queries.json.tmp");
        let mut body = serde_json::to_string_pretty(&json!({
            "v": 1,
            "queries": self.queries,
        }))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        body.push('\n');
        write_new_0600(&tmp, body.as_bytes())?;
        std::fs::rename(&tmp, self.dir.join(QUERIES_FILE))
    }

    /// Atomic rewrite of `devices.json`: tmp file (0600) + rename.
    fn save_devices(&self) -> io::Result<()> {
        let tmp = self.dir.join("devices.json.tmp");
        let mut body = serde_json::to_string_pretty(&self.devices)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        body.push('\n');
        write_new_0600(&tmp, body.as_bytes())?;
        std::fs::rename(&tmp, self.dir.join(DEVICES_FILE))
    }

    fn append_line(&self, file: &str, value: Value) -> io::Result<()> {
        let mut line = value.to_string();
        line.push('\n');
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(self.dir.join(file))?;
        f.write_all(line.as_bytes())
    }
}

/// `devices.json` file name inside the state directory.
pub const DEVICES_FILE: &str = "devices.json";
/// Received-compliance JSONL file name.
pub const COMPLIANCE_FILE: &str = "received-compliance.jsonl";
/// Received-inventory JSONL file name.
pub const INVENTORY_FILE: &str = "received-inventory.jsonl";
/// M10 pending-query queue file name (milestone-10.md section 13.3).
pub const QUERIES_FILE: &str = "queries.json";
/// M10 append-only log of what devices returned, verbatim.
pub const ANSWERS_FILE: &str = "received-answers.jsonl";
/// Dev/CI portal custody: wrapped envelopes only, never plaintext keys.
pub const RECOVERY_ENVELOPES_FILE: &str = "received-recovery-envelopes.jsonl";
/// Dev/CI append-only audit of recovery release attempts; no key material.
pub const RECOVERY_RELEASES_FILE: &str = "recovery-releases.jsonl";

/// Where one queued question stands. `pending` until the device that owns
/// it answers; the terminal value mirrors the device's own
/// `result_category`, because the device is the authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryStatus {
    Pending,
    Answered,
    Refused,
}

impl QueryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            QueryStatus::Pending => "pending",
            QueryStatus::Answered => "answered",
            QueryStatus::Refused => "refused",
        }
    }
}

/// One queued admin question, as persisted in `queries.json`.
///
/// There is no field here through which an administrator could ask for a
/// prompt, a path or a command line: the question is a `device_id`, a
/// closed-vocabulary `requested_scope`, and optionally one `session_id`
/// that may narrow the answer but can never widen it (milestone-10.md
/// section 8.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueryEntry {
    pub query_id: String,
    pub device_id: String,
    pub requesting_admin: String,
    pub organization: String,
    pub requested_scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub created_at: String,
    pub status: QueryStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answered_at: Option<String>,
    /// The device's answer, stored verbatim. The mock never edits it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<Value>,
}

/// Load `queries.json`. A corrupt queue fails loudly for the same reason a
/// corrupt device ledger does: silently starting empty would drop questions
/// behind the check's back.
fn load_queries(path: &Path) -> io::Result<Vec<QueryEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(path)?;
    let document: Value = serde_json::from_slice(&bytes).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: corrupt query queue: {e}", path.display()),
        )
    })?;
    let queries = document.get("queries").cloned().unwrap_or(json!([]));
    serde_json::from_value(queries).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: corrupt query queue: {e}", path.display()),
        )
    })
}

/// FNV-1a — a stable, dependency-free id hash. Nothing cryptographic
/// depends on it: a `qry_` id is a correlation handle, not a secret.
fn fnv1a64(input: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

/// Mint `tok_<32 hex>` from `/dev/urandom` (16 random bytes). No `rand`
/// crate: std-only, and the kernel CSPRNG is exactly what a token stub
/// needs.
fn generate_device_token() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let mut token = String::with_capacity(4 + 32);
    token.push_str("tok_");
    for b in bytes {
        // Infallible: writing hex digits into a String cannot fail.
        let _ = write!(token, "{b:02x}");
    }
    Ok(token)
}

fn write_new_0600(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "punar-mock-state-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn register_persists_and_reloads() {
        let dir = tmp_dir("reload");
        let mut store = StateStore::open(&dir).unwrap();
        let token = store.register("dev_abc").unwrap();
        assert!(token.starts_with("tok_"));
        assert_eq!(token.len(), 4 + 32);
        assert!(token[4..].chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(store.device_for_token(&token), Some("dev_abc"));

        // A second store over the same directory sees the same ledger —
        // the m5-check stop→start must not invalidate the token.
        let reloaded = StateStore::open(&dir).unwrap();
        assert_eq!(reloaded.device_for_token(&token), Some("dev_abc"));
        assert_eq!(reloaded.device_count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reregistration_rotates_the_token() {
        let dir = tmp_dir("rotate");
        let mut store = StateStore::open(&dir).unwrap();
        let first = store.register("dev_abc").unwrap();
        let second = store.register("dev_abc").unwrap();
        assert_ne!(first, second, "re-register mints a fresh token");
        assert_eq!(store.device_for_token(&first), None, "old token is dead");
        assert_eq!(store.device_for_token(&second), Some("dev_abc"));
        assert_eq!(store.device_count(), 1, "still one device");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn corrupt_ledger_fails_loudly() {
        let dir = tmp_dir("corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(DEVICES_FILE), b"{ not json").unwrap();
        let err = StateStore::open(&dir).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn appends_are_one_json_object_per_line() {
        let dir = tmp_dir("append");
        let mut store = StateStore::open(&dir).unwrap();
        store
            .append_compliance("dev_abc", &json!({"overall": "compliant"}))
            .unwrap();
        store
            .append_compliance("dev_abc", &json!({"overall": "drifted"}))
            .unwrap();
        let text = std::fs::read_to_string(dir.join(COMPLIANCE_FILE)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["device_id"], "dev_abc");
        assert_eq!(first["report"]["overall"], "compliant");
        assert!(first["received_at"].as_str().unwrap().ends_with('Z'));
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn a_pending_query_waits_for_the_device_and_survives_a_restart() {
        let dir = tmp_dir("queue");
        let mut store = StateStore::open(&dir).unwrap();
        let token = store.register("dev_abc").unwrap();
        assert_eq!(store.device_for_token(&token), Some("dev_abc"));

        let entry = store
            .enqueue_query("dev_abc", "cio@acme.com", "acme.com", "inventory", None)
            .unwrap();
        assert!(entry.query_id.starts_with("qry_"));
        assert_eq!(entry.status, QueryStatus::Pending);
        assert!(entry.delivered_at.is_none());

        // A question for a *different* device is not this device's to see.
        store
            .enqueue_query("dev_other", "cio@acme.com", "acme.com", "inventory", None)
            .unwrap();
        let pending = store.pending_for_device("dev_abc", 16).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].query_id, entry.query_id);

        // Delivered is not answered: a device that fetched and then died
        // gets the question again.
        let again = store.pending_for_device("dev_abc", 16).unwrap();
        assert_eq!(again.len(), 1, "delivery must not consume the query");

        // The queue survives a restart, like the device ledger.
        let reloaded = StateStore::open(&dir).unwrap();
        assert_eq!(reloaded.queries().len(), 2);
        assert_eq!(
            reloaded.query(&entry.query_id).map(|e| e.status),
            Some(QueryStatus::Pending)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_answer_is_stored_verbatim_and_only_by_the_device_it_belongs_to() {
        let dir = tmp_dir("answer");
        let mut store = StateStore::open(&dir).unwrap();
        store.register("dev_abc").unwrap();
        let entry = store
            .enqueue_query("dev_abc", "cio@acme.com", "acme.com", "inventory", None)
            .unwrap();

        // Another device may not answer this question.
        assert!(
            !store
                .record_answer(
                    "dev_evil",
                    &entry.query_id,
                    &json!({"result_category": "answered"})
                )
                .unwrap()
        );
        assert_eq!(
            store.query(&entry.query_id).unwrap().status,
            QueryStatus::Pending
        );

        let answer = json!({
            "query_id": entry.query_id,
            "result_category": "answered",
            "authorization_decision": "allow",
            "granted_scope": "inventory",
            "payload": {"counts": {"managed": 1, "observed": 0, "unknown": 1}},
        });
        assert!(
            store
                .record_answer("dev_abc", &entry.query_id, &answer)
                .unwrap()
        );
        let stored = store.query(&entry.query_id).unwrap();
        assert_eq!(stored.status, QueryStatus::Answered);
        assert_eq!(stored.answer.as_ref().unwrap(), &answer, "stored verbatim");
        assert!(stored.answered_at.is_some());

        // And the append-only received log has exactly one line.
        let text = std::fs::read_to_string(dir.join(ANSWERS_FILE)).unwrap();
        assert_eq!(text.lines().count(), 1);
        let line: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(line["device_id"], "dev_abc");
        assert_eq!(line["answer"], answer);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_refusal_is_recorded_as_refused_because_the_device_said_so() {
        let dir = tmp_dir("refused");
        let mut store = StateStore::open(&dir).unwrap();
        store.register("dev_abc").unwrap();
        let entry = store
            .enqueue_query(
                "dev_abc",
                "secops@acme.com",
                "acme.com",
                "resource_summary",
                None,
            )
            .unwrap();
        store
            .record_answer(
                "dev_abc",
                &entry.query_id,
                &json!({"result_category": "refused", "refusal_reason": "out_of_scope"}),
            )
            .unwrap();
        assert_eq!(
            store.query(&entry.query_id).unwrap().status,
            QueryStatus::Refused
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn compliance_reports_stamp_the_device_row_with_a_state_only() {
        let dir = tmp_dir("stamp");
        let mut store = StateStore::open(&dir).unwrap();
        store.register("dev_abc").unwrap();
        store
            .append_compliance(
                "dev_abc",
                &json!({"overall": "compliant", "categories": []}),
            )
            .unwrap();
        let record = store.device("dev_abc").unwrap();
        assert_eq!(record.compliance_state.as_deref(), Some("compliant"));
        assert!(record.last_sync.is_some());
        // A state, never a value: nothing else from the report is kept.
        let raw = std::fs::read_to_string(dir.join(DEVICES_FILE)).unwrap();
        assert!(!raw.contains("categories"), "{raw}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
