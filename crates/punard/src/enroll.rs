//! Milestone 5 enrollment plumbing: the control-plane client (NDJSON over
//! a root-only UDS — the dev/CI mock stands in for the Smplify cloud), the
//! private `enrollment.json` / `device-token` stores, the category-only
//! sync report builders, and the `/run/punar/status.json` summary writer.
//!
//! Contracts: `docs/api/ipc.md` sections 5.9–5.11 and 9 (additive, v1);
//! design `docs/development/milestone-5.md` sections 4–8. Trust boundary,
//! stated honestly (milestone-5.md section 4.2): in production this hop is
//! Punar ⇄ Smplify over mutually-authenticated TLS; the mock replaces that
//! transport with filesystem admission on a root-only socket. The
//! `device_token` is still enforced at the protocol layer — the token flow
//! is the thing M5 rehearses.
//!
//! Privacy (SPEC sections 24, 54): the compliance report carries category
//! **states only** — never values, hostnames, timezone strings, audit
//! events, or anything behavioral; the inventory carries device info +
//! capability states, nothing behavioral. Enrollment is explicit
//! (`punarctl enroll start`), never automatic.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use punar_common::Redacted;
use punar_common::query::{
    CP_METHOD_QUERIES_ANSWER, CP_METHOD_QUERIES_PENDING, PendingQuery, ScopeSet,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::util::write_atomic;

/// Compiled-in default control-plane endpoint (milestone-5.md section 4.2).
/// Overridable via the `PUNAR_CONTROL_PLANE_SOCKET` environment variable
/// (resolved in `main.rs`) or the `--control-plane-socket` flag; host tests
/// point it at a temp socket. This seam is the documented simulation
/// boundary — real discovery (DNS/HTTPS + mTLS) is out of scope for M5.
pub const DEFAULT_CONTROL_PLANE_SOCKET: &str = "/run/punar-mock-smplify/api.sock";

/// Environment override for the control-plane socket path.
pub const CONTROL_PLANE_SOCKET_ENV: &str = "PUNAR_CONTROL_PLANE_SOCKET";

/// Production path of the shell summary file (ipc.md section 9).
pub const DEFAULT_STATUS_FILE: &str = "/run/punar/status.json";

/// Per-call read/write timeout on the control-plane socket. `enroll.start`
/// makes at most three calls plus two reports, comfortably inside its 60 s
/// processing bound (ipc.md section 2).
pub const CONTROL_PLANE_CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Bootstrap secret size in bytes (64 hex chars on the wire — the mock
/// requires ≥ 32 hex chars; milestone-5.md section 4.3).
pub const BOOTSTRAP_SECRET_BYTES: usize = 32;

// ---------------------------------------------------------------------------
// Control-plane client (NDJSON RPC, the ipc.md section 3 envelope verbatim)
// ---------------------------------------------------------------------------

/// A control-plane call failure, already split the way the enrollment
/// pipeline needs it: transport trouble (→ `upstream_unreachable`) vs. a
/// structured refusal from the mock (`not_found`, `unauthorized`, …).
#[derive(Debug)]
pub enum UpstreamError {
    /// Connect/send/receive failed or timed out, or the answer was not a
    /// valid protocol frame. The message never contains payload bytes.
    Unreachable(String),
    /// The control plane answered with a structured error.
    Refused { code: String, message: String },
}

impl UpstreamError {
    fn transport(what: &str, err: &io::Error) -> UpstreamError {
        UpstreamError::Unreachable(format!("{what} ({})", err.kind()))
    }
}

/// One-call-per-connection NDJSON client for the (mock) control plane.
/// Requests are `{"v":1,"id":…,"method":…,"params":{…}}`; responses carry
/// `result` xor `error` — the established envelope (milestone-5.md
/// section 4.3).
pub struct ControlPlaneClient {
    socket: PathBuf,
}

impl ControlPlaneClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        ControlPlaneClient {
            socket: socket.into(),
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, UpstreamError> {
        let stream = UnixStream::connect(&self.socket)
            .map_err(|e| UpstreamError::transport("connect failed", &e))?;
        let _ = stream.set_read_timeout(Some(CONTROL_PLANE_CALL_TIMEOUT));
        let _ = stream.set_write_timeout(Some(CONTROL_PLANE_CALL_TIMEOUT));

        let request = json!({
            "v": 1,
            "id": format!("punard-{}", std::process::id()),
            "method": method,
            "params": params,
        });
        let mut line =
            serde_json::to_string(&request).expect("control-plane requests serialize infallibly");
        line.push('\n');

        let mut writer = &stream;
        writer
            .write_all(line.as_bytes())
            .map_err(|e| UpstreamError::transport("send failed", &e))?;

        let mut reader = BufReader::new(&stream);
        let mut response = String::new();
        let read = reader
            .read_line(&mut response)
            .map_err(|e| UpstreamError::transport("no answer", &e))?;
        if read == 0 {
            return Err(UpstreamError::Unreachable(
                "the control plane closed the connection without answering".to_string(),
            ));
        }

        let value: Value = serde_json::from_str(response.trim_end()).map_err(|_| {
            UpstreamError::Unreachable("the control plane answered with a malformed line".into())
        })?;
        if value.get("v") != Some(&json!(1)) {
            return Err(UpstreamError::Unreachable(
                "the control plane answered with an unsupported protocol version".into(),
            ));
        }
        if let Some(error) = value.get("error") {
            return Err(UpstreamError::Refused {
                code: error
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
                message: error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("(no message)")
                    .to_string(),
            });
        }
        value.get("result").cloned().ok_or_else(|| {
            UpstreamError::Unreachable(
                "the control plane answered with neither result nor error".into(),
            )
        })
    }

    /// `org.discover {domain}` → the organization document.
    pub fn org_discover(&self, domain: &str) -> Result<Value, UpstreamError> {
        let result = self.call("org.discover", json!({ "domain": domain }))?;
        result.get("organization").cloned().ok_or_else(|| {
            UpstreamError::Unreachable("org.discover answered without an organization".into())
        })
    }

    /// `enroll.register {device_id, bootstrap}` → `(token, attestation)`.
    /// The bootstrap secret and the returned token are exposed only at this
    /// wire boundary; both live as [`Redacted`] everywhere else.
    pub fn register(
        &self,
        device_id: &str,
        bootstrap: &Redacted<String>,
    ) -> Result<(Redacted<String>, String), UpstreamError> {
        let result = self.call(
            "enroll.register",
            json!({
                "device_id": device_id,
                "bootstrap": bootstrap.expose_secret(),
            }),
        )?;
        let token = result
            .get("device_token")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                UpstreamError::Unreachable("enroll.register answered without a device token".into())
            })?;
        // The attestation step is SIMULATED: the mock answers the literal
        // string "simulated" and punard stores it as an opaque honesty
        // label, surfaced wherever enrollment state appears
        // (milestone-5.md section 5.2). Nothing is measured or verified.
        let attestation = result
            .get("attestation")
            .and_then(Value::as_str)
            .unwrap_or("simulated")
            .to_string();
        Ok((Redacted::new(token.to_string()), attestation))
    }

    /// `policy.fetch {device_token}` → the policy-source envelopes (each
    /// carrying its embedded `DeviceDesiredState` as `policy`).
    pub fn policy_fetch(&self, token: &Redacted<String>) -> Result<Vec<Value>, UpstreamError> {
        let result = self.call(
            "policy.fetch",
            json!({ "device_token": token.expose_secret() }),
        )?;
        match result.get("policies").and_then(Value::as_array) {
            Some(policies) => Ok(policies.clone()),
            None => Err(UpstreamError::Unreachable(
                "policy.fetch answered without a policies array".into(),
            )),
        }
    }

    /// `compliance.report {device_token, report}` (category states only).
    pub fn compliance_report(
        &self,
        token: &Redacted<String>,
        report: &Value,
    ) -> Result<(), UpstreamError> {
        self.call(
            "compliance.report",
            json!({ "device_token": token.expose_secret(), "report": report }),
        )
        .map(|_| ())
    }

    /// `inventory.report {device_token, inventory}`.
    pub fn inventory_report(
        &self,
        token: &Redacted<String>,
        inventory: &Value,
    ) -> Result<(), UpstreamError> {
        self.call(
            "inventory.report",
            json!({ "device_token": token.expose_secret(), "inventory": inventory }),
        )
        .map(|_| ())
    }

    /// M10: `queries.pending {device_token}` — **the device asks** for the
    /// questions addressed to it (milestone-10.md section 7.2).
    ///
    /// This is the whole of the remote-query inbound path, and it is an
    /// outbound call. There is no listener, no port, no push channel and no
    /// callback anywhere in Punar; a remote query reaches this device only
    /// because this device went and fetched it, on a schedule it already
    /// owned. An administrator with a perfectly valid token and this
    /// device's IP address has nowhere to send a request.
    ///
    /// A malformed entry is **dropped, not guessed at**: the wire type is
    /// strict, and a question this build cannot parse is a question it must
    /// not answer.
    pub fn queries_pending(
        &self,
        token: &Redacted<String>,
    ) -> Result<Vec<PendingQuery>, UpstreamError> {
        let result = self.call(
            CP_METHOD_QUERIES_PENDING,
            json!({ "device_token": token.expose_secret() }),
        )?;
        let Some(items) = result.get("queries").and_then(Value::as_array) else {
            return Err(UpstreamError::Unreachable(
                "queries.pending answered without a queries array".into(),
            ));
        };
        Ok(items
            .iter()
            .filter_map(
                |item| match serde_json::from_value::<PendingQuery>(item.clone()) {
                    Ok(query) => Some(query),
                    Err(e) => {
                        eprintln!(
                            "punard: dropping an unparseable pending query ({e}) — a question \
                         this build cannot read is a question it must not answer"
                        );
                        None
                    }
                },
            )
            .collect())
    }

    /// M10: `queries.answer {device_token, query_id, answer}` — post back
    /// what `punar-agentd` decided, **verbatim**.
    ///
    /// `answer` is an opaque [`Value`] on purpose. punard did not build it
    /// and does not understand it; typing it here would create a place
    /// where a courier could reshape a payload, and the whole point of
    /// milestone-10.md section 7.3 is that no such place exists.
    pub fn queries_answer(
        &self,
        token: &Redacted<String>,
        query_id: &str,
        answer: &Value,
    ) -> Result<(), UpstreamError> {
        self.call(
            CP_METHOD_QUERIES_ANSWER,
            json!({
                "device_token": token.expose_secret(),
                "query_id": query_id,
                "answer": answer,
            }),
        )
        .map(|_| ())
    }
}

// ---------------------------------------------------------------------------
// enrollment.json — private daemon store (peer of device-id; 0600, atomic)
// ---------------------------------------------------------------------------

/// The organization identity as persisted and surfaced (ipc.md 5.1/5.10).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrgRecord {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub domain: String,
}

/// The persisted `last_sync` pair (`enroll.status` adds the in-memory
/// `pending` flag on top).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LastSyncRecord {
    pub at: Option<String>,
    /// `"success"` | `"unreachable"` | `null` (no attempt yet).
    pub result: Option<String>,
}

/// `/var/lib/punar/enrollment.json` (milestone-5.md section 5.1) — a
/// private daemon store, deliberately not a public schema. The device
/// token is **not** in this file (separate 0600 file, separate blast
/// radius).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Enrollment {
    pub version: u32,
    pub org: OrgRecord,
    pub enrolled_at: String,
    /// The literal honesty label from the register step ("simulated").
    pub attestation: String,
    /// policy.d file names this enrollment wrote — exactly what
    /// `enroll.stop` removes.
    pub policy_files: Vec<String>,
    pub last_sync: LastSyncRecord,
    /// SHA-256 hex of the last successfully reported inventory (the hash
    /// gate, milestone-5.md section 6).
    pub last_inventory_hash: Option<String>,
    /// M10: the remote-query scopes the **organization asked for at
    /// enrollment**, taken from the org document and written here once
    /// (milestone-10.md section 9.2).
    ///
    /// This array is the middle term of the authorization intersection, and
    /// `punar-agentd` reads it **from this file itself** — never from the
    /// request, never from anything punard passes it. That is what makes
    /// SPEC section 59.4 hold: a compromised control plane cannot talk the
    /// endpoint into exceeding what enrollment established, because the
    /// endpoint does not listen to it on this subject.
    ///
    /// `#[serde(default)]` so an `enrollment.json` written by the M5/M9
    /// build still loads — and defaults to the **empty set**, which grants
    /// nothing. An organization that never asked for a scope never gets
    /// one.
    #[serde(default)]
    pub remote_query_scopes: Vec<String>,
    /// M10: the last remote query this device answered or refused, for
    /// `enroll.status`. Metadata only — never a payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_query: Option<LastQueryRecord>,
}

/// The `enroll.status` view of the most recent remote query
/// (milestone-10.md section 13.2). Three fields, none of which is data
/// about the user's work: when, at what scope, and what was decided. The
/// full record — including who asked — is the user's own
/// `punarctl privacy queries`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastQueryRecord {
    pub at: String,
    pub scope: String,
    pub decision: String,
}

impl Enrollment {
    /// The granted scopes as a parsed, closed [`ScopeSet`]. Values this
    /// build has no name for grant nothing, and are not silently promoted
    /// to anything that does.
    pub fn granted_scopes(&self) -> ScopeSet {
        let values: Vec<Value> = self
            .remote_query_scopes
            .iter()
            .map(|s| Value::String(s.clone()))
            .collect();
        ScopeSet::parse_json(Some(&Value::Array(values))).0
    }

    /// The policy ids recorded at enrollment (file stem = policy id by the
    /// enrollment chain's own naming rule).
    pub fn policy_ids(&self) -> Vec<String> {
        self.policy_files
            .iter()
            .map(|f| f.trim_end_matches(".json").to_string())
            .collect()
    }
}

/// Load `enrollment.json` if present. A corrupt file is an error — same
/// posture as the layer stores (refusing to start beats silently
/// forgetting an enrollment).
pub fn load_enrollment(path: &Path) -> io::Result<Option<Enrollment>> {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let enrollment: Enrollment = serde_json::from_str(&content).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} is corrupt: {e}", path.display()),
                )
            })?;
            Ok(Some(enrollment))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Persist `enrollment.json` (0600, atomic).
pub fn save_enrollment(path: &Path, enrollment: &Enrollment) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(enrollment).expect("enrollment serializes");
    write_atomic(path, &bytes, 0o600)
}

/// Load the device token file if present, wrapped [`Redacted`] before it
/// can reach any formatter (SPEC section 53).
pub fn load_device_token(path: &Path) -> io::Result<Option<Redacted<String>>> {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let token = content.trim().to_string();
            if token.is_empty() {
                return Ok(None);
            }
            Ok(Some(Redacted::new(token)))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Persist the device token alone (0600, atomic). The only place the
/// secret is exposed on the write path — greppable via `expose_secret`.
pub fn save_device_token(path: &Path, token: &Redacted<String>) -> io::Result<()> {
    write_atomic(
        path,
        format!("{}\n", token.expose_secret()).as_bytes(),
        0o600,
    )
}

// ---------------------------------------------------------------------------
// /run/punar/status.json — the shell summary side contract (ipc.md § 9)
// ---------------------------------------------------------------------------

/// The summary tuple. Summary ONLY — no per-capability rows, policy ids,
/// device id, or hostname: the file is world-readable in a user-owned
/// directory and carries exactly what the bar renders. Non-authoritative
/// by design; consumers fail closed to unenrolled on a missing/invalid
/// file.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StatusSummary {
    pub v: u32,
    pub enrolled: bool,
    pub org_name: Option<String>,
    pub compliance_overall: String,
    pub ts: String,
}

/// Write the summary file (0644, atomic tmp+rename within its directory).
pub fn write_status_summary(path: &Path, summary: &StatusSummary) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(summary).expect("status summary serializes");
    bytes.push(b'\n');
    write_atomic(path, &bytes, 0o644)
}

// ---------------------------------------------------------------------------
// Report builders (SPEC sections 24, 52, 54 — category states only)
// ---------------------------------------------------------------------------

/// The compliance report body: `overall` + `{category, state}` pairs and
/// **nothing else** — states, not values; the org never sees the hostname
/// string, the timezone, nft contents, or anything behavioral (SPEC
/// sections 24, 54; m5-check asserts this key set exactly).
pub fn compliance_report_body(
    overall: &str,
    categories: impl IntoIterator<Item = (String, String)>,
) -> Value {
    json!({
        "overall": overall,
        "categories": categories
            .into_iter()
            .map(|(category, state)| json!({ "category": category, "state": state }))
            .collect::<Vec<Value>>(),
    })
}

/// Inventory sources read from disk: os-release fields and the kernel
/// release. Paths are injectable for tests; absent files degrade to
/// `"unknown"` — inventory must never fail a reconcile pass.
pub struct InventorySources {
    pub os_release_path: PathBuf,
    pub kernel_release_path: PathBuf,
}

impl InventorySources {
    fn os_release(&self) -> (String, String, String) {
        let content = std::fs::read_to_string(&self.os_release_path).unwrap_or_default();
        let field = |key: &str| -> String {
            content
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{key}=")))
                .map(|v| v.trim().trim_matches('"').to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "unknown".to_string())
        };
        (field("ID"), field("VERSION_ID"), field("PRETTY_NAME"))
    }

    fn kernel(&self) -> String {
        std::fs::read_to_string(&self.kernel_release_path)
            .map(|s| s.trim().to_string())
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".to_string())
    }
}

/// The inventory body (milestone-5.md section 6): device info + capability
/// states, nothing behavioral. `capabilities` carries
/// `{capability, supported, current_state}` per registered capability.
pub fn inventory_body(
    sources: &InventorySources,
    hostname: &str,
    capabilities: impl IntoIterator<Item = (String, bool, Value)>,
) -> Value {
    let (id, version_id, pretty_name) = sources.os_release();
    json!({
        "os": { "id": id, "version_id": version_id, "pretty_name": pretty_name },
        "kernel": sources.kernel(),
        "hostname": hostname,
        "capabilities": capabilities
            .into_iter()
            .map(|(capability, supported, current_state)| json!({
                "capability": capability,
                "supported": supported,
                "current_state": current_state,
            }))
            .collect::<Vec<Value>>(),
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use punar_common::REDACTED_PLACEHOLDER;

    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("punard-enroll-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_enrollment() -> Enrollment {
        Enrollment {
            version: 1,
            org: OrgRecord {
                id: "acme".into(),
                name: "Acme".into(),
                display_name: "Acme Engineering".into(),
                domain: "acme.com".into(),
            },
            enrolled_at: "2026-08-26T09:00:00Z".into(),
            attestation: "simulated".into(),
            policy_files: vec!["eng-baseline-v12.json".into()],
            last_sync: LastSyncRecord::default(),
            last_inventory_hash: None,
            remote_query_scopes: vec!["inventory".into(), "authority".into()],
            last_query: None,
        }
    }

    #[test]
    fn enrollment_store_round_trips_at_0600_without_a_token_field() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmp("store");
        let path = dir.join("enrollment.json");
        assert_eq!(load_enrollment(&path).unwrap(), None);

        let enrollment = sample_enrollment();
        save_enrollment(&path, &enrollment).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(load_enrollment(&path).unwrap(), Some(enrollment.clone()));
        assert_eq!(enrollment.policy_ids(), ["eng-baseline-v12"]);

        // The token is a separate file with a separate blast radius: the
        // enrollment store has no field that could carry it.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("token"), "{raw}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_enrollment_refuses_to_load() {
        let dir = tmp("corrupt");
        let path = dir.join("enrollment.json");
        std::fs::write(&path, "{oops").unwrap();
        assert!(load_enrollment(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_token_round_trips_redacted_at_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmp("token");
        let path = dir.join("device-token");
        assert!(load_device_token(&path).unwrap().is_none());

        let token = Redacted::new("tok_0123456789abcdef".to_string());
        save_device_token(&path, &token).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let loaded = load_device_token(&path).unwrap().unwrap();
        assert_eq!(loaded.expose_secret(), "tok_0123456789abcdef");
        // The wrapper's formatting can never leak it (SPEC sections 1.19,
        // 53).
        assert_eq!(format!("{loaded:?}"), REDACTED_PLACEHOLDER);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn status_summary_is_the_ipc_9_tuple_exactly() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmp("summary");
        let path = dir.join("status.json");
        write_status_summary(
            &path,
            &StatusSummary {
                v: 1,
                enrolled: true,
                org_name: Some("Acme Engineering".into()),
                compliance_overall: "compliant".into(),
                ts: "2026-08-26T09:02:00Z".into(),
            },
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        let raw: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let keys: Vec<&str> = raw
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        // Summary ONLY (ipc.md section 9): the world-readable file carries
        // exactly what the bar renders (serde_json emits keys sorted).
        assert_eq!(
            keys,
            ["compliance_overall", "enrolled", "org_name", "ts", "v"]
        );
        assert_eq!(raw["org_name"], "Acme Engineering");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compliance_report_is_category_states_only() {
        let report = compliance_report_body(
            "compliant",
            [
                ("security.firewall".to_string(), "compliant".to_string()),
                ("system.hostname".to_string(), "compliant".to_string()),
            ],
        );
        assert_eq!(
            report,
            json!({
                "overall": "compliant",
                "categories": [
                    {"category": "security.firewall", "state": "compliant"},
                    {"category": "system.hostname", "state": "compliant"}
                ]
            })
        );
        // The privacy assertion in miniature (SPEC sections 24, 54): the
        // top-level and per-entry key sets are exact.
        let keys: Vec<&str> = report
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["categories", "overall"]);
        for entry in report["categories"].as_array().unwrap() {
            let keys: Vec<&str> = entry
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(keys, ["category", "state"]);
        }
    }

    #[test]
    fn inventory_reads_os_release_and_degrades_to_unknown() {
        let dir = tmp("inv");
        let os_release = dir.join("os-release");
        std::fs::write(
            &os_release,
            "ID=punar\nVERSION_ID=\"0.5\"\nPRETTY_NAME=\"Punar OS 0.5 (M5)\"\n",
        )
        .unwrap();
        let kernel = dir.join("osrelease");
        std::fs::write(&kernel, "6.12.0-punar\n").unwrap();

        let sources = InventorySources {
            os_release_path: os_release,
            kernel_release_path: kernel,
        };
        let inventory = inventory_body(
            &sources,
            "punar-desktop",
            [(
                "security.firewall".to_string(),
                true,
                Value::String("enabled".into()),
            )],
        );
        assert_eq!(inventory["os"]["id"], "punar");
        assert_eq!(inventory["os"]["version_id"], "0.5");
        assert_eq!(inventory["os"]["pretty_name"], "Punar OS 0.5 (M5)");
        assert_eq!(inventory["kernel"], "6.12.0-punar");
        assert_eq!(inventory["hostname"], "punar-desktop");
        assert_eq!(
            inventory["capabilities"][0]["capability"],
            "security.firewall"
        );
        assert_eq!(inventory["capabilities"][0]["supported"], true);
        assert_eq!(inventory["capabilities"][0]["current_state"], "enabled");

        let absent = InventorySources {
            os_release_path: dir.join("missing"),
            kernel_release_path: dir.join("also-missing"),
        };
        let degraded = inventory_body(&absent, "h", []);
        assert_eq!(degraded["os"]["id"], "unknown");
        assert_eq!(degraded["kernel"], "unknown");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M10: the grant round-trips, and an `enrollment.json` written by an
    /// earlier build still loads — defaulting to the **empty set**, which
    /// grants nothing. An organization that never asked for a scope never
    /// gets one (milestone-10.md section 9.2).
    #[test]
    fn the_remote_query_grant_round_trips_and_defaults_to_nothing() {
        let dir = tmp("scopes");
        let path = dir.join("enrollment.json");
        let enrollment = sample_enrollment();
        save_enrollment(&path, &enrollment).unwrap();
        let loaded = load_enrollment(&path).unwrap().unwrap();
        assert_eq!(
            loaded.granted_scopes().as_words(),
            ["inventory", "authority"]
        );

        // An M5/M9-shaped file: no `remote_query_scopes` key at all.
        let mut raw: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        raw.as_object_mut().unwrap().remove("remote_query_scopes");
        std::fs::write(&path, raw.to_string()).unwrap();
        let legacy = load_enrollment(&path).unwrap().unwrap();
        assert!(legacy.remote_query_scopes.is_empty());
        assert!(
            legacy.granted_scopes().is_empty(),
            "an absent key is the empty set, never a permissive default"
        );

        // A value this build has no name for grants nothing and is not
        // silently promoted to anything that does.
        raw.as_object_mut().unwrap().insert(
            "remote_query_scopes".to_string(),
            json!(["inventory", "telepathy", "all", "*"]),
        );
        std::fs::write(&path, raw.to_string()).unwrap();
        let odd = load_enrollment(&path).unwrap().unwrap();
        assert_eq!(odd.granted_scopes().as_words(), ["inventory"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The grant file has no field that could carry a device token, and the
    /// query methods have no field that could carry a payload. Privacy in
    /// the types, on the transport side.
    #[test]
    fn the_enrollment_store_still_holds_no_secret_after_m10() {
        let dir = tmp("nosecret");
        let path = dir.join("enrollment.json");
        save_enrollment(&path, &sample_enrollment()).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("token"), "{raw}");
        assert!(raw.contains("remote_query_scopes"), "{raw}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn client_maps_a_missing_socket_to_unreachable() {
        let client = ControlPlaneClient::new("/nonexistent/punar-mock/api.sock");
        match client.org_discover("acme.com") {
            Err(UpstreamError::Unreachable(why)) => {
                assert!(why.contains("connect failed"), "{why}");
            }
            other => panic!("expected Unreachable, got {other:?}"),
        }
    }
}
