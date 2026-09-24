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
//! events, or anything behavioral; the inventory carries device facts,
//! capability and posture states and, as far as the enrollment's tier allows,
//! applications ([`crate::inventory`]) — nothing behavioral. Enrollment is
//! explicit (`punarctl enroll start`), never automatic.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use punar_common::Redacted;
use punar_common::ipc::{OrganizationView, OrganizationViewCategory};
use punar_common::query::{
    CP_METHOD_QUERIES_ANSWER, CP_METHOD_QUERIES_PENDING, PendingQuery, ScopeSet,
};
use punar_recovery::{
    EscrowReceipt, RecoveryBinding, RecoveryEnvelope, RecoveryError, SecretRecoveryKey,
    TenantRecoveryKey, VerifiedEscrowReceipt,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::inventory::{Collected, MAX_INVENTORY_BYTES, Withheld};
use crate::util::write_atomic;

/// Compiled-in default control-plane endpoint: `punar-smplifyd`, the
/// built-in Smplify device agent, which serves this same NDJSON contract on
/// a root-only socket and carries it to Smplify over mutually authenticated
/// TLS (docs/development/smplify-enrollment.md). Overridable via the
/// `PUNAR_CONTROL_PLANE_SOCKET` environment variable (resolved in
/// `main.rs`) or the `--control-plane-socket` flag; the dev/CI image points
/// it at `punar-mock-smplify` through a unit drop-in, and host tests at a
/// temp socket.
pub const DEFAULT_CONTROL_PLANE_SOCKET: &str = "/run/punar-smplifyd/api.sock";

/// Environment override for the control-plane socket path.
pub const CONTROL_PLANE_SOCKET_ENV: &str = "PUNAR_CONTROL_PLANE_SOCKET";

/// Production path of the shell summary file (ipc.md section 9).
pub const DEFAULT_STATUS_FILE: &str = "/run/punar/status.json";

/// Per-call read/write timeout on the control-plane socket, for every method
/// [`call_timeout`] does not name. `enroll.start` makes three calls, then
/// a reconcile pass with its reports; all of them waited out in full still
/// fit its 60 s processing bound (ipc.md section 2).
pub const CONTROL_PLANE_CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// `enroll.register`'s timeout. The control plane registers with the
/// organization's server inside this call, and a registration the server
/// recorded but punard gave up on can refuse every later attempt from this
/// machine (Smplify keeps one active record per machine), so punard waits
/// out the built-in agent's whole register budget, and its local work after
/// it, rather than the generic [`CONTROL_PLANE_CALL_TIMEOUT`].
pub const REGISTER_CALL_TIMEOUT: Duration = Duration::from_secs(14);

/// How long punard waits for the answer to one call of `method`: at least a
/// second longer than the built-in agent may spend on the organization's
/// server for it (`punar_smplifyd::budget`), so an answer that exists
/// arrives. An answer that arrives after punard stopped waiting reads as
/// "unreachable" even when the server acted on the request.
pub fn call_timeout(method: &str) -> Duration {
    match method {
        "enroll.register" => REGISTER_CALL_TIMEOUT,
        _ => CONTROL_PLANE_CALL_TIMEOUT,
    }
}

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

/// The automatic escrow path has only two failure domains: the authenticated
/// control-plane hop, or local cryptographic/contract verification. Neither
/// variant carries recovery material.
#[derive(Debug)]
pub enum RecoveryEscrowError {
    Upstream(UpstreamError),
    Local(RecoveryError),
}

impl From<UpstreamError> for RecoveryEscrowError {
    fn from(value: UpstreamError) -> Self {
        Self::Upstream(value)
    }
}

impl From<RecoveryError> for RecoveryEscrowError {
    fn from(value: RecoveryError) -> Self {
        Self::Local(value)
    }
}

/// Public envelope plus a locally verified receipt. The plaintext key has
/// already fallen out of the function without ever entering either object.
#[derive(Debug)]
pub struct RecoveryEscrowOutcome {
    pub envelope: RecoveryEnvelope,
    pub receipt: VerifiedEscrowReceipt,
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
        let _ = stream.set_read_timeout(Some(call_timeout(method)));
        let _ = stream.set_write_timeout(Some(call_timeout(method)));

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

    /// `enroll.register {device_id, bootstrap, code?}` → `(token, attestation)`.
    /// The bootstrap secret, the enrollment code and the returned token are
    /// exposed only at this wire boundary; all live as [`Redacted`]
    /// everywhere else. The code is the organisation-issued enrollment
    /// token the real control plane redeems; the mock needs none.
    pub fn register(
        &self,
        device_id: &str,
        bootstrap: &Redacted<String>,
        code: Option<&Redacted<String>>,
    ) -> Result<(Redacted<String>, String), UpstreamError> {
        let mut params = json!({
            "device_id": device_id,
            "bootstrap": bootstrap.expose_secret(),
        });
        if let Some(code) = code {
            params["code"] = Value::String(code.expose_secret().clone());
        }
        let result = self.call("enroll.register", params)?;
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

    /// `enroll.unregister {device_token}`: ask the control plane to forget
    /// this device's identity. Best effort by contract — unenrollment is a
    /// local restore that must succeed offline (SPEC section 55), so the
    /// caller logs a failure and continues.
    pub fn unregister(&self, token: &Redacted<String>) -> Result<(), UpstreamError> {
        self.call(
            "enroll.unregister",
            json!({ "device_token": token.expose_secret() }),
        )
        .map(|_| ())
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

    /// `inventory.report {device_token, inventory}` → the body the control
    /// plane says it sent on, when it says. `punar-smplifyd` answers
    /// `{sent}` with its translation; the development mock answers without
    /// it, because what it keeps is the inventory itself.
    pub fn inventory_report(
        &self,
        token: &Redacted<String>,
        inventory: &Value,
    ) -> Result<Option<Value>, UpstreamError> {
        let result = self.call(
            "inventory.report",
            json!({ "device_token": token.expose_secret(), "inventory": inventory }),
        )?;
        Ok(result.get("sent").filter(|sent| sent.is_object()).cloned())
    }

    /// Fetch tenant public material through the same authenticated endpoint
    /// and device token as policy. A raw unauthenticated URL is never accepted.
    pub fn recovery_key(
        &self,
        token: &Redacted<String>,
    ) -> Result<TenantRecoveryKey, UpstreamError> {
        let result = self.call(
            "recovery.key",
            json!({"device_token": token.expose_secret()}),
        )?;
        let value = result.get("tenant_recovery_key").cloned().ok_or_else(|| {
            UpstreamError::Unreachable(
                "recovery.key answered without tenant recovery material".into(),
            )
        })?;
        let key: TenantRecoveryKey = serde_json::from_value(value).map_err(|_| {
            UpstreamError::Unreachable(
                "recovery.key answered with malformed tenant recovery material".into(),
            )
        })?;
        key.validate().map_err(|_| {
            UpstreamError::Unreachable(
                "recovery.key answered with unusable tenant recovery material".into(),
            )
        })?;
        Ok(key)
    }

    /// Upload an already wrapped envelope. The recovery key cannot appear in
    /// this request because [`RecoveryEnvelope`] has no plaintext field.
    pub fn recovery_escrow(
        &self,
        token: &Redacted<String>,
        envelope: &RecoveryEnvelope,
    ) -> Result<EscrowReceipt, UpstreamError> {
        let result = self.call(
            "recovery.escrow",
            json!({
                "device_token": token.expose_secret(),
                "envelope": envelope,
            }),
        )?;
        let value = result.get("receipt").cloned().ok_or_else(|| {
            UpstreamError::Unreachable("recovery.escrow answered without a receipt".into())
        })?;
        serde_json::from_value(value).map_err(|_| {
            UpstreamError::Unreachable("recovery.escrow answered with a malformed receipt".into())
        })
    }

    /// The one automatic managed-device flow: fetch authenticated tenant
    /// public material → HPKE seal locally → upload ciphertext → verify the
    /// signed, exact receipt. A caller must not report `escrowed` until this
    /// returns `Ok`.
    pub fn escrow_recovery_key(
        &self,
        token: &Redacted<String>,
        binding: &RecoveryBinding,
        recovery_key: &SecretRecoveryKey,
    ) -> Result<RecoveryEscrowOutcome, RecoveryEscrowError> {
        let tenant_key = self.recovery_key(token)?;
        let envelope = tenant_key.seal(binding, recovery_key)?;
        let raw_receipt = self.recovery_escrow(token, &envelope)?;
        let receipt = raw_receipt.verify(&tenant_key, &envelope)?;
        Ok(RecoveryEscrowOutcome { envelope, receipt })
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
    /// Whether a person on this device may unenroll it: the organization's
    /// `enrollment.removable`, read from its document at enrollment and fixed
    /// here (docs/development/smplify-enrollment.md section 3.1). Never
    /// re-read from a policy fetch, so an organization cannot make an
    /// enrollment non-removable after its user agreed to a removable one.
    ///
    /// Defaults to `true` for a file written before the field existed, the
    /// same reading an organization document without the key gets. No
    /// production enrollment predates it: the Smplify path has not shipped.
    ///
    /// NOT THE ONLY RECORD. `/var` is shared across releases and never rolled
    /// back, so an older punard booted from a retained UKI rewrites this file
    /// without the field on its next sync, and the default above would read
    /// the result as removable. The term is therefore also kept in
    /// [`TERMS_FILE`], which no older build knows or rewrites, and
    /// [`load_enrollment`] folds it back in. It can only take removability
    /// away.
    #[serde(default = "removable_by_default")]
    pub removable: bool,
    /// Whether the organization owns this device: declared in its document
    /// at enrollment (`enrollment.ownership: "organization"`) AND accepted by
    /// the enrolling person, the way a non-removable term is
    /// (docs/development/smplify-enrollment.md section 3.2). Fixed here and
    /// never re-read from a policy fetch. Only then does the inventory carry
    /// the serial number and every system-wide application
    /// ([`crate::inventory`]); a personal enrollment's inventory never names
    /// an application the person chose.
    ///
    /// Defaults to `false`, and no terms file backs it: an older punard that
    /// rewrites this file without the field can only narrow what is sent.
    #[serde(default)]
    pub organization_owned: bool,
    /// When the inventory last reached the control plane. The hash gate skips
    /// an unchanged inventory, but a 2xx proves only that the request
    /// arrived, not that the receiver kept it, so an unchanged inventory is
    /// still resent once [`INVENTORY_RESEND_FLOOR_SECONDS`] have passed.
    /// Written only after a send succeeds.
    #[serde(default)]
    pub last_inventory_sent_at: Option<String>,
}

fn removable_by_default() -> bool {
    true
}

/// The inventory's resend floor: at least once a day, changed or not.
pub const INVENTORY_RESEND_FLOOR_SECONDS: u64 = 24 * 60 * 60;

/// Whether an unchanged inventory is due again. Never sent, an unreadable
/// record, or a clock that moved backwards all resend: a spare report costs a
/// request, a missed one leaves the organization with a stale device.
pub fn inventory_resend_due(last_sent_at: Option<&str>, now: &str) -> bool {
    let last = last_sent_at.and_then(punar_common::time::unix_seconds_from_rfc3339);
    let now = punar_common::time::unix_seconds_from_rfc3339(now);
    match (last, now) {
        (Some(last), Some(now)) => now < last || now - last >= INVENTORY_RESEND_FLOOR_SECONDS,
        _ => true,
    }
}

/// Beside `enrollment.json`: the organization's removal term for one
/// enrollment, bound to it by organization and enrollment time.
pub const TERMS_FILE: &str = "enrollment-terms.json";

/// The contents of [`TERMS_FILE`]. Tolerant of fields a newer build adds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentTerms {
    pub version: u32,
    pub org_id: String,
    pub enrolled_at: String,
    pub removable: bool,
}

fn terms_path(enrollment_path: &Path) -> PathBuf {
    enrollment_path.with_file_name(TERMS_FILE)
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
            let mut enrollment: Enrollment = serde_json::from_str(&content).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} is corrupt: {e}", path.display()),
                )
            })?;
            // The term kept apart from this file wins when it says "not
            // removable" and belongs to this enrollment. One left over from an
            // enrollment an older build ended is for another enrollment, and
            // is ignored.
            let terms = load_terms(&terms_path(path))?.filter(|terms| {
                terms.org_id == enrollment.org.id && terms.enrolled_at == enrollment.enrolled_at
            });
            if let Some(terms) = terms {
                enrollment.removable &= terms.removable;
            }
            Ok(Some(enrollment))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Read [`TERMS_FILE`]. Absent is `None`; corrupt is an error, the same
/// posture as a corrupt `enrollment.json`: refusing to start beats silently
/// forgetting that an organization may keep this device.
fn load_terms(path: &Path) -> io::Result<Option<EnrollmentTerms>> {
    match std::fs::read_to_string(path) {
        Ok(content) => serde_json::from_str(&content).map(Some).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} is corrupt: {e}", path.display()),
            )
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Persist `enrollment.json` (0600, atomic), and the removal term beside it
/// first, so no crash leaves an enrollment without its term.
pub fn save_enrollment(path: &Path, enrollment: &Enrollment) -> io::Result<()> {
    let terms = EnrollmentTerms {
        version: 1,
        org_id: enrollment.org.id.clone(),
        enrolled_at: enrollment.enrolled_at.clone(),
        removable: enrollment.removable,
    };
    let terms_bytes = serde_json::to_vec_pretty(&terms).expect("terms serialize");
    write_atomic(&terms_path(path), &terms_bytes, 0o600)?;
    let bytes = serde_json::to_vec_pretty(enrollment).expect("enrollment serializes");
    write_atomic(path, &bytes, 0o600)
}

/// Remove `enrollment.json`'s removal term (on unenroll).
pub fn remove_terms(enrollment_path: &Path) -> io::Result<()> {
    match std::fs::remove_file(terms_path(enrollment_path)) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
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
// organization-view.json — what the organization last received (SPEC § 24.2)
// ---------------------------------------------------------------------------

/// Beside `enrollment.json`: the inventory exactly as it last reached the
/// organization, so a person can see what their organization can see
/// (`enroll.status.organization_view`, SPEC section 24.2). Written only after
/// a send succeeds, and removed with the enrollment.
pub const ORGANIZATION_VIEW_FILE: &str = "organization-view.json";

/// root:`punar` 0640, the mode of the other records an administrator's surface
/// may show. `/var/lib/punar` itself is root-only, so today a person reads it
/// through `enroll.status`. It holds nothing the organization did not already
/// receive, and nothing secret.
const ORGANIZATION_VIEW_MODE: u32 = 0o640;

/// Larger than any inventory the caps allow ([`MAX_INVENTORY_BYTES`]) with
/// the agent's translation around it; a file past it is not one punard wrote.
const ORGANIZATION_VIEW_MAX_BYTES: u64 = 2 * 1024 * 1024;

/// The contents of [`ORGANIZATION_VIEW_FILE`]. `sent` is the body as the
/// control plane received it and nothing else: `punar-smplifyd`'s own account
/// of what it posted to Smplify, or, from a control plane that does not give
/// one (the development mock, which keeps the inventory itself), the
/// inventory as handed over. The other fields are local bookkeeping and were
/// never sent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrganizationViewRecord {
    pub version: u32,
    /// The enrollment it describes. A view left by an earlier enrollment is
    /// never shown for a later one.
    pub org_id: String,
    pub enrolled_at: String,
    pub sent_at: String,
    pub sent: Value,
}

/// Persist the view (0640 root:`punar`, atomic). The group is applied only
/// when running as root; elsewhere the file stays the daemon user's.
pub fn save_organization_view(
    path: &Path,
    record: &OrganizationViewRecord,
    gid: Option<u32>,
) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(record).expect("organization view serializes");
    bytes.push(b'\n');
    write_atomic(path, &bytes, ORGANIZATION_VIEW_MODE)?;
    if let Some(gid) = gid {
        let _ = std::os::unix::fs::chown(path, Some(0), Some(gid));
    }
    Ok(())
}

/// The view of this enrollment, if one was recorded. Absent, unreadable,
/// oversized, or another enrollment's: `None` — the person is then told
/// nothing has been sent yet rather than shown what may not be true.
pub fn load_organization_view(
    path: &Path,
    enrollment: &Enrollment,
) -> Option<OrganizationViewRecord> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(ORGANIZATION_VIEW_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > ORGANIZATION_VIEW_MAX_BYTES {
        return None;
    }
    serde_json::from_slice::<OrganizationViewRecord>(&bytes)
        .ok()
        .filter(|record| {
            record.org_id == enrollment.org.id && record.enrolled_at == enrollment.enrolled_at
        })
}

/// The envelope of a status body: the organization's own id for the device,
/// and the send time `sent_at` already states. Neither is a fact it learns.
const ENVELOPE_KEYS: [&str; 2] = ["deviceId", "heartbeat"];
/// Smplify's body nests its sections one level down.
const SECTIONS_KEY: &str = "systemInfo";
/// Where a value that belongs to no section is listed.
const LOOSE_CATEGORY: &str = "device";

/// What `enroll.status` says the organization can see: the categories and
/// field names of the last inventory it received, and when. Names, not values
/// — the values are in the file. A field sent as `null` or empty told the
/// organization nothing and is not listed; a list names how many rows it
/// carried.
///
/// It reads whatever was sent rather than a list of what should have been,
/// so it cannot say less than left the device.
pub fn organization_view_summary(record: Option<&OrganizationViewRecord>) -> OrganizationView {
    let Some(record) = record else {
        return OrganizationView {
            sent_at: None,
            categories: Vec::new(),
        };
    };
    let mut categories: std::collections::BTreeMap<String, OrganizationViewCategory> =
        std::collections::BTreeMap::new();
    let mut loose = Vec::new();
    for (key, value) in record.sent.as_object().into_iter().flatten() {
        if ENVELOPE_KEYS.contains(&key.as_str()) {
            continue;
        }
        let sections = match value.as_object() {
            Some(sections) if key == SECTIONS_KEY => sections.iter().collect(),
            _ => vec![(key, value)],
        };
        for (name, value) in sections {
            match value.as_object() {
                Some(fields) => {
                    let category = categories.entry(name.clone()).or_insert_with(|| {
                        OrganizationViewCategory {
                            category: name.clone(),
                            fields: Vec::new(),
                            counts: Default::default(),
                        }
                    });
                    for (field, value) in fields {
                        note_field(category, field, value);
                    }
                }
                None => loose.push((name.clone(), value)),
            }
        }
    }
    if !loose.is_empty() {
        let category = categories
            .entry(LOOSE_CATEGORY.to_string())
            .or_insert_with(|| OrganizationViewCategory {
                category: LOOSE_CATEGORY.to_string(),
                fields: Vec::new(),
                counts: Default::default(),
            });
        for (field, value) in loose {
            note_field(category, &field, value);
        }
    }
    OrganizationView {
        sent_at: Some(record.sent_at.clone()),
        categories: categories
            .into_values()
            .filter(|category| !category.fields.is_empty())
            .map(|mut category| {
                category.fields.sort();
                category.fields.dedup();
                category
            })
            .collect(),
    }
}

fn note_field(category: &mut OrganizationViewCategory, field: &str, value: &Value) {
    let carries = match value {
        Value::Null => false,
        Value::String(text) => !text.is_empty(),
        Value::Array(rows) => !rows.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
        Value::Bool(_) | Value::Number(_) => true,
    };
    if !carries {
        return;
    }
    category.fields.push(field.to_string());
    if let Value::Array(rows) = value {
        category.counts.insert(field.to_string(), rows.len() as u64);
    }
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
    pub device_class: String,
    pub device_class_source: String,
    /// The device's package architecture (`x86_64`, `aarch64`), so a surface
    /// can tell BEFORE it offers an application whether this machine could
    /// install it. The catalogue file the shell reads is identical on every
    /// architecture — it lists each app's per-architecture sources — so
    /// without this the shell offered apps that only exist for another CPU
    /// and the refusal arrived after the person had chosen one.
    pub architecture: String,
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
    /// The os-release facts the inventory carries. The substrate's triple
    /// keeps its "unknown" placeholder (the M5 contract); Punar's own image
    /// identity is `null` when absent, because it is what a control plane
    /// shows as the version and a placeholder there would overwrite a real
    /// value. The image lines matter because Debian unstable, Punar's
    /// substrate, ships no VERSION_ID at all: the release a person and their
    /// organization know this device by is IMAGE_VERSION.
    fn os_release(&self) -> OsRelease {
        let content = std::fs::read_to_string(&self.os_release_path).unwrap_or_default();
        let field = |key: &str| -> Option<String> {
            content
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{key}=")))
                .map(|v| v.trim().trim_matches('"').to_string())
                .filter(|v| !v.is_empty())
        };
        let placeholder = |key: &str| field(key).unwrap_or_else(|| "unknown".to_string());
        OsRelease {
            id: placeholder("ID"),
            version_id: placeholder("VERSION_ID"),
            pretty_name: placeholder("PRETTY_NAME"),
            image_id: field("IMAGE_ID"),
            image_version: field("IMAGE_VERSION"),
        }
    }

    /// `IMAGE_VERSION`: the release every built-in application ships in.
    pub fn image_version(&self) -> Option<String> {
        self.os_release().image_version
    }

    fn kernel(&self) -> String {
        std::fs::read_to_string(&self.kernel_release_path)
            .map(|s| s.trim().to_string())
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".to_string())
    }
}

/// See [`InventorySources::os_release`].
struct OsRelease {
    id: String,
    version_id: String,
    pretty_name: String,
    image_id: Option<String>,
    image_version: Option<String>,
}

/// The inventory body (milestone-5.md section 6): device info, which
/// capabilities this device supports, and what [`crate::inventory`]
/// collected for this tier — `posture` and `hardware` for every managed
/// device, `applications` limited to the image's own unless
/// `organization_owned`, and `identifiers` only when it is. `capabilities`
/// carries `{capability, supported}` per registered capability.
///
/// It holds nothing that may not leave the device, because the resend gate
/// hashes exactly this body. It once also carried the hostname and every
/// capability's observed value (the hostname string, the timezone). Neither
/// was ever sent to Smplify, but both moved the hash: a laptop that joined a
/// network handing out another timezone sent a whole inventory at once, off
/// its daily schedule, and so told the organization when its owner
/// travelled. Capability states reach the organization only as the
/// compliance report's category states; the hostname, once, at registration.
///
/// The tier is applied here as well as in the collector, independently: this
/// is the last place the body exists before it leaves, so a system-wide
/// application or a serial number handed to it for a personal enrollment is
/// dropped, not sent.
///
/// Returns the body and, when the application list went out as `null`, why.
/// The list is never truncated: its receiver deletes every row it does not
/// see ([`crate::inventory::MAX_APPLICATIONS`]).
pub fn inventory_body(
    sources: &InventorySources,
    capabilities: impl IntoIterator<Item = (String, bool)>,
    collected: &Collected,
    organization_owned: bool,
) -> (Value, Option<Withheld>) {
    let os = sources.os_release();
    let applications = collected.applications_for(organization_owned);
    let mut body = json!({
        "os": {
            "id": os.id,
            "version_id": os.version_id,
            "pretty_name": os.pretty_name,
            "image_id": os.image_id,
            "image_version": os.image_version,
            "architecture": collected.architecture,
        },
        "kernel": sources.kernel(),
        "capabilities": capabilities
            .into_iter()
            .map(|(capability, supported)| json!({
                "capability": capability,
                "supported": supported,
            }))
            .collect::<Vec<Value>>(),
        "posture": collected.posture,
        "hardware": collected.hardware,
        "applications": applications.as_ref().ok(),
    });
    if organization_owned {
        body["identifiers"] = json!({ "serial_number": collected.serial_number });
    }
    let mut withheld = applications.err();
    if withheld.is_none() && serialized_len(&body) > MAX_INVENTORY_BYTES {
        body["applications"] = Value::Null;
        withheld = Some(Withheld::TooLarge);
    }
    (body, withheld)
}

fn serialized_len(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
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
            removable: true,
            organization_owned: false,
            last_inventory_sent_at: None,
        }
    }

    /// What `crate::inventory` hands the builder: a device with a serial, one
    /// image application and one system-wide Flatpak, so a test can see
    /// which of them each tier lets through.
    fn collected() -> Collected {
        use crate::inventory::{
            Application, Hardware, PatchStatus, Posture, SOURCE_FLATPAK, SOURCE_IMAGE,
        };
        let row = |name: &str, source: &'static str| Application {
            name: name.into(),
            display_name: name.into(),
            version: Some("1.0".into()),
            source,
            managed: false,
        };
        Collected {
            architecture: "aarch64".into(),
            posture: Posture {
                secure_boot: Some(false),
                uefi: Some(true),
                tpm_present: Some(true),
                tpm_version: Some("2.0".into()),
                is_virtual: Some(true),
                virtualization: Some("qemu".into()),
                disk_encryption_enabled: Some(true),
                firewall_enabled: Some(true),
                firewall: Some("nftables".into()),
                os_patch_status: PatchStatus::Unknown,
                reboot_required: Some(false),
            },
            hardware: Hardware {
                manufacturer: Some("QEMU".into()),
                model_name: Some("QEMU Virtual Machine".into()),
                bios_version: Some("edk2-stable202408".into()),
                cpu_model: None,
                cpu_vendor: None,
                cpu_cores: Some(4),
                cpu_threads: Some(4),
                memory_total_bytes: Some(8 * 1024 * 1024 * 1024),
                device_capacity_bytes: Some(64_000_000_000),
                root_filesystem_type: Some("erofs".into()),
                battery_present: Some(false),
            },
            applications: Ok(vec![
                row("org.punar.Mail", SOURCE_IMAGE),
                row("org.mozilla.firefox", SOURCE_FLATPAK),
            ]),
            serial_number: Some("PNR-SERIAL-0042".into()),
        }
    }

    fn sorted_keys(value: &Value) -> Vec<&str> {
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        keys
    }

    fn fixture_sources(dir: &Path) -> InventorySources {
        let os_release = dir.join("os-release");
        std::fs::write(
            &os_release,
            "ID=debian\nIMAGE_ID=punar-desktop\nIMAGE_VERSION=2026.09.01.1\n",
        )
        .unwrap();
        let kernel = dir.join("osrelease");
        std::fs::write(&kernel, "6.12.0-punar\n").unwrap();
        InventorySources {
            os_release_path: os_release,
            kernel_release_path: kernel,
        }
    }

    const PERSONAL_KEYS: [&str; 6] = [
        "applications",
        "capabilities",
        "hardware",
        "kernel",
        "os",
        "posture",
    ];

    /// The privacy boundary per tier, as exact key sets: a personal
    /// enrollment gets no `identifiers` and only the image's applications,
    /// even when the collector hands the builder more.
    #[test]
    fn each_tier_sends_exactly_its_key_set() {
        let dir = tmp("tiers");
        let sources = fixture_sources(&dir);
        let collected = collected();

        let (personal, withheld) = inventory_body(&sources, [], &collected, false);
        assert_eq!(withheld, None);
        assert_eq!(sorted_keys(&personal), PERSONAL_KEYS);
        assert_eq!(
            sorted_keys(&personal["os"]),
            [
                "architecture",
                "id",
                "image_id",
                "image_version",
                "pretty_name",
                "version_id"
            ]
        );
        assert_eq!(personal["os"]["architecture"], "aarch64");
        assert_eq!(
            sorted_keys(&personal["posture"]),
            [
                "disk_encryption_enabled",
                "firewall",
                "firewall_enabled",
                "is_virtual",
                "os_patch_status",
                "reboot_required",
                "secure_boot",
                "tpm_present",
                "tpm_version",
                "uefi",
                "virtualization"
            ]
        );
        assert_eq!(
            sorted_keys(&personal["hardware"]),
            [
                "battery_present",
                "bios_version",
                "cpu_cores",
                "cpu_model",
                "cpu_threads",
                "cpu_vendor",
                "device_capacity_bytes",
                "manufacturer",
                "memory_total_bytes",
                "model_name",
                "root_filesystem_type"
            ]
        );
        assert_eq!(
            personal["applications"],
            json!([{
                "name": "org.punar.Mail", "display_name": "org.punar.Mail",
                "version": "1.0", "source": "punar-image", "managed": false,
            }])
        );
        let text = personal.to_string();
        assert!(
            !text.contains("PNR-SERIAL-0042"),
            "no serial on a personal device"
        );
        assert!(!text.contains("firefox"), "no app the person chose");

        let (owned, withheld) = inventory_body(&sources, [], &collected, true);
        assert_eq!(withheld, None);
        let mut keys = PERSONAL_KEYS.to_vec();
        keys.push("identifiers");
        keys.sort_unstable();
        assert_eq!(sorted_keys(&owned), keys);
        assert_eq!(
            owned["identifiers"],
            json!({ "serial_number": "PNR-SERIAL-0042" })
        );
        let names: Vec<&str> = owned["applications"]
            .as_array()
            .unwrap()
            .iter()
            .map(|app| app["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["org.punar.Mail", "org.mozilla.firefox"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The body carries facts, never values that locate or identify a
    /// person: no hostname and no capability value (there is no parameter
    /// left to hand one over), no addresses, nothing from /home. A capability
    /// is named with whether it is supported, and nothing else.
    #[test]
    fn the_body_carries_no_personal_values() {
        let dir = tmp("no-values");
        let sources = fixture_sources(&dir);
        let (body, _) = inventory_body(
            &sources,
            [("time.timezone".to_string(), true)],
            &collected(),
            true,
        );
        assert_eq!(
            body["capabilities"],
            json!([{"capability": "time.timezone", "supported": true}])
        );
        let text = body.to_string();
        for forbidden in ["hostname", "current_state", "/home", "machine-id"] {
            assert!(!text.contains(forbidden), "the body carries {forbidden}");
        }
        assert!(!looks_like_mac_or_ipv4(&text), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `aa:bb:cc:dd:ee:ff`, or four dot-separated numbers of at most three
    /// digits each — the shapes an address would have if one leaked.
    fn looks_like_mac_or_ipv4(text: &str) -> bool {
        let mut tokens = text.split(|c: char| !(c.is_ascii_hexdigit() || c == ':' || c == '.'));
        tokens.any(|token| {
            let mac = token.split(':').collect::<Vec<_>>();
            let ip = token.split('.').collect::<Vec<_>>();
            (mac.len() == 6 && mac.iter().all(|p| p.len() == 2))
                || (ip.len() == 4
                    && ip.iter().all(|p| {
                        (1..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit())
                    }))
        })
    }

    #[test]
    fn the_address_detector_itself_detects() {
        assert!(looks_like_mac_or_ipv4("\"52:54:00:12:34:56\""));
        assert!(looks_like_mac_or_ipv4("gw 10.0.2.2 x"));
        assert!(!looks_like_mac_or_ipv4("2026.09.01.1 151.0.7922.173-1"));
    }

    /// Never truncated: over the size cap the list goes out as `null`, and
    /// the caller is told why so it can audit it.
    #[test]
    fn an_oversized_inventory_withholds_its_application_list() {
        use crate::inventory::{Application, SOURCE_IMAGE};
        let dir = tmp("oversized");
        let sources = fixture_sources(&dir);
        let mut collected = collected();
        collected.applications = Ok((0..1900)
            .map(|i| Application {
                name: format!("org.punar.{i}.{}", "x".repeat(200)),
                display_name: "y".repeat(255),
                version: Some("z".repeat(100)),
                source: SOURCE_IMAGE,
                managed: false,
            })
            .collect());
        let (body, withheld) = inventory_body(&sources, [], &collected, false);
        assert_eq!(withheld, Some(Withheld::TooLarge));
        assert_eq!(body["applications"], Value::Null);
        assert!(serde_json::to_vec(&body).unwrap().len() <= MAX_INVENTORY_BYTES);

        collected.applications = Err(Withheld::Unreadable);
        let (body, withheld) = inventory_body(&sources, [], &collected, true);
        assert_eq!(withheld, Some(Withheld::Unreadable));
        assert_eq!(body["applications"], Value::Null);
        assert_eq!(body["identifiers"]["serial_number"], "PNR-SERIAL-0042");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// punard's body through the agent's own translation, the composition a
    /// real sync performs: each tier reaches Smplify as exactly its
    /// allowlist, and a list over either cap arrives as `null`, never cut.
    #[test]
    fn each_tier_reaches_smplify_as_exactly_its_allowlist() {
        use crate::inventory::{Application, MAX_APPLICATIONS, SOURCE_IMAGE};
        let dir = tmp("composed");
        let sources = fixture_sources(&dir);
        let compose = |collected: &Collected, owned: bool| {
            let (inventory, withheld) = inventory_body(
                &sources,
                [("time.timezone".to_string(), true)],
                collected,
                owned,
            );
            (
                punar_smplifyd::status::inventory_status_body("dev-1", &inventory),
                withheld,
            )
        };
        let names = |body: &Value| -> Vec<String> {
            body["systemInfo"]["software"]["installedPackages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["name"].as_str().unwrap().to_string())
                .collect()
        };

        let (personal, withheld) = compose(&collected(), false);
        assert_eq!(withheld, None);
        let personal_hardware = sorted_keys(&personal["systemInfo"]["hardware"]);
        assert_eq!(personal_hardware.len(), 17);
        assert!(!personal_hardware.contains(&"serialNumber"));
        assert_eq!(names(&personal), ["org.punar.Mail"]);
        assert_eq!(personal["systemInfo"]["os"]["name"], "Punar OS");
        assert_eq!(personal["systemInfo"]["os"]["arch"], "aarch64");
        assert_eq!(personal["systemInfo"]["hardware"]["cpuModel"], Value::Null);

        let (owned, _) = compose(&collected(), true);
        let mut owned_hardware = personal_hardware.clone();
        owned_hardware.push("serialNumber");
        owned_hardware.sort_unstable();
        assert_eq!(
            sorted_keys(&owned["systemInfo"]["hardware"]),
            owned_hardware
        );
        assert_eq!(
            owned["systemInfo"]["hardware"]["serialNumber"],
            "PNR-SERIAL-0042"
        );
        assert_eq!(names(&owned), ["org.punar.Mail", "org.mozilla.firefox"]);
        for body in [&personal, &owned] {
            assert_eq!(
                sorted_keys(&body["systemInfo"]),
                ["hardware", "os", "security", "software"]
            );
            let text = body.to_string();
            for forbidden in ["hostname", "current_state", "capabilities"] {
                assert!(!text.contains(forbidden), "{forbidden} reached Smplify");
            }
            assert!(!looks_like_mac_or_ipv4(&text), "{text}");
        }
        assert!(!personal.to_string().contains("PNR-SERIAL-0042"));

        let row = |i: usize, filler: usize| Application {
            name: format!("org.punar.App{i}{}", "x".repeat(filler)),
            display_name: "y".repeat(filler.min(255)),
            version: Some("z".repeat(filler.min(100))),
            source: SOURCE_IMAGE,
            managed: false,
        };
        let mut full = collected();
        full.applications = Ok((0..MAX_APPLICATIONS).map(|i| row(i, 0)).collect());
        let (body, withheld) = compose(&full, false);
        assert_eq!(withheld, None);
        assert_eq!(
            body["systemInfo"]["software"]["installedPackagesCount"],
            MAX_APPLICATIONS
        );
        let mut too_many = collected();
        too_many.applications = Ok((0..=MAX_APPLICATIONS).map(|i| row(i, 0)).collect());
        let mut too_large = collected();
        too_large.applications = Ok((0..1900).map(|i| row(i, 200)).collect());
        for (collected, reason) in [
            (too_many, Withheld::TooMany),
            (too_large, Withheld::TooLarge),
        ] {
            let (body, withheld) = compose(&collected, false);
            assert_eq!(withheld, Some(reason));
            let software = &body["systemInfo"]["software"];
            assert_eq!(software["installedPackages"], Value::Null, "{reason:?}");
            assert_eq!(software["installedPackagesCount"], Value::Null);
            assert_eq!(software["installedPackagesHash"], Value::Null);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn view_record(enrollment: &Enrollment, sent: Value) -> OrganizationViewRecord {
        OrganizationViewRecord {
            version: 1,
            org_id: enrollment.org.id.clone(),
            enrolled_at: enrollment.enrolled_at.clone(),
            sent_at: "2026-09-24T10:00:00Z".into(),
            sent,
        }
    }

    /// The person is told what their organization received, read from the
    /// body that left: punard's inventory through the agent's own
    /// translation, as Smplify has it. Field names that carried a value,
    /// never the values, and never a field that did not travel.
    #[test]
    fn the_organization_view_names_exactly_what_was_sent() {
        let dir = tmp("view-summary");
        let sources = fixture_sources(&dir);
        let (inventory, _) = inventory_body(
            &sources,
            [("time.timezone".to_string(), true)],
            &collected(),
            false,
        );
        let sent = punar_smplifyd::status::inventory_status_body("dev-1", &inventory);
        let view = organization_view_summary(Some(&view_record(&sample_enrollment(), sent)));
        assert_eq!(view.sent_at.as_deref(), Some("2026-09-24T10:00:00Z"));
        let names: Vec<&str> = view
            .categories
            .iter()
            .map(|category| category.category.as_str())
            .collect();
        assert_eq!(names, ["hardware", "os", "security", "software"]);
        let hardware = &view.categories[0].fields;
        assert!(hardware.contains(&"modelName".to_string()));
        // Collected as unknown, sent as null: nothing the organization sees.
        assert!(!hardware.contains(&"cpuModel".to_string()));
        assert!(!hardware.contains(&"serialNumber".to_string()));
        assert_eq!(
            view.categories[1].fields,
            ["arch", "kernelRelease", "name", "version"]
        );
        assert_eq!(view.categories[3].counts.get("installedPackages"), Some(&1));
        let text = serde_json::to_string(&view).unwrap();
        for value in ["QEMU", "PNR-SERIAL-0042", "org.punar.Mail", "hostname"] {
            assert!(!text.contains(value), "the summary carries {value}");
        }

        let nothing = organization_view_summary(None);
        assert_eq!(nothing.sent_at, None);
        assert!(nothing.categories.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Null, empty strings, empty lists and empty sections told the
    /// organization nothing; the envelope is not a fact about the device;
    /// a value outside any section is listed under `device`.
    #[test]
    fn the_organization_view_skips_what_carried_nothing() {
        let sent = json!({
            "deviceId": "d-1",
            "heartbeat": "2026-09-24T10:00:00Z",
            "systemInfo": {"os": {"name": "Punar OS", "version": null}, "network": {}},
            "supportedActions": [],
            "facts": {},
            "hostname": "",
            "kernel": "6.12.0-punar",
            "applications": [{"name": "a"}, {"name": "b"}],
        });
        let view = organization_view_summary(Some(&view_record(&sample_enrollment(), sent)));
        assert_eq!(
            view.categories,
            vec![
                OrganizationViewCategory {
                    category: "device".into(),
                    fields: vec!["applications".into(), "kernel".into()],
                    counts: [("applications".to_string(), 2)].into(),
                },
                OrganizationViewCategory {
                    category: "os".into(),
                    fields: vec!["name".into()],
                    counts: Default::default(),
                },
            ]
        );
    }

    /// A view belongs to one enrollment and is group-readable, no wider.
    /// Anything that is not a view punard wrote for this enrollment reads as
    /// none, so a stale or damaged file is never shown as the truth.
    #[test]
    fn the_organization_view_is_bound_to_its_enrollment() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmp("view-store");
        let path = dir.join(ORGANIZATION_VIEW_FILE);
        let enrollment = sample_enrollment();
        let record = view_record(
            &enrollment,
            json!({"systemInfo": {"os": {"name": "Punar OS"}}}),
        );
        save_organization_view(&path, &record, None).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(load_organization_view(&path, &enrollment), Some(record));

        let mut later = enrollment.clone();
        later.enrolled_at = "2026-09-25T09:00:00Z".into();
        assert_eq!(load_organization_view(&path, &later), None);
        let mut other = enrollment.clone();
        other.org.id = "globex".into();
        assert_eq!(load_organization_view(&path, &other), None);
        std::fs::write(&path, "{not json").unwrap();
        assert_eq!(load_organization_view(&path, &enrollment), None);
        std::fs::write(&path, vec![b' '; ORGANIZATION_VIEW_MAX_BYTES as usize + 1]).unwrap();
        assert_eq!(load_organization_view(&path, &enrollment), None);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(load_organization_view(&path, &enrollment), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unchanged_inventory_is_resent_after_a_day() {
        let sent = "2026-09-24T10:00:00Z";
        assert!(inventory_resend_due(None, sent));
        assert!(!inventory_resend_due(Some(sent), "2026-09-24T10:00:01Z"));
        assert!(!inventory_resend_due(Some(sent), "2026-09-25T09:59:59Z"));
        assert!(inventory_resend_due(Some(sent), "2026-09-25T10:00:00Z"));
        assert!(
            inventory_resend_due(Some(sent), "2026-09-23T10:00:00Z"),
            "clock moved back"
        );
        assert!(inventory_resend_due(Some("yesterday"), sent));
    }

    /// Both fields default for a file an older build wrote, and the default
    /// tier is the narrow one.
    #[test]
    fn ownership_and_send_time_round_trip_and_default_narrow() {
        let dir = tmp("owned");
        let path = dir.join("enrollment.json");
        let mut owned = sample_enrollment();
        owned.organization_owned = true;
        owned.last_inventory_sent_at = Some("2026-09-24T10:00:00Z".into());
        save_enrollment(&path, &owned).unwrap();
        assert_eq!(load_enrollment(&path).unwrap().unwrap(), owned);

        let mut raw: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        raw.as_object_mut().unwrap().remove("organization_owned");
        raw.as_object_mut()
            .unwrap()
            .remove("last_inventory_sent_at");
        std::fs::write(&path, raw.to_string()).unwrap();
        let older = load_enrollment(&path).unwrap().unwrap();
        assert!(!older.organization_owned);
        assert_eq!(older.last_inventory_sent_at, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Removability is fixed at enrollment and survives a restart. A file
    /// written before the field existed, and with no term beside it, reads as
    /// removable, exactly as an organization document without the key does.
    #[test]
    fn removability_persists_and_a_file_without_it_reads_as_removable() {
        let dir = tmp("removable");
        let path = dir.join("enrollment.json");
        let mut fixed = sample_enrollment();
        fixed.removable = false;
        save_enrollment(&path, &fixed).unwrap();
        assert!(!load_enrollment(&path).unwrap().unwrap().removable);

        remove_terms(&path).unwrap();
        let mut raw: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        raw.as_object_mut().unwrap().remove("removable");
        std::fs::write(&path, raw.to_string()).unwrap();
        assert!(load_enrollment(&path).unwrap().unwrap().removable);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An older punard, booted from a retained UKI, rewrites enrollment.json
    /// without the field. The term kept beside it, which that build never
    /// touches, keeps the device non-removable. A term left from another
    /// enrollment is ignored, and a term can only take removability away.
    #[test]
    fn the_removal_term_survives_an_older_build_rewriting_the_enrollment() {
        let dir = tmp("terms");
        let path = dir.join("enrollment.json");
        let mut kept = sample_enrollment();
        kept.removable = false;
        save_enrollment(&path, &kept).unwrap();
        assert!(dir.join(TERMS_FILE).is_file());

        // What a pre-term build writes back on its next sync.
        let mut raw: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        raw.as_object_mut().unwrap().remove("removable");
        std::fs::write(&path, raw.to_string()).unwrap();
        let reloaded = load_enrollment(&path).unwrap().unwrap();
        assert!(!reloaded.removable, "the term outlived the rewrite");
        // Saving it again restores the field in enrollment.json itself.
        save_enrollment(&path, &reloaded).unwrap();
        let raw: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(raw["removable"], false);

        // A term for another enrollment (an older build ended that one and a
        // removable one began) does not apply.
        let mut other = sample_enrollment();
        other.enrolled_at = "2026-09-30T00:00:00Z".into();
        std::fs::write(&path, serde_json::to_vec(&other).unwrap()).unwrap();
        assert!(load_enrollment(&path).unwrap().unwrap().removable);

        // A term that says "removable" never loosens a file that says not.
        save_enrollment(&path, &sample_enrollment()).unwrap();
        let mut raw: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        raw["removable"] = serde_json::json!(false);
        std::fs::write(&path, raw.to_string()).unwrap();
        assert!(!load_enrollment(&path).unwrap().unwrap().removable);

        // A corrupt term refuses, like a corrupt enrollment.
        std::fs::write(dir.join(TERMS_FILE), b"{not json").unwrap();
        assert!(load_enrollment(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
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
                device_class: "laptop".into(),
                device_class_source: "observed".into(),
                architecture: "aarch64".into(),
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
        // exactly what the shell renders or uses for its resident-cost
        // choice (serde_json emits keys sorted).
        assert_eq!(
            keys,
            [
                "architecture",
                "compliance_overall",
                "device_class",
                "device_class_source",
                "enrolled",
                "org_name",
                "ts",
                "v"
            ]
        );
        assert_eq!(raw["org_name"], "Acme Engineering");
        // The shell decides whether to OFFER an application on this value, so
        // an empty or absent one has to be readable as "not known yet" rather
        // than as an architecture nothing matches.
        assert_eq!(raw["architecture"], "aarch64");
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
        let (inventory, _) = inventory_body(
            &sources,
            [("security.firewall".to_string(), true)],
            &collected(),
            false,
        );
        assert_eq!(inventory["os"]["id"], "punar");
        assert_eq!(inventory["os"]["version_id"], "0.5");
        assert_eq!(inventory["os"]["pretty_name"], "Punar OS 0.5 (M5)");
        assert_eq!(inventory["os"]["image_id"], Value::Null);
        assert_eq!(inventory["os"]["image_version"], Value::Null);
        assert_eq!(inventory["kernel"], "6.12.0-punar");
        assert_eq!(inventory.get("hostname"), None);
        assert_eq!(
            inventory["capabilities"],
            json!([{"capability": "security.firewall", "supported": true}])
        );

        let absent = InventorySources {
            os_release_path: dir.join("missing"),
            kernel_release_path: dir.join("also-missing"),
        };
        let (degraded, _) = inventory_body(&absent, [], &collected(), false);
        assert_eq!(degraded["os"]["id"], "unknown");
        assert_eq!(degraded["kernel"], "unknown");

        // Debian unstable, Punar's substrate, has no VERSION_ID; Punar's own
        // release is IMAGE_VERSION, and it is what the inventory carries.
        let punar = dir.join("os-release-punar");
        std::fs::write(
            &punar,
            "PRETTY_NAME=\"Debian GNU/Linux forky/sid\"\nID=debian\n\
             IMAGE_ID=punar-desktop\nIMAGE_VERSION=2026.09.01.1\n",
        )
        .unwrap();
        let sid = InventorySources {
            os_release_path: punar,
            kernel_release_path: dir.join("osrelease"),
        };
        let (inventory, _) = inventory_body(&sid, [], &collected(), false);
        assert_eq!(inventory["os"]["version_id"], "unknown");
        assert_eq!(inventory["os"]["image_id"], "punar-desktop");
        assert_eq!(inventory["os"]["image_version"], "2026.09.01.1");
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

    /// Every call punard makes waits at least a second longer than the
    /// built-in agent may spend on the organization's server for it, so an
    /// answer the agent has is never read as "unreachable".
    #[test]
    fn every_call_waits_out_what_the_agent_may_spend_on_it() {
        for method in [
            "org.discover",
            "enroll.register",
            "enroll.unregister",
            "policy.fetch",
            "compliance.report",
            "inventory.report",
            "recovery.key",
            "recovery.escrow",
            CP_METHOD_QUERIES_PENDING,
            CP_METHOD_QUERIES_ANSWER,
        ] {
            let budget = punar_smplifyd::budget::call_budget(method);
            assert!(
                call_timeout(method) >= budget + Duration::from_secs(1),
                "{method}: punard waits {:?}, the agent may spend {budget:?}",
                call_timeout(method)
            );
        }
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
