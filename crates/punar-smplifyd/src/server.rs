//! The root-only socket and the method table. One request per connection,
//! sequentially: punard is the only client, it makes one call at a time, and
//! nothing here long-polls inside a call.
//!
//! Peer admission is `SO_PEERCRED` uid 0 — the mock deliberately relies on
//! filesystem admission alone (milestone-5.md section 4.2); the real daemon
//! does both, because its answers carry the organisation's word.
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::discovery::{self, Organization};
use crate::identity::{self, Record, Store};
use crate::protocol::{CallError, ErrorCode, error_line, parse_request_line, result_line};
use crate::upstream::{Api, UpstreamError};

const MAX_LINE_BYTES: usize = 1024 * 1024;
const LINE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Daemon {
    store: Store,
    discovery_dir: PathBuf,
    os_release_path: PathBuf,
    /// The organisation `org.discover` last resolved: `enroll.register`
    /// carries no domain, so it enrols into the organisation punard just
    /// asked about, exactly as the mock does.
    pending: Mutex<Option<Organization>>,
}

impl Daemon {
    pub fn new(state_dir: impl Into<PathBuf>, discovery_dir: impl Into<PathBuf>) -> Daemon {
        Daemon {
            store: Store::new(state_dir),
            discovery_dir: discovery_dir.into(),
            os_release_path: PathBuf::from("/etc/os-release"),
            pending: Mutex::new(None),
        }
    }

    #[cfg(test)]
    pub fn with_os_release(mut self, path: impl Into<PathBuf>) -> Daemon {
        self.os_release_path = path.into();
        self
    }

    /// socket → bind → chmod 0600 → listen, then serve forever.
    pub fn serve(&self, socket: &Path) -> std::io::Result<()> {
        if let Some(parent) = socket.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match std::fs::remove_file(socket) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let listener = UnixListener::bind(socket)?;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
        eprintln!("punar-smplifyd: serving {}", socket.display());
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => self.handle(stream),
                Err(e) => eprintln!("punar-smplifyd: accept failed ({})", e.kind()),
            }
        }
        Ok(())
    }

    fn handle(&self, mut stream: UnixStream) {
        if !peer_is_root(&stream) {
            // Silence is the answer: an unprivileged peer learns nothing,
            // not even that a control plane lives here.
            return;
        }
        let _ = stream.set_read_timeout(Some(LINE_TIMEOUT));
        let _ = stream.set_write_timeout(Some(LINE_TIMEOUT));
        let mut line = String::new();
        {
            let mut reader = BufReader::new(&stream);
            let mut bounded = (&mut reader).take((MAX_LINE_BYTES + 1) as u64);
            if bounded.read_line(&mut line).is_err() || line.len() > MAX_LINE_BYTES {
                return;
            }
        }
        let answer = self.answer_line(line.trim_end_matches(['\r', '\n']));
        let _ = stream.write_all(answer.as_bytes());
        let _ = stream.flush();
    }

    pub fn answer_line(&self, line: &str) -> String {
        let request = match parse_request_line(line) {
            Ok(request) => request,
            Err(error) => return error_line(None, &error),
        };
        match self.dispatch(&request.method, request.params.as_ref()) {
            Ok(result) => result_line(&request.id, &result),
            Err(error) => error_line(Some(&request.id), &error),
        }
    }

    pub fn dispatch(&self, method: &str, params: Option<&Value>) -> Result<Value, CallError> {
        match method {
            "org.discover" => self.org_discover(params),
            "enroll.register" => self.enroll_register(params),
            "enroll.unregister" => self.enroll_unregister(params),
            "identity.status" => self.identity_status(),
            "policy.fetch" => self.policy_fetch(params),
            "compliance.report" => {
                self.report(params, "report", crate::upstream::compliance_status_body)
            }
            "inventory.report" => {
                self.report(params, "inventory", crate::upstream::inventory_status_body)
            }
            "queries.pending" => {
                self.authorized(params)?;
                Ok(json!({ "queries": [] }))
            }
            "queries.answer" => {
                self.authorized(params)?;
                Ok(json!({}))
            }
            "recovery.key" | "recovery.escrow" => Err(CallError::new(
                ErrorCode::OutOfScope,
                "organization recovery escrow is not available through Smplify in this release",
            )),
            _ => Err(CallError::new(
                ErrorCode::UnknownMethod,
                format!("{method} is not a method"),
            )),
        }
    }

    fn org_discover(&self, params: Option<&Value>) -> Result<Value, CallError> {
        let domain = param_str(params, "domain")?;
        let organization = discovery::discover(&self.discovery_dir, &domain)?;
        let document = organization.document.clone();
        *self.pending.lock().unwrap() = Some(organization);
        Ok(json!({ "organization": document }))
    }

    fn enroll_register(&self, params: Option<&Value>) -> Result<Value, CallError> {
        let device_id = param_str(params, "device_id")?;
        let code = Zeroizing::new(param_str(params, "code").map_err(|_| {
            CallError::new(
                ErrorCode::InvalidParams,
                "an enrollment code is required: punarctl enroll start <domain> reads it from stdin",
            )
        })?);
        let organization = self.pending.lock().unwrap().clone().ok_or_else(|| {
            CallError::new(
                ErrorCode::InvalidParams,
                "no organization was discovered before registering",
            )
        })?;

        let os_release = crate::device::os_release(&self.os_release_path);
        let anonymous = Api::anonymous(&organization.server).map_err(internal)?;
        let os_identifier = anonymous
            .resolve_os(&os_release)
            .ok()
            .flatten()
            .unwrap_or_else(|| crate::device::CANONICAL_OS_IDENTIFIER.to_string());
        eprintln!(
            "punar-smplifyd: registering with {} as {}",
            organization.server.origin(),
            os_identifier
        );

        let csr = identity::generate_csr().map_err(internal)?;
        let enrolled = anonymous
            .enroll(
                &code,
                &csr.csr_pem,
                &crate::device::hostname(),
                &os_identifier,
                &device_id,
            )
            .map_err(enrollment_refusal)?;
        drop(code);
        // punard asks for a registration only while it holds no enrollment,
        // so an identity still here is one it never committed: left by an
        // enrollment that failed after register on a build that did not
        // release it, or by state punard lost. Keeping it would strand the
        // device (punard says unenrolled, so `enroll stop` has nothing to
        // stop). It is replaced only now, after Smplify has accepted the new
        // code, so a mistyped code never costs a working identity; the old
        // files go first so no half-old, half-new identity is ever on disk.
        if let Ok(Some(stale)) = self.store.load() {
            eprintln!(
                "punar-smplifyd: replacing an identity punard never committed (device {})",
                stale.device_id
            );
        }
        if self.store.exists() {
            self.store.wipe().map_err(internal)?;
        }

        let (token, token_sha256) = identity::new_device_token().map_err(internal)?;
        let mut record = Record {
            device_id: enrolled.device_id.clone(),
            server: organization.server.origin(),
            org_id: organization.id.clone(),
            org_name: organization.name.clone(),
            os_identifier: os_identifier.clone(),
            not_after: enrolled.not_after.clone(),
            tenant_public_key: None,
            token_sha256,
            enrolled_at: crate::clock::now_rfc3339(),
        };
        self.store
            .save(&record, &csr.key_pem, &enrolled.cert_pem, &enrolled.ca_pem)
            .map_err(internal)?;

        // First check-in over the new identity pins the tenant's signing
        // key. A failure here is reported but does not undo the enrollment:
        // the certificate is issued and the next sync retries.
        match self.api().and_then(|api| {
            api.checkin(&enrolled.device_id, &os_identifier, &os_release)
                .map_err(internal)
        }) {
            Ok(tenant_key) => {
                record.tenant_public_key = tenant_key;
                let _ = self.store.update(&record);
            }
            Err(error) => eprintln!(
                "punar-smplifyd: first check-in deferred ({})",
                error.message
            ),
        }

        *self.pending.lock().unwrap() = None;
        Ok(json!({
            "device_token": &*token,
            "attestation": "none",
            "organization": organization.document,
        }))
    }

    fn enroll_unregister(&self, params: Option<&Value>) -> Result<Value, CallError> {
        self.authorized(params)?;
        self.store.wipe().map_err(internal)?;
        Ok(json!({}))
    }

    fn identity_status(&self) -> Result<Value, CallError> {
        match self.store.load().map_err(internal)? {
            Some(record) => Ok(json!({
                "enrolled": true,
                "device_id": record.device_id,
                "server": record.server,
                "org_id": record.org_id,
                "org_name": record.org_name,
                "os_identifier": record.os_identifier,
                "not_after": record.not_after,
                "tenant_key_pinned": record.tenant_public_key.is_some(),
                "enrolled_at": record.enrolled_at,
            })),
            None => Ok(json!({ "enrolled": false })),
        }
    }

    fn policy_fetch(&self, params: Option<&Value>) -> Result<Value, CallError> {
        let record = self.authorized(params)?;
        let api = self.api()?;
        match api.bundle(&record.device_id).map_err(upstream_refusal)? {
            None => Ok(json!({ "policies": [] })),
            Some(bundle) => {
                // A bundle exists but this release carries no Punar policy
                // payload: nothing is applied, and the fact is logged rather
                // than reported as a refusal punard would misread as "is the
                // control plane running?".
                eprintln!(
                    "punar-smplifyd: a {}-byte bundle (delivery {}) is assigned to this device but carries no Punar policy; ignored",
                    bundle.bytes.len(),
                    bundle.delivery_id.as_deref().unwrap_or("unknown")
                );
                Ok(json!({ "policies": [] }))
            }
        }
    }

    fn report(
        &self,
        params: Option<&Value>,
        key: &str,
        compose: fn(&str, &Value) -> Value,
    ) -> Result<Value, CallError> {
        let record = self.authorized(params)?;
        let payload = params.and_then(|p| p.get(key)).ok_or_else(|| {
            CallError::new(ErrorCode::InvalidParams, format!("{key} is required"))
        })?;
        self.pin_tenant_key_if_missing(&record);
        let body = compose(&record.device_id, payload);
        self.api()?
            .status(&record.device_id, &body)
            .map_err(upstream_refusal)?;
        Ok(json!({}))
    }

    /// Pin the organization's signing key if the check-in at registration
    /// did not. That first check-in is allowed to fail without undoing the
    /// enrollment, so this is the "next sync retries" its comment promises:
    /// one check-in per report until the key is held, then never again. It is
    /// pinned once and never replaced here: a key that changes under a pinned
    /// device is a question for re-enrollment, not for a sync.
    fn pin_tenant_key_if_missing(&self, record: &Record) {
        if record.tenant_public_key.is_some() {
            return;
        }
        let os_release = crate::device::os_release(&self.os_release_path);
        let answer = self.api().and_then(|api| {
            api.checkin(&record.device_id, &record.os_identifier, &os_release)
                .map_err(internal)
        });
        match answer {
            Ok(Some(key)) => {
                let mut pinned = record.clone();
                pinned.tenant_public_key = Some(key);
                if let Err(error) = self.store.update(&pinned) {
                    eprintln!("punar-smplifyd: could not store the tenant key ({error:?})");
                }
            }
            Ok(None) => {
                eprintln!(
                    "punar-smplifyd: check-in answered without a tenant key; retrying next sync"
                )
            }
            Err(error) => eprintln!(
                "punar-smplifyd: check-in deferred again ({}); retrying next sync",
                error.message
            ),
        }
    }

    /// The identity punard's `device_token` names, or `unauthorized`.
    fn authorized(&self, params: Option<&Value>) -> Result<Record, CallError> {
        let presented = param_str(params, "device_token")?;
        let record = self.store.load().map_err(internal)?.ok_or_else(|| {
            CallError::new(
                ErrorCode::Unauthorized,
                "this device holds no Smplify identity",
            )
        })?;
        if !identity::token_matches(&record, &presented) {
            return Err(CallError::new(
                ErrorCode::Unauthorized,
                "the device token does not match this identity",
            ));
        }
        Ok(record)
    }

    fn api(&self) -> Result<Api, CallError> {
        let record = self.store.load().map_err(internal)?.ok_or_else(|| {
            CallError::new(
                ErrorCode::Unauthorized,
                "this device holds no Smplify identity",
            )
        })?;
        let server = crate::http::parse_https_url(&record.server).map_err(|_| {
            CallError::new(ErrorCode::Internal, "the stored server origin is invalid")
        })?;
        let identity = self.store.client_identity().map_err(internal)?;
        Api::with_identity(&server, identity).map_err(internal)
    }
}

fn param_str(params: Option<&Value>, key: &str) -> Result<String, CallError> {
    params
        .and_then(|p| p.get(key))
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CallError::new(ErrorCode::InvalidParams, format!("{key} is required")))
}

fn internal(error: impl std::fmt::Display) -> CallError {
    CallError::new(ErrorCode::Internal, error.to_string())
}

/// `/enroll` refusals, in the person's terms. 401 is the code; 409 is a
/// device or fleet conflict; anything else is the server's own message.
fn enrollment_refusal(error: UpstreamError) -> CallError {
    match error.status() {
        Some(401) | Some(403) => CallError::new(
            ErrorCode::Unauthorized,
            "Smplify did not accept the enrollment code (expired, revoked, already used, or mistyped)",
        ),
        Some(409) => CallError::new(
            ErrorCode::Denied,
            format!("Smplify refused this device ({error})"),
        ),
        Some(_) | None => CallError::new(ErrorCode::Internal, error.to_string()),
    }
}

fn upstream_refusal(error: UpstreamError) -> CallError {
    match error.status() {
        Some(401) | Some(403) => CallError::new(ErrorCode::Unauthorized, error.to_string()),
        Some(404) => CallError::new(ErrorCode::NotFound, "Smplify no longer knows this device"),
        _ => CallError::new(ErrorCode::Internal, error.to_string()),
    }
}

fn peer_is_root(stream: &UnixStream) -> bool {
    match rustix::net::sockopt::socket_peercred(stream) {
        Ok(cred) => cred.uid.is_root(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn daemon() -> (Daemon, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "punar-smplifyd-srv-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("discovery")).unwrap();
        let d = Daemon::new(root.join("state"), root.join("discovery"))
            .with_os_release(root.join("os-release"));
        (d, root)
    }

    #[test]
    fn unknown_methods_bad_envelopes_and_missing_identity_are_refused() {
        let (d, root) = daemon();
        let line = d.answer_line(r#"{"v":1,"id":"a","method":"nope.nope"}"#);
        assert!(line.contains(r#""code":"unknown_method""#));
        let line = d.answer_line("not json");
        assert!(line.contains(r#""code":"malformed_request""#));
        let line = d.answer_line(
            r#"{"v":1,"id":"b","method":"policy.fetch","params":{"device_token":"x"}}"#,
        );
        assert!(line.contains(r#""code":"unauthorized""#));
        let line = d.answer_line(
            r#"{"v":1,"id":"c","method":"recovery.key","params":{"device_token":"x"}}"#,
        );
        assert!(line.contains(r#""code":"out_of_scope""#));
        let line = d.answer_line(r#"{"v":1,"id":"d","method":"identity.status"}"#);
        assert!(line.contains(r#""enrolled":false"#));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn register_needs_a_discovered_organization_and_a_code() {
        let (d, root) = daemon();
        let line = d.answer_line(r#"{"v":1,"id":"a","method":"enroll.register","params":{"device_id":"x","bootstrap":"b"}}"#);
        assert!(line.contains("enrollment code is required"), "{line}");
        let line = d.answer_line(r#"{"v":1,"id":"a","method":"enroll.register","params":{"device_id":"x","bootstrap":"b","code":"lex_1"}}"#);
        assert!(line.contains("no organization was discovered"), "{line}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn discovery_uses_the_pinned_document_and_remembers_it() {
        let (d, root) = daemon();
        std::fs::write(
            root.join("discovery/acme.com.json"),
            r#"{"id":"acme","name":"Acme","enrollment":{"server":"https://api.acme.example","methods":["code"]}}"#,
        )
        .unwrap();
        let line = d.answer_line(
            r#"{"v":1,"id":"a","method":"org.discover","params":{"domain":"acme.com"}}"#,
        );
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["result"]["organization"]["id"], "acme");
        assert_eq!(
            v["result"]["organization"]["discovery"]["domain"],
            "acme.com"
        );
        assert!(d.pending.lock().unwrap().is_some());
        let _ = std::fs::remove_dir_all(root);
    }
}
