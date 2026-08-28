//! The NDJSON-over-UDS server: bind → chmod 0600 → listen, accept loop,
//! sequential per-connection request handling, and the mock method table.
//!
//! Deliberately the same skeleton as `punard`'s server (no async runtime;
//! std threads, one per connection; buffers bounded by the 4096-byte wire
//! line limit) so the CI image carries one server shape, not two. The
//! differences are the point: permissions are `0600` root (filesystem
//! admission stands in for production mTLS — milestone-5.md section 4.2),
//! there is no `SO_PEERCRED` authorization, and the method table is the
//! control-plane one.
//!
//! Method table (milestone-5.md section 4.3):
//!
//! | method | params | result |
//! |---|---|---|
//! | `org.discover` | `{domain}` | `{"organization": <org.json verbatim>}` |
//! | `enroll.register` | `{device_id, bootstrap}` | `{"device_token", "attestation": "simulated", "organization"}` |
//! | `policy.fetch` | `{device_token}` | `{"policies": [<envelope + embedded policy>]}` |
//! | `compliance.report` | `{device_token, report}` | `{"accepted": true}` |
//! | `inventory.report` | `{device_token, inventory}` | `{"accepted": true}` |
//! | `recovery.key` | `{device_token}` | authenticated tenant HPKE + receipt-verification public material |
//! | `recovery.escrow` | `{device_token, envelope}` | a signed receipt bound to that envelope |
//! | `queries.pending` | `{device_token}` | `{"queries": [<PendingQuery>, …]}` — **the device asks; nothing is pushed** |
//! | `queries.answer` | `{device_token, query_id, answer}` | `{"accepted": true}` — the answer is stored verbatim |
//! | `admin.devices` | `{admin}` | `{"devices": [{device_id, enrolled_at, last_sync, compliance_state}]}` |
//! | `admin.device` | `{admin, device_id}` | that device's received inventory + compliance + answered-query history |
//! | `admin.ai_query` | `{admin, device_id, scope, session_id?}` | `{query_id, status: "pending"}`, or `denied` / `out_of_scope` |
//! | `admin.query_result` | `{admin, query_id}` | `{status, answer?}` |
//! | `admin.fleet` | `{admin}` | the section 12.1 aggregate as structured data |
//! | `admin.recovery_release` | `{admin, device_id, reason}` | one audited plaintext recovery-key release; dev/CI only |
//!
//! The admin half is role-gated by [`crate::rbac`] **before** a query is
//! enqueued — an administrator without the role cannot even ask. That check
//! is defence in depth and nothing more: the device re-evaluates
//! authorization from its own `enrollment.json` and is the one that
//! decides (SPEC section 59.4).

use std::io::{self, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use punar_common::ipc::{MAX_REQUEST_LINE_BYTES, SERVER_READ_TIMEOUT, SERVER_WRITE_TIMEOUT};
use punar_common::time::utc_now_rfc3339;
use punar_recovery::{EscrowReceipt, HPKE_SUITE, RecoveryEnvelope, TenantRecoveryKey};
use serde::Deserialize;
use serde_json::{Value, json};

use punar_common::query::{MAX_QUERIES_PER_SYNC, PendingQuery, QueryScope};

use crate::config::MockConfig;
use crate::fixtures::{self, FixtureError, FixtureSet};
use crate::fleet;
use crate::protocol::{self, ErrorCode, MockError, error_line, result_line};
use crate::state::{ATTESTATION_SIMULATED, QueryStatus, StateStore};

/// Minimum bootstrap secret length the mock accepts: 32 hex characters.
/// (`punard` sends 64 — a 32-byte secret hex-encoded; the mock's bar is the
/// documented protocol floor.) Shape check only: nothing cryptographic
/// happens here, the acceptance is *simulated* and logged as such.
pub const BOOTSTRAP_MIN_HEX_CHARS: usize = 32;

/// Dev/CI-only recovery fixture. This complete HPKE keypair is RFC 9180
/// appendix A.2.1 public test material, so the mock can prove authorized
/// recovery release as well as device-side custody. The Ed25519 seed is also
/// public test material and signs receipts only. Production keeps both
/// private keys in tenant-scoped KMS/HSM custody; neither is compiled into a
/// production service.
const MOCK_RECOVERY_KEY_ID: &str = "trk_mock_2026_08";
const MOCK_HPKE_PUBLIC_KEY: &str = "QxDul9iMwfCIpVdsd6sM9cOseX89lROcbIS1QpxZZio";
const MOCK_HPKE_PRIVATE_KEY: [u8; 32] = [
    0x80, 0x57, 0x99, 0x1e, 0xef, 0x8f, 0x1f, 0x1a, 0xf1, 0x8f, 0x4a, 0x94, 0x91, 0xd1, 0x6a, 0x1c,
    0xe3, 0x33, 0xf6, 0x95, 0xd4, 0xdb, 0x8e, 0x38, 0xda, 0x75, 0x97, 0x5c, 0x44, 0x78, 0xe0, 0xfb,
];
const MOCK_RECEIPT_SIGNING_SEED: [u8; 32] = [9; 32];

/// A startup failure: bad fixtures or an unusable state directory.
#[derive(Debug)]
pub enum StartupError {
    Fixtures(FixtureError),
    State(io::Error),
}

impl std::fmt::Display for StartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartupError::Fixtures(e) => write!(f, "fixture set unusable: {e}"),
            StartupError::State(e) => write!(f, "state directory unusable: {e}"),
        }
    }
}

impl std::error::Error for StartupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StartupError::Fixtures(e) => Some(e),
            StartupError::State(e) => Some(e),
        }
    }
}

struct Inner {
    socket_path: PathBuf,
    state_dir: PathBuf,
    fixtures: FixtureSet,
    // One lock over devices + the append files: handlers run on connection
    // threads, and the received-side JSONL must interleave whole lines.
    state: Mutex<StateStore>,
    shutdown: AtomicBool,
}

/// A constructed (not yet listening) mock server.
pub struct MockServer {
    inner: Arc<Inner>,
}

/// A listening mock server; [`MockHandle::stop`] shuts it down and removes
/// the socket file.
pub struct MockHandle {
    inner: Arc<Inner>,
    accept_thread: JoinHandle<()>,
}

impl MockServer {
    /// Load fixtures and open the state store. Fails loudly on any defect —
    /// this is CI scaffolding and must not limp.
    pub fn new(cfg: MockConfig) -> Result<MockServer, StartupError> {
        let fixtures = fixtures::load(&cfg.fixtures_dir).map_err(StartupError::Fixtures)?;
        let state = StateStore::open(&cfg.state_dir).map_err(StartupError::State)?;
        Ok(MockServer {
            inner: Arc::new(Inner {
                socket_path: cfg.socket,
                state_dir: cfg.state_dir,
                fixtures,
                state: Mutex::new(state),
                shutdown: AtomicBool::new(false),
            }),
        })
    }

    /// The loaded fixture set (startup log line).
    pub fn fixtures(&self) -> &FixtureSet {
        &self.inner.fixtures
    }

    /// Number of already-registered devices (startup log line; nonzero
    /// after a restart because state persists deliberately).
    pub fn device_count(&self) -> usize {
        self.inner.state.lock().unwrap().device_count()
    }

    /// Bind the socket (stale files unlinked), set `0600` **before**
    /// `listen()` (root-only filesystem admission; chown best-effort when
    /// unprivileged), then start the accept loop on a background thread.
    /// The socket is listening when this returns.
    pub fn spawn(self) -> io::Result<MockHandle> {
        let inner = self.inner;
        let listener = bind_root_only(&inner.socket_path)?;
        let accept_inner = Arc::clone(&inner);
        let accept_thread = std::thread::Builder::new()
            .name("mock-accept".to_string())
            .spawn(move || accept_loop(&accept_inner, &listener))?;
        Ok(MockHandle {
            inner,
            accept_thread,
        })
    }
}

impl MockHandle {
    pub fn socket_path(&self) -> &Path {
        &self.inner.socket_path
    }

    /// Request shutdown, wake the accept loop, join it, remove the socket.
    pub fn stop(self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
        // Nudge a blocked accept(2) with a throwaway connection.
        let _ = UnixStream::connect(&self.inner.socket_path);
        let _ = self.accept_thread.join();
        let _ = std::fs::remove_file(&self.inner.socket_path);
    }
}

/// socket + bind + chmod 0600 + (best-effort) chown root + listen, in that
/// order. rustix keeps this free of `unsafe`; std's `UnixListener::bind`
/// would listen before permissions could be fixed, leaving a window where a
/// non-root peer could connect.
fn bind_root_only(path: &Path) -> io::Result<UnixListener> {
    use rustix::net::{AddressFamily, SocketType, bind, listen, socket};

    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let fd = socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
    let addr = rustix::net::SocketAddrUnix::new(path)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    bind(&fd, &addr)?;
    // Not yet listening: connects fail ECONNREFUSED while we fix perms.
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    // Meaningful only as root; harmless EPERM in host tests.
    let _ = std::os::unix::fs::chown(path, Some(0), Some(0));
    listen(&fd, 16)?;
    Ok(UnixListener::from(fd))
}

fn accept_loop(inner: &Arc<Inner>, listener: &UnixListener) {
    loop {
        if inner.shutdown.load(Ordering::SeqCst) {
            break;
        }
        match listener.accept() {
            Ok((stream, _addr)) => {
                if inner.shutdown.load(Ordering::SeqCst) {
                    break;
                }
                let conn_inner = Arc::clone(inner);
                let spawned = std::thread::Builder::new()
                    .name("mock-conn".to_string())
                    .spawn(move || handle_connection(&conn_inner, stream));
                if let Err(e) = spawned {
                    eprintln!("punar-mock-smplify: could not spawn connection thread: {e}");
                }
            }
            Err(e) => {
                if inner.shutdown.load(Ordering::SeqCst) {
                    break;
                }
                eprintln!("punar-mock-smplify: accept failed: {e}");
            }
        }
    }
}

/// Outcome of one bounded line read.
enum LineRead {
    Line(String),
    TooLong,
    Eof,
}

/// Read one `\n`-terminated line of at most `max` bytes (terminator
/// included), never buffering more than `max` bytes of an oversized line —
/// the same bounded reader shape as `punard`'s server.
fn read_line_bounded<R: Read>(reader: &mut BufReader<R>, max: usize) -> io::Result<LineRead> {
    use std::io::BufRead;
    let mut line: Vec<u8> = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(LineRead::Eof)
            } else {
                // Trailing data without newline: treat as a (final) line.
                Ok(LineRead::Line(String::from_utf8_lossy(&line).into_owned()))
            };
        }
        if let Some(pos) = available.iter().position(|b| *b == b'\n') {
            if line.len() + pos + 1 > max {
                reader.consume(pos + 1);
                return Ok(LineRead::TooLong);
            }
            line.extend_from_slice(&available[..pos]);
            reader.consume(pos + 1);
            return Ok(LineRead::Line(String::from_utf8_lossy(&line).into_owned()));
        }
        let chunk = available.len();
        if line.len() + chunk > max {
            reader.consume(chunk);
            return Ok(LineRead::TooLong);
        }
        line.extend_from_slice(available);
        reader.consume(chunk);
    }
}

fn write_line(stream: &mut UnixStream, line: &str) -> io::Result<()> {
    stream.write_all(line.as_bytes())?;
    stream.flush()
}

fn handle_connection(inner: &Inner, mut stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(SERVER_READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(SERVER_WRITE_TIMEOUT));

    let reader_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("punar-mock-smplify: could not clone connection stream: {e}");
            return;
        }
    };
    let mut reader = BufReader::with_capacity(MAX_REQUEST_LINE_BYTES, reader_stream);

    // Requests are processed sequentially, in order (ipc.md section 2).
    loop {
        match read_line_bounded(&mut reader, MAX_REQUEST_LINE_BYTES) {
            Ok(LineRead::Eof) => break,
            Ok(LineRead::TooLong) => {
                let err = MockError::new(
                    ErrorCode::MalformedRequest,
                    format!(
                        "The request line exceeded the {MAX_REQUEST_LINE_BYTES}-byte limit \
                         (docs/api/ipc.md section 2 framing)."
                    ),
                );
                let _ = write_line(&mut stream, &error_line(None, &err));
                break; // framing violation closes the connection
            }
            Ok(LineRead::Line(line)) => match protocol::parse_request_line(&line) {
                Ok(request) => {
                    let response = match dispatch(inner, &request.method, request.params) {
                        Ok(result) => result_line(&request.id, &result),
                        Err(err) => error_line(Some(&request.id), &err),
                    };
                    if write_line(&mut stream, &response).is_err() {
                        break;
                    }
                }
                Err(reject) => {
                    let close = reject.error.code.closes_connection();
                    let _ = write_line(
                        &mut stream,
                        &error_line(reject.id.as_deref(), &reject.error),
                    );
                    if close {
                        break;
                    }
                }
            },
            Err(_) => break, // read timeout or I/O error: close
        }
    }
}

// ---------------------------------------------------------------------------
// Method params (strict, like every Punar params struct)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OrgDiscoverParams {
    domain: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollRegisterParams {
    device_id: String,
    bootstrap: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFetchParams {
    device_token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComplianceReportParams {
    device_token: String,
    report: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryReportParams {
    device_token: String,
    inventory: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueriesPendingParams {
    device_token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueriesAnswerParams {
    device_token: String,
    query_id: String,
    answer: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryKeyParams {
    device_token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryEscrowParams {
    device_token: String,
    envelope: RecoveryEnvelope,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminParams {
    admin: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminDeviceParams {
    admin: String,
    device_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminAiQueryParams {
    admin: String,
    device_id: String,
    /// Untrusted, and kept a `String` on purpose: an unrecognised value
    /// must be *refusable* as `out_of_scope`, not unparseable.
    scope: String,
    #[serde(default)]
    session_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminQueryResultParams {
    admin: String,
    query_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminRecoveryReleaseParams {
    admin: String,
    device_id: String,
    reason: String,
}

fn parse_params<T: serde::de::DeserializeOwned>(
    method: &str,
    params: Option<Value>,
) -> Result<T, MockError> {
    let value = params.unwrap_or(Value::Null);
    serde_json::from_value(value).map_err(|e| {
        MockError::with_details(
            ErrorCode::InvalidParams,
            format!("Invalid params for {method}: {e}."),
            json!({"reason": e.to_string()}),
        )
    })
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

fn dispatch(inner: &Inner, method: &str, params: Option<Value>) -> Result<Value, MockError> {
    match method {
        "org.discover" => org_discover(inner, params),
        "enroll.register" => enroll_register(inner, params),
        "policy.fetch" => policy_fetch(inner, params),
        "compliance.report" => compliance_report(inner, params),
        "inventory.report" => inventory_report(inner, params),
        // Device-facing recovery custody: the device fetches tenant public
        // material, then uploads only an HPKE envelope. Nothing is pushed to
        // the device. Decryption is reachable only through the separately
        // RBAC-gated and audited dev recovery-release method below.
        "recovery.key" => recovery_key(inner, params),
        "recovery.escrow" => recovery_escrow(inner, params),
        // M10 device-facing: the device dials outward and collects the
        // questions addressed to it. There is no inverse of these two
        // methods anywhere in this crate.
        "queries.pending" => queries_pending(inner, params),
        "queries.answer" => queries_answer(inner, params),
        // M10 admin-facing (the names M5 reserved, now real).
        "admin.devices" => admin_devices(inner, params),
        "admin.device" => admin_device(inner, params),
        "admin.ai_query" => admin_ai_query(inner, params),
        "admin.query_result" => admin_query_result(inner, params),
        "admin.fleet" => admin_fleet(inner, params),
        "admin.recovery_release" => admin_recovery_release(inner, params),
        _ => Err(MockError::with_details(
            ErrorCode::UnknownMethod,
            format!("{method} is not a method of the mock control plane."),
            json!({"method": method}),
        )),
    }
}

fn org_discover(inner: &Inner, params: Option<Value>) -> Result<Value, MockError> {
    let p: OrgDiscoverParams = parse_params("org.discover", params)?;
    // DNS names are case-insensitive; the comparison follows suit so a
    // client's normalization choice cannot produce a spurious not_found.
    if !p.domain.eq_ignore_ascii_case(&inner.fixtures.domain) {
        return Err(MockError::with_details(
            ErrorCode::NotFound,
            format!(
                "No organization with domain {:?} is registered with this mock \
                 control plane. Next step: the dev/CI fixture set serves exactly \
                 one organization (domain {:?}).",
                p.domain, inner.fixtures.domain
            ),
            json!({"domain": p.domain}),
        ));
    }
    Ok(json!({"organization": inner.fixtures.organization}))
}

fn enroll_register(inner: &Inner, params: Option<Value>) -> Result<Value, MockError> {
    let p: EnrollRegisterParams = parse_params("enroll.register", params)?;
    if p.device_id.is_empty() {
        return Err(MockError::with_details(
            ErrorCode::InvalidParams,
            "The device_id must be a non-empty string.".to_string(),
            json!({"param": "device_id", "reason": "empty"}),
        ));
    }
    if p.bootstrap.len() < BOOTSTRAP_MIN_HEX_CHARS
        || !p.bootstrap.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(MockError::with_details(
            ErrorCode::InvalidParams,
            format!(
                "The bootstrap secret must be at least {BOOTSTRAP_MIN_HEX_CHARS} hex \
                 characters. This dev/CI mock checks only the shape — acceptance is \
                 simulated, nothing cryptographic happens here."
            ),
            json!({"param": "bootstrap", "reason": "must be >= 32 hex chars"}),
        ));
    }
    let token = inner
        .state
        .lock()
        .unwrap()
        .register(&p.device_id)
        .map_err(internal)?;
    eprintln!(
        "punar-mock-smplify: enroll.register {}: bootstrap simulated-accept \
         (shape check only), attestation \"{ATTESTATION_SIMULATED}\", token rotated",
        p.device_id
    );
    Ok(json!({
        "device_token": token,
        "attestation": ATTESTATION_SIMULATED,
        "organization": inner.fixtures.organization,
    }))
}

fn policy_fetch(inner: &Inner, params: Option<Value>) -> Result<Value, MockError> {
    let p: PolicyFetchParams = parse_params("policy.fetch", params)?;
    let state = inner.state.lock().unwrap();
    require_token(&state, &p.device_token)?;
    Ok(json!({"policies": inner.fixtures.policies}))
}

fn compliance_report(inner: &Inner, params: Option<Value>) -> Result<Value, MockError> {
    let p: ComplianceReportParams = parse_params("compliance.report", params)?;
    require_object("compliance.report", "report", &p.report)?;
    let mut state = inner.state.lock().unwrap();
    let device_id = require_token(&state, &p.device_token)?;
    state
        .append_compliance(&device_id, &p.report)
        .map_err(internal)?;
    Ok(json!({"accepted": true}))
}

fn inventory_report(inner: &Inner, params: Option<Value>) -> Result<Value, MockError> {
    let p: InventoryReportParams = parse_params("inventory.report", params)?;
    require_object("inventory.report", "inventory", &p.inventory)?;
    let mut state = inner.state.lock().unwrap();
    let device_id = require_token(&state, &p.device_token)?;
    state
        .append_inventory(&device_id, &p.inventory)
        .map_err(internal)?;
    Ok(json!({"accepted": true}))
}

fn tenant_recovery_key(organization_id: &str) -> TenantRecoveryKey {
    let signing_key = SigningKey::from_bytes(&MOCK_RECEIPT_SIGNING_SEED);
    TenantRecoveryKey {
        v: 1,
        organization_id: organization_id.to_string(),
        key_id: MOCK_RECOVERY_KEY_ID.to_string(),
        suite: HPKE_SUITE.to_string(),
        public_key: MOCK_HPKE_PUBLIC_KEY.to_string(),
        receipt_signing_public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
    }
}

fn recovery_key(inner: &Inner, params: Option<Value>) -> Result<Value, MockError> {
    let p: RecoveryKeyParams = parse_params("recovery.key", params)?;
    let state = inner.state.lock().unwrap();
    require_token(&state, &p.device_token)?;
    let key = tenant_recovery_key(&inner.fixtures.org_id);
    key.validate().map_err(|_| {
        MockError::new(
            ErrorCode::Internal,
            "The dev/CI tenant recovery-key fixture is invalid.",
        )
    })?;
    Ok(json!({"tenant_recovery_key": key}))
}

fn recovery_escrow(inner: &Inner, params: Option<Value>) -> Result<Value, MockError> {
    let p: RecoveryEscrowParams = parse_params("recovery.escrow", params)?;
    p.envelope.validate().map_err(|_| {
        MockError::with_details(
            ErrorCode::InvalidParams,
            "The recovery envelope failed its public shape and binding checks.",
            json!({"param": "envelope"}),
        )
    })?;
    let tenant_key = tenant_recovery_key(&inner.fixtures.org_id);
    let mut state = inner.state.lock().unwrap();
    let device_id = require_token(&state, &p.device_token)?.to_string();
    if p.envelope.organization_id != inner.fixtures.org_id
        || p.envelope.tenant_key_id != tenant_key.key_id
        || p.envelope.device_id != device_id
    {
        return Err(MockError::with_details(
            ErrorCode::InvalidParams,
            "The recovery envelope is not bound to this token, organization, and tenant key.",
            json!({"param": "envelope", "reason": "binding_mismatch"}),
        ));
    }
    state
        .append_recovery_envelope(&device_id, &p.envelope)
        .map_err(internal)?;

    let digest = p.envelope.digest_hex().map_err(|_| {
        MockError::new(
            ErrorCode::Internal,
            "Could not digest the recovery envelope.",
        )
    })?;
    let mut receipt = EscrowReceipt {
        v: 1,
        receipt_id: format!("rct_{}", &digest[..16]),
        received_at: utc_now_rfc3339(),
        organization_id: p.envelope.organization_id.clone(),
        tenant_key_id: p.envelope.tenant_key_id.clone(),
        device_id: p.envelope.device_id.clone(),
        luks_uuid: p.envelope.luks_uuid.clone(),
        recovery_keyslot: p.envelope.recovery_keyslot,
        envelope_sha256: digest,
        signature: String::new(),
    };
    let signing_key = SigningKey::from_bytes(&MOCK_RECEIPT_SIGNING_SEED);
    let payload = receipt.signing_payload().map_err(|_| {
        MockError::new(
            ErrorCode::Internal,
            "Could not encode the recovery receipt.",
        )
    })?;
    receipt.signature = URL_SAFE_NO_PAD.encode(signing_key.sign(&payload).to_bytes());
    Ok(json!({"receipt": receipt}))
}

// ---------------------------------------------------------------------------
// M10 device-facing: the pull (milestone-10.md section 7.2)
// ---------------------------------------------------------------------------

/// `queries.pending {device_token}` — hand this device the questions
/// addressed to **it**, oldest first, capped at
/// [`MAX_QUERIES_PER_SYNC`].
///
/// A device sees only its own queue: the token resolves to exactly one
/// `device_id` and the filter is on that id. Delivery does not consume the
/// entry — a device that fetched and then lost power gets the question
/// again, and an administrator is never answered with permanent silence
/// because of one dropped connection.
fn queries_pending(inner: &Inner, params: Option<Value>) -> Result<Value, MockError> {
    let p: QueriesPendingParams = parse_params("queries.pending", params)?;
    let mut state = inner.state.lock().unwrap();
    let device_id = require_token(&state, &p.device_token)?;
    let entries = state
        .pending_for_device(&device_id, MAX_QUERIES_PER_SYNC)
        .map_err(internal)?;
    let queries: Vec<PendingQuery> = entries
        .into_iter()
        .map(|e| PendingQuery {
            query_id: e.query_id,
            requesting_admin: e.requesting_admin,
            organization: e.organization,
            requested_scope: e.requested_scope,
            session_id: e.session_id,
            received_at: e.created_at,
        })
        .collect();
    Ok(json!({ "queries": queries }))
}

/// `queries.answer {device_token, query_id, answer}` — record what the
/// device decided, verbatim. The mock does not inspect, reshape or
/// second-guess the payload: the device is the authority about its own
/// data (milestone-10.md section 7.3).
fn queries_answer(inner: &Inner, params: Option<Value>) -> Result<Value, MockError> {
    let p: QueriesAnswerParams = parse_params("queries.answer", params)?;
    require_object("queries.answer", "answer", &p.answer)?;
    let mut state = inner.state.lock().unwrap();
    let device_id = require_token(&state, &p.device_token)?;
    let accepted = state
        .record_answer(&device_id, &p.query_id, &p.answer)
        .map_err(internal)?;
    if !accepted {
        return Err(MockError::with_details(
            ErrorCode::NotFound,
            format!(
                "No query {:?} is addressed to this device. Next step: a device may \
                 answer only questions it fetched from its own queue.",
                p.query_id
            ),
            json!({"query_id": p.query_id}),
        ));
    }
    Ok(json!({ "accepted": true }))
}

// ---------------------------------------------------------------------------
// M10 admin-facing (SPEC section 51; milestone-10.md sections 9.1, 13.3)
// ---------------------------------------------------------------------------

/// Resolve an admin identity against the role fixture, or refuse.
///
/// The refusal names the honest boundary every time: these are fixture
/// strings, not authenticated principals. There is no IdP in M10 and
/// pretending otherwise would be the exact dishonesty SPEC section 1.22
/// forbids.
fn require_admin<'a>(inner: &'a Inner, admin: &str) -> Result<&'a str, MockError> {
    let directory = &inner.fixtures.admins;
    if !directory.is_loaded() {
        return Err(MockError::with_details(
            ErrorCode::Denied,
            "This mock has no admin role table, so it grants no administrator \
             anything. Next step: stage fixtures/organizations/acme/admins.json \
             into the fixture directory (milestone-10.md section 9.1)."
                .to_string(),
            json!({"reason": "admins.json not loaded"}),
        ));
    }
    directory.role_of(admin).ok_or_else(|| {
        MockError::with_details(
            ErrorCode::Denied,
            format!(
                "{admin:?} is not an administrator of this organization. Identities \
                 here are asserted by the organization fixture and are not verified \
                 by anything — this mock has no IdP. Next step: use an identity \
                 listed in admins.json."
            ),
            json!({"admin": admin, "identity_verified": false}),
        )
    })
}

fn admin_devices(inner: &Inner, params: Option<Value>) -> Result<Value, MockError> {
    let p: AdminParams = parse_params("admin.devices", params)?;
    require_admin(inner, &p.admin)?;
    let state = inner.state.lock().unwrap();
    let devices: Vec<Value> = state
        .devices()
        .map(|(id, record)| {
            json!({
                "device_id": id,
                "enrolled_at": record.registered_at,
                "last_sync": record.last_sync,
                "compliance_state": record.compliance_state,
                "attestation": record.attestation,
            })
        })
        .collect();
    Ok(json!({
        "devices": devices,
        "identity_verified": false,
    }))
}

fn admin_device(inner: &Inner, params: Option<Value>) -> Result<Value, MockError> {
    let p: AdminDeviceParams = parse_params("admin.device", params)?;
    require_admin(inner, &p.admin)?;
    let state = inner.state.lock().unwrap();
    let Some(record) = state.device(&p.device_id) else {
        return Err(MockError::with_details(
            ErrorCode::NotFound,
            format!("No device {:?} is registered with this mock.", p.device_id),
            json!({"device_id": p.device_id}),
        ));
    };
    // The received side, read back from the append-only logs. Whatever a
    // device sent is all there is: the mock has no other source, and it
    // cannot ask for more without the device's cooperation.
    let inventory = last_received(
        &inner.state_dir,
        crate::state::INVENTORY_FILE,
        &p.device_id,
        "inventory",
    );
    let compliance = last_received(
        &inner.state_dir,
        crate::state::COMPLIANCE_FILE,
        &p.device_id,
        "report",
    );
    let queries: Vec<Value> = state
        .queries()
        .iter()
        .filter(|e| e.device_id == p.device_id)
        .map(|e| {
            json!({
                "query_id": e.query_id,
                "requesting_admin": e.requesting_admin,
                "requested_scope": e.requested_scope,
                "created_at": e.created_at,
                "status": e.status.as_str(),
                "answered_at": e.answered_at,
            })
        })
        .collect();
    Ok(json!({
        "device_id": p.device_id,
        "enrolled_at": record.registered_at,
        "last_sync": record.last_sync,
        "compliance_state": record.compliance_state,
        "attestation": record.attestation,
        "inventory": inventory,
        "compliance": compliance,
        "queries": queries,
        "identity_verified": false,
    }))
}

/// `admin.ai_query` — the RBAC gate, then the queue. Nothing is sent.
///
/// Two refusals happen here and both happen **before** enqueuing, so a
/// query the organization may not ask never reaches a device at all:
/// `out_of_scope` for a scope outside the closed vocabulary, `denied` for a
/// scope the asking role does not carry. The device's own check runs later
/// and independently, and it is the one that decides.
fn admin_ai_query(inner: &Inner, params: Option<Value>) -> Result<Value, MockError> {
    let p: AdminAiQueryParams = parse_params("admin.ai_query", params)?;
    require_admin(inner, &p.admin)?;
    let Some(scope) = QueryScope::from_wire(&p.scope) else {
        return Err(MockError::with_details(
            ErrorCode::OutOfScope,
            format!(
                "{:?} is not a query scope. The vocabulary is closed: {}. There is no \
                 wildcard and no free text. Next step: ask again at one of those \
                 scopes.",
                p.scope,
                QueryScope::vocabulary()
            ),
            json!({"scope": p.scope, "vocabulary": QueryScope::ALL.map(|s| s.as_str())}),
        ));
    };
    if !inner.fixtures.admins.permits(&p.admin, scope) {
        let permitted = inner
            .fixtures
            .admins
            .scopes_of(&p.admin)
            .map(|s| s.to_prose())
            .unwrap_or_else(|| "nothing".to_string());
        return Err(MockError::with_details(
            ErrorCode::Denied,
            format!(
                "The role {:?} may ask for {permitted}, not {}. The query was not \
                 enqueued and no device will ever see it. Next step: an \
                 administrator with a broader role asks, or the organization \
                 changes the role.",
                inner.fixtures.admins.role_of(&p.admin).unwrap_or("unknown"),
                scope.as_str()
            ),
            json!({"admin": p.admin, "scope": scope.as_str(), "permitted": permitted}),
        ));
    }
    let mut state = inner.state.lock().unwrap();
    if state.device(&p.device_id).is_none() {
        return Err(MockError::with_details(
            ErrorCode::NotFound,
            format!("No device {:?} is registered with this mock.", p.device_id),
            json!({"device_id": p.device_id}),
        ));
    }
    let entry = state
        .enqueue_query(
            &p.device_id,
            &p.admin,
            &inner.fixtures.domain,
            scope.as_str(),
            p.session_id,
        )
        .map_err(internal)?;
    Ok(json!({
        "query_id": entry.query_id,
        "status": QueryStatus::Pending.as_str(),
        // Stated on every surface that shows a query (milestone-10.md
        // section 7.2): the waiting happens on the administrator's side,
        // which is where a request the device did not initiate ought to
        // wait.
        "note": "the device answers on its next sync · one reconcile period (~120 s) \
                 plus the round trip · nothing is pushed to the device",
    }))
}

fn admin_query_result(inner: &Inner, params: Option<Value>) -> Result<Value, MockError> {
    let p: AdminQueryResultParams = parse_params("admin.query_result", params)?;
    require_admin(inner, &p.admin)?;
    let state = inner.state.lock().unwrap();
    let Some(entry) = state.query(&p.query_id) else {
        return Err(MockError::with_details(
            ErrorCode::NotFound,
            format!("No query {:?} was ever asked of this mock.", p.query_id),
            json!({"query_id": p.query_id}),
        ));
    };
    // An administrator reads back their own question. Anything wider would
    // let one role's query become another role's answer, which is the RBAC
    // gate with extra steps.
    if entry.requesting_admin != p.admin {
        return Err(MockError::with_details(
            ErrorCode::Denied,
            format!(
                "Query {:?} was asked by a different administrator. Next step: the \
                 administrator who asked reads the answer.",
                p.query_id
            ),
            json!({"query_id": p.query_id}),
        ));
    }
    Ok(json!({
        "query_id": entry.query_id,
        "device_id": entry.device_id,
        "requested_scope": entry.requested_scope,
        "status": entry.status.as_str(),
        "answered_at": entry.answered_at,
        "answer": entry.answer,
        "identity_verified": false,
    }))
}

fn admin_fleet(inner: &Inner, params: Option<Value>) -> Result<Value, MockError> {
    let p: AdminParams = parse_params("admin.fleet", params)?;
    require_admin(inner, &p.admin)?;
    if !inner.fixtures.admins.permits_fleet(&p.admin) {
        return Err(MockError::with_details(
            ErrorCode::Denied,
            format!(
                "The role {:?} may not read the fleet view. Next step: a \
                 fleet_viewer or a security_admin reads it.",
                inner.fixtures.admins.role_of(&p.admin).unwrap_or("unknown")
            ),
            json!({"admin": p.admin}),
        ));
    }
    let state = inner.state.lock().unwrap();
    Ok(fleet::aggregate(&state).to_json())
}

/// Dev/CI proof of the other half of escrow: a separately permissioned,
/// reason-bound operator may release the newest key for one device. The
/// private key is public RFC test material in this mock; production performs
/// this unwrap inside tenant-scoped KMS/HSM custody after authenticated,
/// step-up portal authorization.
fn admin_recovery_release(inner: &Inner, params: Option<Value>) -> Result<Value, MockError> {
    let p: AdminRecoveryReleaseParams = parse_params("admin.recovery_release", params)?;
    if !valid_release_identifier(&p.device_id, 128) || !valid_release_identifier(&p.reason, 63) {
        return Err(MockError::with_details(
            ErrorCode::InvalidParams,
            "Recovery release requires a valid device id and a 1–63 character structured reason code (letters, numbers, '.', '_', ':', or '-').",
            json!({"param": "device_id|reason"}),
        ));
    }

    if let Err(error) = require_admin(inner, &p.admin) {
        append_recovery_release_audit(inner, &p, "denied")?;
        return Err(error);
    }
    if !inner.fixtures.admins.permits_recovery_release(&p.admin) {
        append_recovery_release_audit(inner, &p, "denied")?;
        return Err(MockError::with_details(
            ErrorCode::Denied,
            format!(
                "The role {:?} may not release disk recovery material. The attempt was audited. Next step: a role explicitly listed in recovery_release_roles performs the recovery.",
                inner.fixtures.admins.role_of(&p.admin).unwrap_or("unknown")
            ),
            json!({"admin": p.admin, "device_id": p.device_id, "identity_verified": false}),
        ));
    }

    let envelope = {
        let state = inner.state.lock().unwrap();
        if state.device(&p.device_id).is_none() {
            drop(state);
            append_recovery_release_audit(inner, &p, "not_found")?;
            return Err(MockError::with_details(
                ErrorCode::NotFound,
                format!("No device {:?} is registered with this mock.", p.device_id),
                json!({"device_id": p.device_id}),
            ));
        }
        state
            .latest_recovery_envelope(&p.device_id)
            .map_err(internal)?
    };
    let Some(envelope) = envelope else {
        append_recovery_release_audit(inner, &p, "not_found")?;
        return Err(MockError::with_details(
            ErrorCode::NotFound,
            "This device has no escrowed recovery envelope. The attempt was audited.",
            json!({"device_id": p.device_id}),
        ));
    };

    let recovery_key = match envelope.open_for_recipient(&MOCK_HPKE_PRIVATE_KEY) {
        Ok(key) => key,
        Err(_) => {
            append_recovery_release_audit(inner, &p, "unwrap_failed")?;
            return Err(MockError::new(
                ErrorCode::Internal,
                "The tenant recovery service could not unwrap this envelope; no recovery material was released.",
            ));
        }
    };
    append_recovery_release_audit(inner, &p, "released")?;
    let device_id = envelope.device_id;
    let luks_uuid = envelope.luks_uuid;
    let recovery_keyslot = envelope.recovery_keyslot;
    let tenant_key_id = envelope.tenant_key_id;
    Ok(recovery_key.deliver_to_unlock_sink(|key| {
        json!({
            "device_id": device_id,
            "luks_uuid": luks_uuid,
            "recovery_keyslot": recovery_keyslot,
            "tenant_key_id": tenant_key_id,
            "reason": p.reason,
            "recovery_key": key,
            "identity_verified": false,
            "release_once": true,
            "warning": "dev/CI mock: asserted fixture identity, not a production IdP; protect this one-time response and never log it",
        })
    }))
}

fn append_recovery_release_audit(
    inner: &Inner,
    params: &AdminRecoveryReleaseParams,
    outcome: &str,
) -> Result<(), MockError> {
    inner
        .state
        .lock()
        .unwrap()
        .append_recovery_release(&params.admin, &params.device_id, &params.reason, outcome)
        .map_err(internal)
}

fn valid_release_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

/// Read the last received line for one device out of an append-only log.
/// Best-effort: an absent log is `null`, never a fabricated empty object —
/// `—` and `0` are different here too.
fn last_received(state_dir: &Path, file: &str, device_id: &str, key: &str) -> Value {
    let Ok(text) = std::fs::read_to_string(state_dir.join(file)) else {
        return Value::Null;
    };
    text.lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|v| v.get("device_id").and_then(Value::as_str) == Some(device_id))
        .and_then(|v| v.get(key).cloned())
        .unwrap_or(Value::Null)
}

/// Resolve a token or answer `unauthorized` — the protocol-layer check that
/// stands in for production device auth (milestone-5.md section 4.2:
/// enforced even though transport admission already implies root, because
/// the token flow is what M5 rehearses and `punard`'s error path needs a
/// counterparty that can say no).
fn require_token(state: &StateStore, token: &str) -> Result<String, MockError> {
    state
        .device_for_token(token)
        .map(str::to_string)
        .ok_or_else(|| {
            MockError::new(
                ErrorCode::Unauthorized,
                "The device token was not recognized. This mock's token check \
                 stands in for production device authentication. \
                 Next step: re-enroll to obtain a fresh token."
                    .to_string(),
            )
        })
}

fn require_object(method: &str, param: &str, value: &Value) -> Result<(), MockError> {
    if value.is_object() {
        Ok(())
    } else {
        Err(MockError::with_details(
            ErrorCode::InvalidParams,
            format!("The {param} param of {method} must be a JSON object."),
            json!({"param": param, "reason": "not an object"}),
        ))
    }
}

fn internal(e: io::Error) -> MockError {
    MockError::new(
        ErrorCode::Internal,
        format!("The mock could not persist state: {e}."),
    )
}
