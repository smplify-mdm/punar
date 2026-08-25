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
//! | `admin.devices`, `admin.device` | — | `unknown_method` (**reserved for M10**, SPEC section 51) |

use std::io::{self, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use punar_common::ipc::{MAX_REQUEST_LINE_BYTES, SERVER_READ_TIMEOUT, SERVER_WRITE_TIMEOUT};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::MockConfig;
use crate::fixtures::{self, FixtureError, FixtureSet};
use crate::protocol::{self, ErrorCode, MockError, error_line, result_line};
use crate::state::{ATTESTATION_SIMULATED, StateStore};

/// Minimum bootstrap secret length the mock accepts: 32 hex characters.
/// (`punard` sends 64 — a 32-byte secret hex-encoded; the mock's bar is the
/// documented protocol floor.) Shape check only: nothing cryptographic
/// happens here, the acceptance is *simulated* and logged as such.
pub const BOOTSTRAP_MIN_HEX_CHARS: usize = 32;

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
        // Reserved so nobody invents a different admin surface later:
        // remote device queries are SPEC section 51, Milestone 10. m5-check
        // reads the state directory as root instead.
        "admin.devices" | "admin.device" => Err(MockError::with_details(
            ErrorCode::UnknownMethod,
            format!(
                "{method} is reserved for the Milestone 10 admin surface (SPEC \
                 section 51) and is not implemented by this dev/CI mock. \
                 Next step: m5-check asserts received state by reading the \
                 mock's state directory directly."
            ),
            json!({"method": method, "reserved_for": "M10"}),
        )),
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
    let state = inner.state.lock().unwrap();
    let device_id = require_token(&state, &p.device_token)?;
    state
        .append_compliance(&device_id, &p.report)
        .map_err(internal)?;
    Ok(json!({"accepted": true}))
}

fn inventory_report(inner: &Inner, params: Option<Value>) -> Result<Value, MockError> {
    let p: InventoryReportParams = parse_params("inventory.report", params)?;
    require_object("inventory.report", "inventory", &p.inventory)?;
    let state = inner.state.lock().unwrap();
    let device_id = require_token(&state, &p.device_token)?;
    state
        .append_inventory(&device_id, &p.inventory)
        .map_err(internal)?;
    Ok(json!({"accepted": true}))
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
