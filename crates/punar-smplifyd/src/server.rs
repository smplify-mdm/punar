//! The root-only socket and the method table. One request per connection,
//! one connection at a time, in the order they arrive, and nothing here
//! long-polls inside a call. punard is the only client, but it may have
//! several calls in flight (a timer pass, a root administrator's reconcile
//! and an enrollment overlap): those wait in the listen queue, and punard
//! waits for each answer from the end of the calls ahead of it
//! (`punard::enroll::AgentQueue`), so every call here must end within its
//! own budget (`punar_smplifyd::budget`) for the ones behind it to be
//! answered in time.
//!
//! Peer admission is `SO_PEERCRED` uid 0 — the mock deliberately relies on
//! filesystem admission alone (milestone-5.md section 4.2); the real daemon
//! does both, because its answers carry the organisation's word.
//!
//! The listener is systemd's (`punar-smplifyd.socket`), and the agent's
//! lifetime follows enrollment ([`punar_smplifyd::activation`]):
//! [`Daemon::serve_listener`] returns [`Stopped::Dormant`] once nothing of an
//! identity is left and no call has come for the idle time, or right after
//! an `enroll.unregister` wiped it. While anything of one is left it waits
//! for calls with no timeout at all, so an enrolled device's agent has no
//! wakeup of its own.
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use punar_smplifyd::budget::{CALL_BUDGET, PIN_BUDGET, REGISTER_BUDGET};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::discovery::{self, Organization};
use crate::identity::{self, Csr, Record, Store};
use crate::protocol::{CallError, ErrorCode, error_line, parse_request_line, result_line};
use crate::upstream::{Api, Bundle, Enrolled, UpstreamError};

const MAX_LINE_BYTES: usize = 1024 * 1024;
const LINE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a failed tenant-key check-in waits before the next, doubled after
/// each further failure up to [`PIN_RETRY_CAP`]. One sync pass comes every two
/// minutes, so the first retry is the next pass's.
const PIN_RETRY_BASE: Duration = Duration::from_secs(60);
const PIN_RETRY_CAP: Duration = Duration::from_secs(30 * 60);

pub struct Daemon {
    store: Store,
    discovery_dir: PathBuf,
    os_release_path: PathBuf,
    /// The organisation `org.discover` last resolved: `enroll.register`
    /// carries no domain, so it enrols into the organisation punard just
    /// asked about, exactly as the mock does.
    pending: Mutex<Option<Organization>>,
    /// The whole of one of punard's calls, [`CALL_BUDGET`]; shorter in tests.
    call_budget: Duration,
    /// The whole of one `enroll.register`, [`REGISTER_BUDGET`]; shorter in
    /// tests.
    register_budget: Duration,
    /// The tenant-key check-in's own budget, [`PIN_BUDGET`]; shorter in tests.
    pin_budget: Duration,
    /// [`PIN_RETRY_BASE`]; shorter in tests.
    pin_retry_base: Duration,
    /// Time the tenant-key check-in takes past its own budget, as a slow
    /// name lookup or a slow disk could make it: for the test that holds a
    /// report to its whole budget even then. It moves [`Daemon::now`] on
    /// rather than sleeping, so it costs the test nothing and a loaded host
    /// cannot add to it.
    #[cfg(test)]
    pin_overrun: Mutex<Duration>,
    /// How far the tests have moved [`Daemon::now`] past the monotonic
    /// clock: a retry wait or an overrun is stepped over, not slept through,
    /// so what a test asserts about them cannot depend on how busy the host
    /// running it is.
    #[cfg(test)]
    clock_skew: Mutex<Duration>,
    /// Every budget a request to Smplify was given, in the order the
    /// requests were made ([`Daemon::grant`]). The tests hold each call to
    /// the budgets it hands out, which the HTTP client then enforces
    /// (`http::tests`), and time a whole call only with a margin no load on
    /// a shared host reaches.
    #[cfg(test)]
    granted: Mutex<Vec<Duration>>,
    /// Time building a client takes, as reading the identity and the
    /// system's roots on a slow disk or a loaded host could. Slept, not
    /// stepped over: the HTTP client keeps its deadline by the real clock,
    /// and what the tests prove is that this time is spent from it.
    #[cfg(test)]
    client_setup: Duration,
    /// When the tenant-key check-in may next be tried after failing. Kept in
    /// memory only: a restart costs one early check-in, not a stale schedule
    /// on disk.
    pin_retry: Mutex<Option<PinRetry>>,
    /// Whether the last compliance report could not reach Smplify at all,
    /// so that one getting through says the link is back
    /// ([`Daemon::after_compliance_post`]).
    link_down: AtomicBool,
    /// Set by an `enroll.unregister` that wiped the identity: once its
    /// answer is written the agent goes dormant ([`Stopped::Dormant`]).
    released: AtomicBool,
    /// Answer a peer of any uid, for tests, which do not run as root.
    #[cfg(test)]
    admit_any_peer: bool,
}

/// Why [`Daemon::serve_listener`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopped {
    /// Nothing of an identity is left, and the agent exits with
    /// [`punar_smplifyd::activation::DORMANT_EXIT_STATUS`] until the socket
    /// starts it again.
    Dormant,
}

/// A tenant-key check-in that failed, for the identity it was made for.
struct PinRetry {
    device_id: String,
    failures: u32,
    not_before: Instant,
}

impl Daemon {
    pub fn new(state_dir: impl Into<PathBuf>, discovery_dir: impl Into<PathBuf>) -> Daemon {
        Daemon {
            store: Store::new(state_dir),
            discovery_dir: discovery_dir.into(),
            os_release_path: PathBuf::from("/etc/os-release"),
            pending: Mutex::new(None),
            call_budget: CALL_BUDGET,
            register_budget: REGISTER_BUDGET,
            pin_budget: PIN_BUDGET,
            pin_retry_base: PIN_RETRY_BASE,
            #[cfg(test)]
            pin_overrun: Mutex::new(Duration::ZERO),
            #[cfg(test)]
            clock_skew: Mutex::new(Duration::ZERO),
            #[cfg(test)]
            granted: Mutex::new(Vec::new()),
            #[cfg(test)]
            client_setup: Duration::ZERO,
            pin_retry: Mutex::new(None),
            link_down: AtomicBool::new(false),
            released: AtomicBool::new(false),
            #[cfg(test)]
            admit_any_peer: false,
        }
    }

    #[cfg(test)]
    pub fn with_os_release(mut self, path: impl Into<PathBuf>) -> Daemon {
        self.os_release_path = path.into();
        self
    }

    #[cfg(test)]
    fn with_call_budget(mut self, budget: Duration) -> Daemon {
        self.call_budget = budget;
        self
    }

    #[cfg(test)]
    fn with_register_budget(mut self, budget: Duration) -> Daemon {
        self.register_budget = budget;
        self
    }

    #[cfg(test)]
    fn with_pin_budget(mut self, budget: Duration, retry_base: Duration) -> Daemon {
        self.pin_budget = budget;
        self.pin_retry_base = retry_base;
        self
    }

    #[cfg(test)]
    fn with_client_setup(mut self, takes: Duration) -> Daemon {
        self.client_setup = takes;
        self
    }

    /// The clock a report's budget and the check-in's retry schedule are
    /// kept by: the monotonic clock, which only the tests move.
    fn now(&self) -> Instant {
        Instant::now() + self.clock_skew()
    }

    #[cfg(not(test))]
    fn clock_skew(&self) -> Duration {
        Duration::ZERO
    }

    #[cfg(test)]
    fn clock_skew(&self) -> Duration {
        *self.clock_skew.lock().unwrap()
    }

    /// Move [`Daemon::now`] on by `by`, as that much time passing would.
    #[cfg(test)]
    fn advance(&self, by: Duration) {
        *self.clock_skew.lock().unwrap() += by;
    }

    /// The deadline of one request to Smplify given `budget` from now. Every
    /// client this agent builds takes its deadline from here, before it is
    /// built ([`Daemon::api`], [`Daemon::anonymous`]): building one reads the
    /// identity and the system's whole root store, and a budget the client
    /// counted from its own request would leave that time outside every
    /// budget punard waits out.
    fn grant(&self, budget: Duration) -> Instant {
        #[cfg(test)]
        self.granted.lock().unwrap().push(budget);
        Instant::now() + budget
    }

    /// Without systemd (development, tests): socket → bind → chmod 0600 →
    /// listen, then serve forever. Nothing would start the agent again, so
    /// it never goes dormant.
    pub fn serve(&self, socket: &Path) -> std::io::Result<()> {
        let listener = bind(socket)?;
        eprintln!("punar-smplifyd: serving {}", socket.display());
        self.serve_listener(listener, None).map(|_| ())
    }

    /// Serve calls from `listener`, one at a time, in the order they arrive.
    /// With `idle`, the agent is dormant once no call has come for that long
    /// while nothing of an identity is left, and at once after a wipe;
    /// while anything is left it waits for a call however long that takes.
    /// Without `idle` it serves until an error.
    pub fn serve_listener(
        &self,
        listener: UnixListener,
        idle: Option<Duration>,
    ) -> std::io::Result<Stopped> {
        listener.set_nonblocking(true)?;
        loop {
            let wait = idle.filter(|_| !self.store.holds_anything());
            if !readable_within(&listener, wait)? {
                // Waited out the idle time. Only an empty state directory
                // lets it go: a call cannot have put an identity there
                // meanwhile, but a check costs one directory read.
                if !self.store.holds_anything() {
                    return Ok(Stopped::Dormant);
                }
                continue;
            }
            let stream = match listener.accept() {
                Ok((stream, _)) => stream,
                // Taken, or given up on, between the poll and here.
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    eprintln!("punar-smplifyd: accept failed ({})", e.kind());
                    continue;
                }
            };
            // Blocking, with the per-line timeouts `handle` sets.
            if stream.set_nonblocking(false).is_err() {
                continue;
            }
            self.handle(stream);
            if self.released.swap(false, Ordering::SeqCst)
                && idle.is_some()
                && !self.store.holds_anything()
            {
                return Ok(Stopped::Dormant);
            }
        }
    }

    fn handle(&self, mut stream: UnixStream) {
        if !self.admits(&stream) {
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
            "identity.status" => self.identity_status(params),
            "policy.fetch" => self.policy_fetch(params),
            "compliance.report" => self.report(
                params,
                "report",
                crate::status::compliance_status_body,
                PinTenantKey::First,
            ),
            "inventory.report" => self.report(
                params,
                "inventory",
                crate::status::inventory_status_body,
                PinTenantKey::Never,
            ),
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

    /// Redeem the enrollment code for a certificate, within
    /// [`Daemon::register_budget`] in all. punard waits a little longer than
    /// that for the answer, and it must get one: Smplify keeps the device
    /// record it creates at `/enroll` and refuses a second active record for
    /// the same machine, so a registration Smplify accepted but punard gave
    /// up on leaves a device that cannot enroll again until an administrator
    /// removes the stale record. The two requests therefore share one
    /// deadline, and nothing else is asked of Smplify here: the first
    /// check-in, which pins the tenant key, is the first compliance report's
    /// ([`Daemon::report`]).
    fn enroll_register(&self, params: Option<&Value>) -> Result<Value, CallError> {
        let started = Instant::now();
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
        // Resolving is optional, so it may never cost /enroll most of the
        // deadline: a third at most, and an unresolved image enrolls under
        // the canonical identifier.
        let os_identifier = self
            .anonymous(&organization.server, self.grant(self.register_budget / 3))?
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
        let enrolled = self
            .anonymous(
                &organization.server,
                self.grant(self.register_budget.saturating_sub(started.elapsed())),
            )?
            .enroll(
                &code,
                &csr.csr_pem,
                &crate::device::hostname(),
                &os_identifier,
                &device_id,
            )
            .map_err(enrollment_refusal)?;
        drop(code);
        self.keep_identity(organization, os_identifier, &csr, enrolled)
    }

    /// Store the identity Smplify just issued and answer punard. Local work
    /// only: Smplify already holds the device record, so every moment spent
    /// here is one in which punard could give up on a registration that
    /// succeeded.
    fn keep_identity(
        &self,
        organization: Organization,
        os_identifier: String,
        csr: &Csr,
        enrolled: Enrolled,
    ) -> Result<Value, CallError> {
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
        let record = Record {
            device_id: enrolled.device_id,
            server: organization.server.origin(),
            org_id: organization.id.clone(),
            org_name: organization.name.clone(),
            os_identifier,
            not_after: enrolled.not_after,
            // Pinned by the first compliance report's check-in.
            tenant_public_key: None,
            token_sha256,
            enrolled_at: crate::clock::now_rfc3339(),
        };
        self.store
            .save(&record, &csr.key_pem, &enrolled.cert_pem, &enrolled.ca_pem)
            .map_err(internal)?;
        // A new identity pins at its first report, whatever an earlier one's
        // check-ins did, even should Smplify issue it the same device id.
        *self.pin_retry.lock().unwrap() = None;

        *self.pending.lock().unwrap() = None;
        Ok(json!({
            "device_token": &*token,
            "attestation": "none",
            "organization": organization.document,
        }))
    }

    /// Wipe the identity, locally: it asks Smplify nothing, so unenrolling
    /// works offline, and the agent goes dormant once the answer is written.
    /// With no identity at all there is nothing to authorize, and whatever a
    /// crash or an earlier wipe left (a key, a certificate) goes the same
    /// way: punard asks again until a wipe is confirmed (docs/api/ipc.md
    /// section 5.11), so a wipe whose answer was lost must be confirmable.
    ///
    /// `any_identity: true` wipes whatever is held, the token or none. punard
    /// sends it only while it holds no enrollment, under its enrollment
    /// guard: an identity it never received the token for (a registration
    /// whose answer was lost) or one its token does not name is then nothing
    /// punard uses, and must not stay. Only root can ask (`SO_PEERCRED`), and
    /// root could remove the files itself. Without it, the identity punard's
    /// token names is wiped and any other is refused and kept.
    fn enroll_unregister(&self, params: Option<&Value>) -> Result<Value, CallError> {
        let any_identity = params
            .and_then(|params| params.get("any_identity"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !any_identity {
            let presented = param_str(params, "device_token")?;
            if let Some(record) = self.store.load().map_err(internal)? {
                if !identity::token_matches(&record, &presented) {
                    return Err(CallError::new(
                        ErrorCode::Unauthorized,
                        "the device token does not match this identity",
                    ));
                }
            }
        }
        self.store.wipe().map_err(internal)?;
        *self.pin_retry.lock().unwrap() = None;
        self.released.store(true, Ordering::SeqCst);
        Ok(json!({ "wiped": true }))
    }

    /// Local only, and punard's liveness call on every pass while enrolled:
    /// one file read, nothing asked of Smplify. With the `device_token`
    /// punard holds, it also says whether that token is this identity's.
    fn identity_status(&self, params: Option<&Value>) -> Result<Value, CallError> {
        match self.store.load().map_err(internal)? {
            Some(record) => {
                let mut status = json!({
                    "enrolled": true,
                    "device_id": record.device_id,
                    "server": record.server,
                    "org_id": record.org_id,
                    "org_name": record.org_name,
                    "os_identifier": record.os_identifier,
                    "not_after": record.not_after,
                    "tenant_key_pinned": record.tenant_public_key.is_some(),
                    "enrolled_at": record.enrolled_at,
                });
                if let Ok(presented) = param_str(params, "device_token") {
                    status["token_matches"] = json!(identity::token_matches(&record, &presented));
                }
                Ok(status)
            }
            None => Ok(json!({ "enrolled": false })),
        }
    }

    fn policy_fetch(&self, params: Option<&Value>) -> Result<Value, CallError> {
        let started = Instant::now();
        let record = self.authorized(params)?;
        let api = self.api(self.grant(self.call_budget.saturating_sub(started.elapsed())))?;
        let bundle = api.bundle(&record.device_id).map_err(upstream_refusal)?;
        Ok(policy_answer(bundle.as_ref()))
    }

    /// One report. punard reads the answer within its own timeout for the
    /// method, and a report that Smplify kept but whose answer came later
    /// reads there as "unreachable": the inventory's hash and send time are
    /// not saved, the person's record of what left is not written, and the
    /// whole inventory goes up again on every pass. So the tenant-key
    /// check-in rides only the compliance report, which every sync pass
    /// sends first, with [`Daemon::pin_budget`] of its own, and the status
    /// POST has [`Daemon::call_budget`], or less when that is all that is
    /// left of the call's whole budget, measured from its start and spent on
    /// building each client as well as on its request ([`Daemon::grant`]):
    /// `compliance.report` answers within their sum, and `inventory.report`
    /// within [`Daemon::call_budget`] (`punar_smplifyd::budget::call_budget`),
    /// which punard waits out.
    fn report(
        &self,
        params: Option<&Value>,
        key: &str,
        compose: fn(&str, &Value) -> Value,
        pin: PinTenantKey,
    ) -> Result<Value, CallError> {
        // The whole call is held to its budget from here, whatever the
        // check-in before the status POST took: a POST given a fresh budget
        // after a check-in that overran its own could answer after punard
        // stopped waiting, and a report Smplify stored would read as
        // unreachable.
        let started = self.now();
        let whole = match pin {
            PinTenantKey::First => self.pin_budget + self.call_budget,
            PinTenantKey::Never => self.call_budget,
        };
        let record = self.authorized(params)?;
        let payload = params.and_then(|p| p.get(key)).ok_or_else(|| {
            CallError::new(ErrorCode::InvalidParams, format!("{key} is required"))
        })?;
        if pin == PinTenantKey::First {
            self.pin_tenant_key_if_missing(&record);
        }
        let left = whole
            .saturating_sub(self.now().saturating_duration_since(started))
            .min(self.call_budget);
        if left.is_zero() {
            return Err(CallError::new(
                ErrorCode::Internal,
                "no time was left in this call to send the report; it is sent again on the \
                 next pass",
            ));
        }
        let deadline = self.grant(left);
        let body = compose(&record.device_id, payload);
        let mut reached = None;
        let posted = self.api(deadline).and_then(|api| {
            let posted = api.status(&record.device_id, &body);
            reached = Some(posted.as_ref().map_or_else(reached_smplify, |_| true));
            posted.map_err(upstream_refusal)
        });
        // Only the compliance report, which every pass sends first, speaks
        // for the link: an inventory is larger and may fail where a report
        // gets through, and a refusal is Smplify answering.
        if let (PinTenantKey::First, Some(reached)) = (pin, reached) {
            self.after_compliance_post(reached);
        }
        posted?;
        // What left, exactly as it left. punard keeps it as the person's
        // record of what their organization received (SPEC section 24.2), so
        // that record is the translation's output, never punard's guess at
        // it from the inventory it handed over.
        Ok(json!({ "sent": body }))
    }

    /// Pin the organization's signing key. Registration leaves it to the
    /// first compliance report, and a check-in that fails undoes nothing, so
    /// this is one check-in within [`Daemon::pin_budget`] per compliance
    /// report until the key is held, then never again. After a failure the
    /// next try waits, doubling up to [`PIN_RETRY_CAP`]: a link that cannot
    /// carry the check-in, or a Smplify that holds no key, would otherwise
    /// cost every pass a check-in that cannot succeed. It is pinned once and
    /// never replaced here: a key that changes under a pinned device is a
    /// question for re-enrollment, not for a sync.
    fn pin_tenant_key_if_missing(&self, record: &Record) {
        if record.tenant_public_key.is_some() {
            return;
        }
        let started = self.now();
        let failures = match &*self.pin_retry.lock().unwrap() {
            Some(retry) if retry.device_id == record.device_id => {
                if started < retry.not_before {
                    return;
                }
                retry.failures
            }
            _ => 0,
        };
        let os_release = crate::device::os_release(&self.os_release_path);
        let answer = self.api(self.grant(self.pin_budget)).and_then(|api| {
            api.checkin(&record.device_id, &record.os_identifier, &os_release)
                .map_err(internal)
        });
        #[cfg(test)]
        self.advance(*self.pin_overrun.lock().unwrap());
        let why = match answer {
            Ok(Some(key)) => {
                let mut pinned = record.clone();
                pinned.tenant_public_key = Some(key);
                match self.store.update(&pinned) {
                    Ok(()) => {
                        *self.pin_retry.lock().unwrap() = None;
                        return;
                    }
                    Err(error) => format!("the tenant key could not be stored ({error:?})"),
                }
            }
            Ok(None) => "check-in answered without a tenant key".to_string(),
            Err(error) => format!("check-in failed ({})", error.message),
        };
        let failures = failures.saturating_add(1);
        let wait = retry_delay(self.pin_retry_base, failures);
        eprintln!(
            "punar-smplifyd: the tenant key is not pinned: {why}; retrying in {} s",
            wait.as_secs()
        );
        *self.pin_retry.lock().unwrap() = Some(PinRetry {
            device_id: record.device_id.clone(),
            failures,
            not_before: started + wait,
        });
    }

    /// A compliance report that reaches Smplify after one that could not
    /// means the link is back. A check-in the outage backed off (doubling up
    /// to half an hour, with nothing getting through at all) is then tried
    /// again at the next compliance report, instead of after the wait the
    /// outage built up. Nothing else moves this: an inventory that cannot get
    /// through while reports do, or a report Smplify refuses, is no outage,
    /// and the backoff still spares a link that carries reports but not the
    /// check-in.
    fn after_compliance_post(&self, reached: bool) {
        let was_down = self.link_down.swap(!reached, Ordering::SeqCst);
        if reached && was_down {
            *self.pin_retry.lock().unwrap() = None;
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

    /// A client for this device's identity whose every request must end by
    /// `deadline`, which the caller fixed before this builds it
    /// ([`Daemon::grant`]).
    fn api(&self, deadline: Instant) -> Result<Api, CallError> {
        self.building_a_client();
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
        Api::with_identity(&server, identity, deadline).map_err(internal)
    }

    /// A client without the device's identity, for resolving and enrolling,
    /// whose every request must end by `deadline`, which the caller fixed
    /// before this builds it ([`Daemon::grant`]).
    fn anonymous(&self, server: &crate::http::Url, deadline: Instant) -> Result<Api, CallError> {
        self.building_a_client();
        Api::anonymous(server, deadline).map_err(internal)
    }

    #[cfg(not(test))]
    fn building_a_client(&self) {}

    /// [`Daemon::client_setup`], spent where building a client spends it.
    #[cfg(test)]
    fn building_a_client(&self) {
        std::thread::sleep(self.client_setup);
    }
}

/// `base` after the first failure, doubled after each further one, never
/// more than [`PIN_RETRY_CAP`].
fn retry_delay(base: Duration, failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    base.saturating_mul(1 << doublings).min(PIN_RETRY_CAP)
}

/// Whether a report first tries to pin the tenant key ([`Daemon::report`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum PinTenantKey {
    First,
    Never,
}

/// The `policy.fetch` answer for what Smplify delivered, with the marker
/// that says what an empty list means (docs/api/ipc.md section 5.9). punard
/// withdraws an organization's policy only on `"none"`, so the two empty
/// answers must never look alike: 204 is Smplify saying nothing is assigned;
/// a bundle this release cannot read is something assigned that must not
/// wipe the policy the device already enforces.
///
/// When the bundle carries a Punar payload (slice 2), one that fails its
/// signature check is an error, never an empty list.
fn policy_answer(bundle: Option<&Bundle>) -> Value {
    match bundle {
        None => json!({ "policies": [], "assignment": "none" }),
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
            json!({ "policies": [], "assignment": "unusable" })
        }
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

/// socket → bind → chmod 0600 → listen, replacing a stale socket file.
fn bind(socket: &Path) -> std::io::Result<UnixListener> {
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
    Ok(listener)
}

/// Wait for a connection, for at most `wait` (forever without one): whether
/// one is there.
fn readable_within(listener: &UnixListener, wait: Option<Duration>) -> std::io::Result<bool> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    let timeout = wait.map(|wait| Timespec {
        tv_sec: wait.as_secs().try_into().unwrap_or(i64::MAX),
        tv_nsec: wait.subsec_nanos().into(),
    });
    let mut fds = [PollFd::new(listener, PollFlags::IN)];
    loop {
        match poll(&mut fds, timeout.as_ref()) {
            Ok(_) => break,
            // A signal the agent does not handle ends it; any other
            // interruption is waited out again.
            Err(rustix::io::Errno::INTR) => continue,
            Err(errno) => return Err(errno.into()),
        }
    }
    let revents = fds[0].revents();
    if revents.intersects(PollFlags::ERR | PollFlags::NVAL) {
        return Err(std::io::Error::other("the listening socket failed"));
    }
    Ok(revents.contains(PollFlags::IN))
}

/// Whether a failed request reached Smplify: it answered, if only with a
/// refusal or something this agent cannot read. A failure to connect,
/// resolve, finish a handshake or hear back at all did not.
fn reached_smplify(error: &UpstreamError) -> bool {
    use crate::http::HttpError;
    !matches!(
        error,
        UpstreamError::Transport(
            HttpError::Timeout | HttpError::Io(_) | HttpError::Resolve | HttpError::Tls
        )
    )
}

impl Daemon {
    fn admits(&self, stream: &UnixStream) -> bool {
        #[cfg(test)]
        if self.admit_any_peer {
            return true;
        }
        peer_is_root(stream)
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
    use std::sync::Arc;

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

    /// A Smplify that accepts every connection and never answers: each
    /// request spends whatever budget it was given. Its port, and the port
    /// each connection it accepted came from, in the order they came
    /// ([`settled`]).
    fn silent_smplify() -> (u16, Arc<Mutex<Vec<u16>>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let arrivals = Arc::new(Mutex::new(Vec::new()));
        let counted = Arc::clone(&arrivals);
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming().flatten() {
                let from = stream.peer_addr().map_or(0, |peer| peer.port());
                counted.lock().unwrap().push(from);
                held.push(stream);
            }
        });
        (port, arrivals)
    }

    /// How many connections reached the [`silent_smplify`] at `port` before
    /// now, exactly, however far behind its accept loop is. Every connection
    /// the agent made had completed its handshake before the call answered
    /// (connect returns only then), so it waits in the listener's queue ahead
    /// of the one this makes now, and the queue is accepted in order: once
    /// this one is counted, every connection before it has been. Once per
    /// test, after the calls it counts.
    fn settled(port: u16, arrivals: &Mutex<Vec<u16>>) -> usize {
        let marker = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mine = marker.local_addr().unwrap().port();
        let started = Instant::now();
        loop {
            if let Some(before) = arrivals.lock().unwrap().iter().rposition(|&p| p == mine) {
                return before;
            }
            assert!(
                started.elapsed() < PATIENCE,
                "the silent Smplify stopped accepting"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A Smplify nothing gets through to: every connection is closed as soon
    /// as it is accepted, as a link that drops mid-handshake closes it, so
    /// each request fails at once as a transport failure and spends none of
    /// its budget. A connection is counted before it is closed, and the
    /// agent cannot see the close until then, so once a call has answered
    /// the count holds every request it made. Its port, and the count.
    fn unreachable_smplify() -> (u16, Arc<Mutex<usize>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let arrivals = Arc::new(Mutex::new(0));
        let counted = Arc::clone(&arrivals);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                *counted.lock().unwrap() += 1;
                drop(stream);
            }
        });
        (port, arrivals)
    }

    /// Longer than any call against [`unreachable_smplify`] takes on any
    /// host, and shorter than every budget those tests hand out: a request
    /// that waited out its budget against a Smplify that refused it at once
    /// fails the test instead of passing it slowly.
    const PATIENCE: Duration = Duration::from_secs(20);

    /// How far past its whole budget a call against a [`silent_smplify`] may
    /// answer. The call ends at its deadline by the real clock, and this
    /// margin is the host's time to wake it and hand back the answer, so it
    /// is far more than any load stretches that to: what it catches is a
    /// request that outlives its deadline, not a busy scheduler. A client
    /// given a fresh budget, or built outside its deadline, is caught
    /// exactly, by what reaches Smplify
    /// (`the_time_spent_building_a_client_comes_out_of_the_call_budget`).
    const OVERRUN: Duration = Duration::from_secs(3);

    /// Answer one report on a thread of its own, from an agent holding
    /// `token`: the answer, the budget each request it made was given, in
    /// order, and how long the call took.
    fn report_granting(
        d: &Arc<Daemon>,
        token: &str,
        method: &str,
        key: &str,
    ) -> (String, Vec<Duration>, Duration) {
        d.granted.lock().unwrap().clear();
        let (took, line) = answer_apart(
            d,
            json!({"v": 1, "id": "r", "method": method,
                   "params": {"device_token": token, key: {}}}),
            PATIENCE,
        );
        let granted = std::mem::take(&mut *d.granted.lock().unwrap());
        (line, granted, took)
    }

    /// Answer `request` on a thread of its own, so a call that never
    /// returns fails the test instead of hanging it: how long it took, and
    /// the answer.
    fn answer_apart(
        daemon: &Arc<Daemon>,
        request: Value,
        patience: Duration,
    ) -> (Duration, String) {
        let daemon = Arc::clone(daemon);
        let (sender, answer) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let started = Instant::now();
            let line = daemon.answer_line(&request.to_string());
            let _ = sender.send((started.elapsed(), line));
        });
        answer
            .recv_timeout(patience)
            .expect("the call outlived its patience")
    }

    /// An organization whose Smplify is at `port` on this machine, as
    /// `org.discover` would resolve it.
    fn organization_at(port: u16) -> Value {
        json!({
            "id": "acme",
            "name": "Acme",
            "enrollment": {"server": format!("https://127.0.0.1:{port}"), "methods": ["code"]},
        })
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

    /// Smplify keeps the device record it creates at `/enroll` and refuses a
    /// second one for the same machine, so a registration punard gave up on
    /// can lock the device out. However slow Smplify is, registering answers
    /// within one register budget, which punard waits out: resolving and
    /// enrolling share one deadline, resolving may not spend all of it, and
    /// nothing else is asked of Smplify.
    ///
    /// Held to the budgets the two requests were given, to exactly the
    /// requests that reached Smplify, and to the whole call's time by the
    /// real clock with a margin no host load reaches ([`OVERRUN`]).
    #[test]
    fn a_registration_answers_within_its_budget_from_a_silent_smplify() {
        // Long enough that building a client, which reads the system's
        // roots, never spends a third of it even on a loaded host: both
        // requests are sent, and each waits out its deadline.
        const BUDGET: Duration = Duration::from_secs(3);
        let (d, root) = daemon();
        let (port, arrivals) = silent_smplify();
        std::fs::write(
            root.join("discovery/acme.com.json"),
            organization_at(port).to_string(),
        )
        .unwrap();
        let d = Arc::new(d.with_register_budget(BUDGET));
        let line = d.answer_line(
            r#"{"v":1,"id":"a","method":"org.discover","params":{"domain":"acme.com"}}"#,
        );
        assert!(line.contains(r#""result""#), "{line}");

        let (took, line) = answer_apart(
            &d,
            json!({"v": 1, "id": "r", "method": "enroll.register",
                   "params": {"device_id": "machine-1", "bootstrap": "b", "code": "lex_1"}}),
            BUDGET + PATIENCE,
        );
        assert!(
            line.contains(r#""error""#),
            "Smplify never answered: {line}"
        );
        assert!(
            took < BUDGET + OVERRUN,
            "a registration against a {BUDGET:?} deadline answered after {took:?}"
        );
        let granted = d.granted.lock().unwrap().clone();
        assert_eq!(
            granted.len(),
            2,
            "resolving and enrolling, nothing else: {granted:?}"
        );
        assert_eq!(
            granted[0],
            BUDGET / 3,
            "resolving may spend a third at most"
        );
        // The silent Smplify held the resolve for the whole of its third, so
        // /enroll was given what was left of the one deadline, never a fresh
        // one. A socket timeout can fire up to a scheduler tick early, which
        // is the difference between a third and the quarter asserted.
        assert!(
            granted[1] <= BUDGET - BUDGET / 4,
            "enrolling was given {:?} of a {BUDGET:?} deadline after resolving waited out its third",
            granted[1]
        );
        // And enough to go out: /enroll always has what resolving's third
        // left, less only the moments the host took to wake the resolve and
        // make the key, which are far under a third. So both granted requests
        // were sent, and the count below cannot pass with a request made
        // outside `grant()` standing in for one that never went out.
        assert!(
            granted[1] >= BUDGET / 3,
            "enrolling was given only {:?} of a {BUDGET:?} deadline",
            granted[1]
        );
        assert_eq!(
            settled(port, &arrivals),
            granted.len(),
            "each granted request reached Smplify, and nothing else did"
        );
        assert!(!d.store.exists(), "no identity without a certificate");
        let _ = std::fs::remove_dir_all(root);
    }

    /// Building a client (reading the identity, loading the system's roots)
    /// takes time before its request is sent, and that time is spent from
    /// the request's own deadline, fixed before the client is built: never
    /// from a budget counted afresh when the request starts. Here each client
    /// takes longer to build than the whole of the budget left for it, so no
    /// request may go out at all, where a deadline counted from the request
    /// would send every one. Counted by what reaches Smplify, which no host
    /// load changes: the setup is slept, so a busy host only makes each
    /// deadline further past.
    #[test]
    fn the_time_spent_building_a_client_comes_out_of_the_call_budget() {
        const BUDGET: Duration = Duration::from_millis(300);
        const SETUP: Duration = Duration::from_millis(600);
        let (d, root) = daemon();
        let d = d
            .with_call_budget(BUDGET)
            .with_pin_budget(BUDGET, Duration::from_secs(600))
            .with_client_setup(SETUP);
        let (port, arrivals) = unreachable_smplify();
        let token = enrolled_at(&d, port);
        let d = Arc::new(d);

        let (line, granted, _) = report_granting(&d, &token, "inventory.report", "inventory");
        assert!(line.contains(r#""error""#), "{line}");
        assert_eq!(granted.len(), 1, "one request: {granted:?}");
        assert_eq!(
            *arrivals.lock().unwrap(),
            0,
            "the inventory went out after its deadline"
        );

        // The check-in's client outlives the check-in's budget, and building
        // it leaves nothing of the report's whole budget for the POST, whose
        // client is then not even built.
        let (line, granted, _) = report_granting(&d, &token, "compliance.report", "report");
        assert!(line.contains("no time was left in this call"), "{line}");
        assert_eq!(granted, [BUDGET], "only the check-in was given a deadline");
        assert_eq!(
            *arrivals.lock().unwrap(),
            0,
            "the check-in went out after its deadline"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// The same for registering, where punard giving up costs most:
    /// resolving's client takes longer to build than resolving's third, and
    /// enrolling's longer than what is then left of the one deadline, so
    /// neither request may go out. A /enroll given a fresh budget would.
    #[test]
    fn a_registration_spends_the_time_building_its_clients_from_its_one_deadline() {
        const BUDGET: Duration = Duration::from_millis(1200);
        const SETUP: Duration = Duration::from_millis(700);
        let (d, root) = daemon();
        let (port, arrivals) = unreachable_smplify();
        std::fs::write(
            root.join("discovery/acme.com.json"),
            organization_at(port).to_string(),
        )
        .unwrap();
        let d = Arc::new(d.with_register_budget(BUDGET).with_client_setup(SETUP));
        let line = d.answer_line(
            r#"{"v":1,"id":"a","method":"org.discover","params":{"domain":"acme.com"}}"#,
        );
        assert!(line.contains(r#""result""#), "{line}");

        let (_, line) = answer_apart(
            &d,
            json!({"v": 1, "id": "r", "method": "enroll.register",
                   "params": {"device_id": "machine-1", "bootstrap": "b", "code": "lex_1"}}),
            PATIENCE,
        );
        assert!(line.contains(r#""error""#), "{line}");
        let granted = d.granted.lock().unwrap().clone();
        assert_eq!(granted.len(), 2, "resolving and enrolling: {granted:?}");
        assert_eq!(granted[0], BUDGET / 3);
        assert!(
            granted[1] <= BUDGET - SETUP,
            "enrolling was given {:?} after resolving's client took {SETUP:?} to build",
            granted[1]
        );
        assert_eq!(
            *arrivals.lock().unwrap(),
            0,
            "a request went out after its deadline"
        );
        assert!(!d.store.exists(), "no identity without a certificate");
        let _ = std::fs::remove_dir_all(root);
    }

    /// Against a Smplify that never answers, a compliance report waits out
    /// the check-in's budget and then what is left for its POST, and answers
    /// once both are spent: by the real clock, within its whole budget and a
    /// margin no host load reaches ([`OVERRUN`]).
    #[test]
    fn a_compliance_report_to_a_silent_smplify_ends_with_its_whole_budget() {
        // Long enough that building each client never spends it all, even
        // on a loaded host: both requests are sent and wait out their
        // deadlines.
        const BUDGET: Duration = Duration::from_millis(1000);
        const PIN: Duration = Duration::from_millis(1000);
        let (d, root) = daemon();
        let d = d
            .with_call_budget(BUDGET)
            .with_pin_budget(PIN, Duration::from_secs(600));
        let (port, arrivals) = silent_smplify();
        let token = enrolled_at(&d, port);
        let d = Arc::new(d);
        let (line, granted, took) = report_granting(&d, &token, "compliance.report", "report");
        assert!(line.contains(r#""error""#), "{line}");
        assert!(
            took < PIN + BUDGET + OVERRUN,
            "a compliance report against a {:?} budget answered after {took:?}",
            PIN + BUDGET
        );
        assert_eq!(granted.len(), 2, "the check-in, then the POST: {granted:?}");
        assert_eq!(granted[0], PIN);
        assert!(granted[1] <= BUDGET, "{granted:?}");
        assert_eq!(
            settled(port, &arrivals),
            2,
            "the check-in and the POST reached Smplify, and nothing else did"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Once Smplify has issued the certificate, the agent only stores it and
    /// answers: the check-in that pins the tenant key is the first compliance
    /// report's, so a slow check-in can never make punard give up on a
    /// registration Smplify already recorded.
    #[test]
    fn a_registration_smplify_accepted_is_kept_without_asking_smplify_again() {
        let (d, root) = daemon();
        let (port, arrivals) = silent_smplify();
        let d = d.with_call_budget(Duration::from_millis(500));
        let organization = discovery::parse_document("acme.com", organization_at(port)).unwrap();
        let csr = identity::generate_csr().unwrap();
        let key = rcgen::KeyPair::from_pem(&csr.key_pem).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["dev-1".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let enrolled = Enrolled {
            device_id: "dev-1".into(),
            cert_pem: cert.pem(),
            ca_pem: cert.pem(),
            not_after: None,
        };

        let answer = d
            .keep_identity(organization, "punar".into(), &csr, enrolled)
            .unwrap();
        assert!(answer["device_token"].as_str().is_some(), "{answer}");
        assert_eq!(settled(port, &arrivals), 0, "Smplify was asked again");
        let status = d.identity_status(None).unwrap();
        assert_eq!(status["device_id"], "dev-1");
        assert_eq!(status["tenant_key_pinned"], false);
        let _ = std::fs::remove_dir_all(root);
    }

    /// A report that Smplify kept but whose answer reaches punard late reads
    /// there as "unreachable", and the whole inventory is then uploaded again
    /// on every pass. So even while the tenant key is unpinned and nothing
    /// reaches Smplify at all, each report answers within the agent's budget
    /// for it, which punard waits out: the inventory report makes one
    /// request, and the compliance report's check-in has a budget of its own
    /// beside its status POST's. A check-in that failed is not tried again
    /// until its retry time, which doubles, so a Smplify that never answers it
    /// does not cost every pass a second request.
    ///
    /// Held to the budgets the requests were given, and to the agent's clock,
    /// which the test steps over the retry waits: the HTTP client keeps each
    /// request to its deadline (`http::tests`), the time building its client
    /// takes included (`the_time_spent_building_a_client_comes_out_of_the_call_budget`),
    /// and a whole report against a Smplify that never answers is timed
    /// end to end with a margin no load reaches
    /// (`a_compliance_report_to_a_silent_smplify_ends_with_its_whole_budget`).
    /// A stopwatch or a sleep here, on a loaded host, would say as much about
    /// the host as about the agent.
    #[test]
    fn a_report_answers_within_its_budget_and_a_failing_pin_backs_off() {
        // Handed out, never spent: every request fails at once.
        const BUDGET: Duration = Duration::from_secs(60);
        const PIN: Duration = Duration::from_secs(40);
        const RETRY: Duration = Duration::from_secs(600);
        let (d, root) = daemon();
        let d = d.with_call_budget(BUDGET).with_pin_budget(PIN, RETRY);
        let (port, arrivals) = unreachable_smplify();
        let token = enrolled_at(&d, port);
        let d = Arc::new(d);
        let report = |method: &str, key: &str| {
            let (line, granted, _) = report_granting(&d, &token, method, key);
            assert!(
                line.contains(r#""error""#),
                "nothing reached Smplify: {line}"
            );
            granted
        };
        let arrived = || *arrivals.lock().unwrap();

        // One request, given what is left of the call's budget: all of it,
        // but for the moments the call spent before asking.
        let (line, granted, took) = report_granting(&d, &token, "inventory.report", "inventory");
        assert!(line.contains(r#""error""#), "{line}");
        assert_eq!(
            granted.len(),
            1,
            "the inventory report asks Smplify one thing: {granted:?}"
        );
        assert!(
            granted[0] <= BUDGET && granted[0] + took >= BUDGET,
            "the inventory report was given {:?} of its {BUDGET:?}",
            granted[0]
        );
        assert_eq!(arrived(), 1);

        // The check-in first, with a budget of its own, then the status POST
        // with the call's.
        assert_eq!(
            report("compliance.report", "report"),
            [PIN, BUDGET],
            "the compliance report tries the pin first"
        );
        assert_eq!(arrived(), 3);

        // Until its retry time, a failed check-in is not tried again.
        d.advance(RETRY / 2);
        assert_eq!(
            report("compliance.report", "report"),
            [BUDGET],
            "only the status POST"
        );
        assert_eq!(arrived(), 4);

        // Then it is, once.
        d.advance(RETRY);
        assert_eq!(
            report("compliance.report", "report"),
            [PIN, BUDGET],
            "the check-in is retried after its wait"
        );
        assert_eq!(arrived(), 6);

        // And after failing again it waits twice as long: not after one
        // retry time, but after two.
        d.advance(RETRY);
        assert_eq!(
            report("compliance.report", "report"),
            [BUDGET],
            "the second wait is longer than the first"
        );
        d.advance(RETRY);
        assert_eq!(
            report("compliance.report", "report"),
            [PIN, BUDGET],
            "and ends after twice the first"
        );
        assert_eq!(arrived(), 9);
        let _ = std::fs::remove_dir_all(root);
    }

    /// A compliance report is held to its whole budget from the moment the
    /// call begins, however long the tenant-key check-in before it took: a
    /// check-in that overran its own budget (a slow name lookup, a slow
    /// disk) leaves the status POST only what is left, and none at all once
    /// the budget is spent, so the answer still reaches punard inside its
    /// wait and a report Smplify stored is never read as unreachable.
    #[test]
    fn a_report_after_a_slow_check_in_keeps_to_its_whole_budget() {
        const BUDGET: Duration = Duration::from_secs(60);
        const PIN: Duration = Duration::from_secs(40);
        let (d, root) = daemon();
        let d = d
            .with_call_budget(BUDGET)
            .with_pin_budget(PIN, Duration::from_secs(600));
        let (port, arrivals) = unreachable_smplify();
        let token = enrolled_at(&d, port);
        let d = Arc::new(d);
        let report = |overrun: Duration| {
            *d.pin_overrun.lock().unwrap() = overrun;
            // Each report tries the check-in, whatever the last one did.
            *d.pin_retry.lock().unwrap() = None;
            report_granting(&d, &token, "compliance.report", "report")
        };

        // The check-in and its overrun spent the whole budget: nothing is
        // left for the POST, which is not sent.
        let (line, granted, _) = report(PIN + BUDGET);
        assert!(line.contains("no time was left in this call"), "{line}");
        assert_eq!(granted, [PIN], "only the check-in");
        assert_eq!(*arrivals.lock().unwrap(), 1);

        // It overran by less: the POST is given what is left of the whole
        // budget, which is less than its own, and never a fresh one. Only the
        // time the call really took comes off it besides.
        let overrun = PIN + BUDGET / 2;
        let left = PIN + BUDGET - overrun;
        let (line, granted, took) = report(overrun);
        assert!(line.contains(r#""error""#), "{line}");
        assert_eq!(granted.len(), 2, "the check-in, then the POST: {granted:?}");
        assert_eq!(granted[0], PIN);
        assert!(
            granted[1] <= left && granted[1] + took >= left,
            "the POST was given {:?} when {left:?} was left of the call's budget",
            granted[1]
        );
        assert_eq!(*arrivals.lock().unwrap(), 3);
        let _ = std::fs::remove_dir_all(root);
    }

    /// An outage backs the tenant-key check-in off like any failure, but
    /// once a status POST gets through again the link is back, and the next
    /// compliance report tries the check-in at once instead of waiting out
    /// what the outage built up.
    #[test]
    fn a_check_in_an_outage_backed_off_is_tried_once_the_link_is_back() {
        const BUDGET: Duration = Duration::from_secs(60);
        const PIN: Duration = Duration::from_secs(40);
        let (d, root) = daemon();
        let d = d
            .with_call_budget(BUDGET)
            .with_pin_budget(PIN, Duration::from_secs(600));
        let (port, arrivals) = unreachable_smplify();
        let token = enrolled_at(&d, port);
        let d = Arc::new(d);
        let report = || report_granting(&d, &token, "compliance.report", "report").1;
        let arrived = || *arrivals.lock().unwrap();
        assert_eq!(report(), [PIN, BUDGET], "the check-in, then the POST");
        assert_eq!(arrived(), 2);
        assert!(
            d.link_down.load(Ordering::SeqCst),
            "a POST that reached nothing is an outage"
        );
        assert_eq!(report(), [BUDGET], "the check-in waits");
        assert_eq!(arrived(), 3);
        // A POST gets through: nothing here can answer one, so the agent is
        // told as a report that got through would tell it.
        d.after_compliance_post(true);
        assert_eq!(
            report(),
            [PIN, BUDGET],
            "the check-in is tried again at once"
        );
        assert_eq!(arrived(), 5);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Only a compliance report speaks for the link, and only one that could
    /// not reach Smplify at all says it is down. An inventory that cannot get
    /// through while reports do is no outage, so a compliance report that
    /// gets through afterwards does not cut short the wait of a check-in that
    /// keeps failing; and a refusal is Smplify answering.
    #[test]
    fn only_a_compliance_report_that_could_not_reach_smplify_says_the_link_is_down() {
        let (d, root) = daemon();
        let d = d
            .with_call_budget(Duration::from_secs(60))
            .with_pin_budget(Duration::from_secs(40), Duration::from_secs(600));
        let (port, arrivals) = unreachable_smplify();
        let token = enrolled_at(&d, port);
        let waiting = d.now() + Duration::from_secs(600);
        *d.pin_retry.lock().unwrap() = Some(PinRetry {
            device_id: "dev-1".into(),
            failures: 3,
            not_before: waiting,
        });
        let d = Arc::new(d);
        let (line, _, _) = report_granting(&d, &token, "inventory.report", "inventory");
        assert!(line.contains(r#""error""#), "{line}");
        assert_eq!(*arrivals.lock().unwrap(), 1);
        // A compliance report gets through.
        d.after_compliance_post(true);
        assert!(
            d.pin_retry
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|retry| retry.not_before == waiting),
            "the check-in keeps its wait"
        );

        assert!(!reached_smplify(&UpstreamError::Transport(
            crate::http::HttpError::Timeout
        )));
        assert!(reached_smplify(&UpstreamError::Status {
            status: 422,
            detail: String::new(),
        }));
        let _ = std::fs::remove_dir_all(root);
    }

    /// A listener on a fresh path served on a thread of its own, answering
    /// any peer (tests are not root): how it stopped arrives on the channel.
    fn serve_apart(
        d: &Arc<Daemon>,
        root: &Path,
        idle: Duration,
    ) -> (PathBuf, std::sync::mpsc::Receiver<std::io::Result<Stopped>>) {
        let socket = root.join("api.sock");
        let listener = bind(&socket).unwrap();
        let d = Arc::clone(d);
        let (sender, stopped) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(d.serve_listener(listener, Some(idle)));
        });
        (socket, stopped)
    }

    fn call(socket: &Path, request: Value) -> Value {
        let mut stream = UnixStream::connect(socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        writeln!(stream, "{request}").unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    fn admitting(mut d: Daemon) -> Daemon {
        d.admit_any_peer = true;
        d
    }

    /// An identity on disk whose Smplify is `server`, and the device token
    /// punard would hold for it.
    fn enrolled_with(d: &Daemon, server: &str) -> Zeroizing<String> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["dev-1".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let (token, token_sha256) = identity::new_device_token().unwrap();
        d.store
            .save(
                &Record {
                    device_id: "dev-1".into(),
                    server: server.into(),
                    org_id: "acme".into(),
                    org_name: "Acme".into(),
                    os_identifier: "punar".into(),
                    not_after: None,
                    tenant_public_key: None,
                    token_sha256,
                    enrolled_at: "2026-09-24T00:00:00Z".into(),
                },
                &Zeroizing::new(key.serialize_pem()),
                &cert.pem(),
                &cert.pem(),
            )
            .unwrap();
        token
    }

    /// An identity on disk, and the device token punard would hold for it.
    fn enrolled_store(d: &Daemon) -> Zeroizing<String> {
        enrolled_with(d, "https://api.acme.example")
    }

    /// The same, for a Smplify on this machine at `port`.
    fn enrolled_at(d: &Daemon, port: u16) -> Zeroizing<String> {
        enrolled_with(d, &format!("https://127.0.0.1:{port}"))
    }

    /// An agent that holds no identity answers, and goes dormant once no call
    /// has come for the idle time: a device that never enrolled, or declined
    /// to, runs no agent.
    #[test]
    fn an_agent_with_no_identity_goes_dormant_once_idle() {
        const IDLE: Duration = Duration::from_millis(1000);
        let (d, root) = daemon();
        let d = Arc::new(admitting(d));
        let (socket, stopped) = serve_apart(&d, &root, IDLE);
        // Taken before the call, never after its answer: the agent starts
        // its idle wait only once it has answered, so this is no later than
        // that wait began, however long the host takes to hand the answer
        // back to this thread.
        let asked = Instant::now();
        let answer = call(
            &socket,
            json!({"v": 1, "id": "a", "method": "identity.status"}),
        );
        assert_eq!(answer["result"], json!({"enrolled": false}));
        assert_eq!(
            stopped.recv_timeout(IDLE * 10).expect("dormant").unwrap(),
            Stopped::Dormant
        );
        assert!(asked.elapsed() >= IDLE, "not before the idle time");
        let _ = std::fs::remove_dir_all(root);
    }

    /// Anything left of an identity keeps the agent running, a key whose
    /// record was deleted included: deleting `device.json` is not a quiet way
    /// to stop it. It answers that it holds no identity, which punard, being
    /// enrolled, reports as management interrupted. Once nothing at all is
    /// left, the next call starts the idle time again.
    #[test]
    fn anything_left_of_an_identity_keeps_the_agent_running() {
        const IDLE: Duration = Duration::from_millis(200);
        let (d, root) = daemon();
        let d = Arc::new(admitting(d));
        enrolled_store(&d);
        std::fs::remove_file(d.store.path().join("device.json")).unwrap();
        let (socket, stopped) = serve_apart(&d, &root, IDLE);
        let answer = call(
            &socket,
            json!({"v": 1, "id": "a", "method": "identity.status"}),
        );
        assert_eq!(answer["result"], json!({"enrolled": false}));
        assert!(
            stopped.recv_timeout(IDLE * 5).is_err(),
            "the key is still there"
        );
        d.store.wipe().unwrap();
        call(
            &socket,
            json!({"v": 1, "id": "b", "method": "identity.status"}),
        );
        assert_eq!(
            stopped.recv_timeout(IDLE * 10).expect("dormant").unwrap(),
            Stopped::Dormant
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// `enroll.unregister` wipes the identity punard's token names without
    /// asking Smplify anything, answers, and the agent goes dormant at once,
    /// long before its idle time. Another token is refused and the identity
    /// kept; `identity.status` says which token is the identity's.
    #[test]
    fn an_unregister_wipes_answers_and_goes_dormant_at_once() {
        let (d, root) = daemon();
        let d = Arc::new(admitting(d));
        let token = enrolled_store(&d);
        let (socket, stopped) = serve_apart(&d, &root, Duration::from_secs(600));
        let status = |token: &str| {
            call(
                &socket,
                json!({"v": 1, "id": "s", "method": "identity.status",
                       "params": {"device_token": token}}),
            )["result"]
                .clone()
        };
        assert_eq!(status(&token)["token_matches"], true);
        assert_eq!(status("not-the-token")["token_matches"], false);
        let refused = call(
            &socket,
            json!({"v": 1, "id": "u", "method": "enroll.unregister",
                   "params": {"device_token": "not-the-token"}}),
        );
        assert_eq!(refused["error"]["code"], "unauthorized", "{refused}");
        assert!(d.store.load().unwrap().is_some(), "kept");

        let wiped = call(
            &socket,
            json!({"v": 1, "id": "u", "method": "enroll.unregister",
                   "params": {"device_token": &*token}}),
        );
        assert_eq!(wiped["result"], json!({"wiped": true}), "{wiped}");
        assert_eq!(
            stopped
                .recv_timeout(Duration::from_secs(5))
                .expect("dormant at once")
                .unwrap(),
            Stopped::Dormant
        );
        assert!(!d.store.holds_anything());
        let _ = std::fs::remove_dir_all(root);
    }

    /// A wipe whose answer never reached punard is asked for again: with no
    /// identity left there is nothing to authorize, and whatever a crash
    /// left of one goes too, so punard can confirm it.
    #[test]
    fn an_unregister_with_nothing_left_to_authorize_is_confirmed() {
        let (d, root) = daemon();
        let token = enrolled_store(&d);
        std::fs::remove_file(d.store.path().join("device.json")).unwrap();
        let line = d.answer_line(
            &json!({"v": 1, "id": "u", "method": "enroll.unregister",
                    "params": {"device_token": &*token}})
            .to_string(),
        );
        assert!(line.contains(r#""wiped":true"#), "{line}");
        assert!(!d.store.holds_anything(), "the key went too");
        let _ = std::fs::remove_dir_all(root);
    }

    /// punard, holding no enrollment, asks for whatever the agent holds to
    /// go (`any_identity`): an identity its token does not name, and one it
    /// never received a token for (a registration whose answer was lost),
    /// are wiped as surely as its own, so no key is left with nothing that
    /// can remove it. Without the flag the token still has to match.
    #[test]
    fn an_unregister_for_any_identity_wipes_one_the_token_does_not_name() {
        let (d, root) = daemon();
        enrolled_store(&d);
        let refused = d.answer_line(
            &json!({"v": 1, "id": "u", "method": "enroll.unregister",
                    "params": {"device_token": "not-the-token"}})
            .to_string(),
        );
        assert!(refused.contains("unauthorized"), "{refused}");
        assert!(d.store.holds_anything());
        let line = d.answer_line(
            &json!({"v": 1, "id": "u", "method": "enroll.unregister",
                    "params": {"device_token": "not-the-token", "any_identity": true}})
            .to_string(),
        );
        assert!(line.contains(r#""wiped":true"#), "{line}");
        assert!(!d.store.holds_anything());

        enrolled_store(&d);
        let line = d.answer_line(
            &json!({"v": 1, "id": "u", "method": "enroll.unregister",
                    "params": {"any_identity": true}})
            .to_string(),
        );
        assert!(line.contains(r#""wiped":true"#), "{line}");
        assert!(!d.store.holds_anything(), "no token needed");
        let _ = std::fs::remove_dir_all(root);
    }

    /// Nothing assigned and something assigned that this release cannot use
    /// are both an empty list, and only the marker tells punard which: only
    /// the first may withdraw the policy the device enforces.
    #[test]
    fn policy_fetch_says_what_an_empty_list_means() {
        assert_eq!(
            policy_answer(None),
            json!({"policies": [], "assignment": "none"})
        );
        let bundle = Bundle {
            bytes: vec![0x1f, 0x8b, 0, 0],
            delivery_id: Some("dlv-1".into()),
        };
        assert_eq!(
            policy_answer(Some(&bundle)),
            json!({"policies": [], "assignment": "unusable"})
        );
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
