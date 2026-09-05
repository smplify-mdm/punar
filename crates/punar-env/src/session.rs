//! `punar-env agent <name>` — the managed AI agent session (SPEC section
//! 27's launch flow; docs/development/milestone-7.md section 5).
//!
//! What "managed" means here is exactly what can be proven: the agent runs
//! in a transient systemd **scope** named after its session id, so the
//! kernel's own cgroup line attributes every process in that session
//! (SPEC section 22), and inside a bubblewrap mount/PID/IPC/UTS boundary
//! that exposes only the declared project, a private home/runtime and an
//! ephemeral `/tmp`. `punar-agentd` reads the cgroup before it grants the
//! `managed` classification. `punar-env` never *claims* managed — it
//! launches into both boundaries, registers with the lifecycle pid, and
//! reports whatever classification the daemon computed.
//!
//! Fail-closed by design (milestone-7.md section 5.1): if the registry is
//! unreachable or refuses the registration, the scope is stopped and the
//! launch fails. An unregistered "managed" session is a contradiction this
//! command refuses to create.
//!
//! The agent remains a host process rather than moving inside the M6 Podman
//! toolchain container, but it no longer sees the host filesystem. Network
//! context, the secret broker and the tool gateway keep their own explicit
//! enforcement labels (SPEC 1.22); filesystem isolation is now enforced by
//! the kernel rather than left as a declaration.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use punar_common::agent::{
    AgentClassification, AgentsRegisterParams, AuthorityRow, AuthoritySummary,
};
use punar_common::network::{NetworkSessionEnforcement, NetworkSessionReadyState};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::adapter::{self, MOCK_LABEL};
use crate::agentd::{self, AgentdError};
use crate::authority::{self, Citation};
use crate::engine::{EnvError, project_grade};
use crate::isolation::{
    self, BWRAP_PATH, PUNAR_ENV_PATH, SANDBOX_WORKSPACE, SYSTEMCTL_PATH, SYSTEMD_RUN_PATH,
    SessionIsolation,
};
use crate::manifest::{FilesystemAccess, Manifest};
use crate::netd;
use crate::render::RULE_WIDTH;

/// Sentinel environment for a session that runs on the host (the M7 case;
/// milestone-7.md section 5.6).
const ENVIRONMENT_HOST: &str = "host";

/// Version reported for a mock session — never a version string that could
/// be mistaken for a real agent build.
const VERSION_MOCK: &str = "mock";

/// Version reported when the adapter has no probe, or the probe failed.
const VERSION_UNKNOWN: &str = "unknown";

/// The parent waits only for the fixed gate's exact-session proof.  The gate's
/// agentd/netd calls have their own finite I/O budgets and fail without ever
/// executing Bubblewrap; this outer bound is teardown-only, never a release.
const GATE_WAIT: Duration = Duration::from_secs(45);
const GATE_POLL_INTERVAL: Duration = Duration::from_millis(25);
const GATE_SPEC_VERSION: u8 = 1;

/// The transient scope unit for a session: the SPEC section 22
/// attribution chain, spelled once.
pub fn scope_unit(session_id: &str) -> String {
    format!("punar-agent-{session_id}.scope")
}

/// The `systemd-run` argv for a managed session. **Fixed argv** (M6
/// section 3.2): one argument per item, no host shell anywhere. The isolated
/// command starts after systemd-run's `--`; bubblewrap has its own separator
/// before the adapter argv.
pub fn systemd_run_argv(
    session_id: &str,
    agent: &str,
    project: &str,
    gate_spec: &Path,
    nonce: &str,
) -> Vec<std::ffi::OsString> {
    let argv = vec![
        SYSTEMD_RUN_PATH.into(),
        "--user".into(),
        "--scope".into(),
        "--quiet".into(),
        "--collect".into(),
        format!("--unit=punar-agent-{session_id}").into(),
        std::ffi::OsString::from(format!(
            "--description=Punar managed AI agent session {session_id} \
             ({agent}, project {project})"
        )),
        "--".into(),
        PUNAR_ENV_PATH.into(),
        "__agent-gate".into(),
        "--spec".into(),
        gate_spec.as_os_str().to_os_string(),
        "--session-id".into(),
        session_id.into(),
        "--nonce".into(),
        nonce.into(),
    ];
    argv
}

/// `systemctl --user stop <scope>` — the fail-closed teardown.
fn stop_scope_argv(unit: &str) -> Vec<String> {
    vec![
        SYSTEMCTL_PATH.to_string(),
        "--user".to_string(),
        "stop".to_string(),
        unit.to_string(),
    ]
}

/// Whether a `/proc/<pid>/cgroup` body places the process in `unit` — the
/// same evidence `punar-agentd` checks before granting `managed`.
pub fn cgroup_has_scope(cgroup: &str, unit: &str) -> bool {
    cgroup.lines().any(|line| {
        line.rsplit_once(':')
            .is_some_and(|(_, path)| path.split('/').any(|component| component == unit))
    })
}

/// Mint a session identity: `agt_` + 12 lowercase hex characters from the
/// OS RNG (milestone-7.md section 5.1 step 2). The launcher mints it
/// because the scope must carry the id *before* registration can verify
/// the scope; `punar-agentd` remains the authority that accepts it.
pub fn mint_session_id() -> Result<String, EnvError> {
    Ok(format!("agt_{}", random_hex::<6>()?))
}

fn mint_gate_nonce() -> Result<String, EnvError> {
    random_hex::<16>()
}

fn random_hex<const N: usize>() -> Result<String, EnvError> {
    let mut file = std::fs::File::open("/dev/urandom").map_err(|e| {
        EnvError::Runtime(format!(
            "cannot open /dev/urandom to create the agent session identity: {e}.\n\
             Every managed session needs an unguessable id (SPEC sections 19.2, 22); \
             punar-env will not fall back to a predictable one.\n\
             Next step: check that /dev/urandom is present and readable."
        ))
    })?;
    let mut bytes = [0u8; N];
    file.read_exact(&mut bytes).map_err(|e| {
        EnvError::Runtime(format!(
            "cannot read randomness for the agent session identity: {e}.\n\
             Next step: check that /dev/urandom is present and readable."
        ))
    })?;
    let mut id = String::with_capacity(N * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(id, "{byte:02x}");
    }
    Ok(id)
}

/// The only mutable handoff into the fixed trusted gate.  It contains no
/// program selector: argv[0] must be `/usr/bin/bwrap` and the gate refuses any
/// other value before registration.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentGateSpec {
    v: u8,
    nonce: String,
    registration: AgentsRegisterParams,
    project_path: PathBuf,
    home_path: PathBuf,
    sandbox_argv: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentGateReady {
    v: u8,
    nonce: String,
    session_id: String,
    process_id: u32,
    classification: AgentClassification,
    project: String,
    network_state: NetworkSessionReadyState,
    network_enforcement: NetworkSessionEnforcement,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentGateRelease {
    v: u8,
    nonce: String,
    session_id: String,
}

/// The membership check that survived the M6 stub verbatim: `<name>` must
/// be declared in the manifest's `ai.agents` list.
pub fn require_declared(m: &Manifest, name: &str) -> Result<(), EnvError> {
    if m.ai.agents.iter().any(|a| a == name) {
        return Ok(());
    }
    Err(EnvError::Runtime(format!(
        "agent '{name}' is not declared in this environment's manifest.\n\
         Declared agents: {}.\n\
         Next step: add it to ai.agents, or launch a declared agent.",
        m.ai.agents.join(" · ")
    )))
}

fn require_agent_runtime_supported(name: &str, mock: bool) -> Result<(), EnvError> {
    if !mock && name == "claude-code" {
        return Err(EnvError::Runtime(
            "Claude Code host sessions are not enabled by this bounded isolation slice.\n\
             Punar has not yet audited Claude's complete package/runtime closure or designed secure persistent authentication state, and mounting the real home would violate the managed-agent boundary.\n\
             Nothing was launched. Next step: use the explicitly labelled mock in image validation, or wait for the curated Claude package/state contract."
                .to_string(),
        ));
    }
    Ok(())
}

/// Everything one managed session is, gathered before the agent starts.
#[derive(Debug, Clone)]
pub struct Session {
    pub session_id: String,
    pub agent: String,
    pub adapter: String,
    pub version: String,
    pub project: String,
    pub environment: String,
    pub scope_unit: String,
    /// The adapter definition file that governed this launch — provenance
    /// the `--json` object carries so a reader can check the data that
    /// produced the session (SPEC section 26: adapters are data).
    pub definition_source: String,
    pub workdir: String,
    pub grade: FilesystemAccess,
    pub mock: bool,
    pub authority: AuthoritySummary,
    pub citation: Citation,
}

impl Session {
    /// The register params: only facts the launcher owns. `user`,
    /// `started_at` and `classification` are absent by design — the
    /// daemon stamps and computes them (ipc.md section 10.2).
    fn register_params(&self, process_id: u32) -> AgentsRegisterParams {
        AgentsRegisterParams {
            session_id: self.session_id.clone(),
            agent: self.agent.clone(),
            version: self.version.clone(),
            process_id,
            project: self.project.clone(),
            environment: self.environment.clone(),
            authority: self.authority.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering (Plate D-014 grammar in punar-env's dialect — see render.rs)
// ---------------------------------------------------------------------------

const LABEL_W: usize = 14;
const CAT_W: usize = 12;
const ZONE_W: usize = 13;
const VALUE_W: usize = 13;

fn pad(text: &str, width: usize) -> String {
    let len = text.chars().count();
    if len >= width {
        format!("{text} ")
    } else {
        format!("{text}{}", " ".repeat(width - len))
    }
}

/// Split `filesystem.project` into its category and zone halves for the
/// permission columns.
fn split_zone(zone: &str) -> (&str, &str) {
    zone.split_once('.').unwrap_or(("", zone))
}

/// The launch block: masthead, attribution, the authority register with
/// its policy citation, and the three not-yet-configured contexts, each
/// labeled with the milestone that will make it real (SPEC 1.22).
pub fn render_launch(s: &Session) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "PUNAR-ENV · AGENT SESSION · {}\n",
        s.session_id.to_uppercase()
    ));
    out.push_str(&"─".repeat(RULE_WIDTH));
    out.push('\n');
    if s.mock {
        out.push_str(MOCK_LABEL);
        out.push('\n');
    }
    out.push_str(&pad("Agent", LABEL_W));
    out.push_str(&format!(
        "{} · {} · adapter {}\n",
        s.agent, s.version, s.adapter
    ));
    out.push_str(&pad("Session", LABEL_W));
    out.push_str(&format!("{}\n", s.session_id));
    out.push_str(&pad("Scope", LABEL_W));
    out.push_str(&format!("{} · attribution via cgroup\n", s.scope_unit));
    out.push_str(&pad("Project", LABEL_W));
    out.push_str(&format!("{} · environment {}\n", s.project, s.environment));
    out.push_str(&pad("Workspace", LABEL_W));
    out.push_str(&format!(
        "{} → {} · {} · enforced by mount namespace\n",
        s.workdir,
        SANDBOX_WORKSPACE,
        s.grade.as_str()
    ));
    out.push_str(&pad("Isolation", LABEL_W));
    out.push_str("mount + PID + IPC + UTS · private home/tmp/runtime\n");

    out.push_str(&format!(
        "\nAUTHORITY · WHAT IT MAY ACCESS · POLICY · {}\n",
        s.citation.display()
    ));
    let zone_w = s
        .authority
        .rows
        .iter()
        .map(|r| split_zone(&r.zone).1.chars().count() + 2)
        .max()
        .unwrap_or(0)
        .max(ZONE_W);
    let value_w = s
        .authority
        .rows
        .iter()
        .map(|r| r.decision.chars().count() + 2)
        .max()
        .unwrap_or(0)
        .max(VALUE_W);
    for row in &s.authority.rows {
        let (category, zone) = split_zone(&row.zone);
        out.push_str(&format!(
            "  {}{}{}{}\n",
            pad(category, CAT_W),
            pad(zone, zone_w),
            pad(&row.decision, value_w),
            row.enforcement
        ));
    }

    // Keep the host-agent/container boundary explicit. Managed host-agent
    // sessions are attached to punar-netd policy by cgroup; project
    // containers remain --network none and therefore deny-only.
    out.push_str(
        "\nNETWORK · ENFORCED · exact nftables cgroup-v2 session rule verified · container: deny only\n",
    );
    out.push_str("CREDENTIALS · DECLARED · M9 secret broker · nothing is brokered in M7\n");
    out.push_str("TOOLS · M11+ · no tool gateway mediates this session yet\n");
    out
}

/// The registry line, printed once the daemon has accepted the session and
/// reported the classification it **computed** from the scope cgroup. A
/// classification other than `managed` is the honest downgrade the daemon
/// decided on, and the line says what that means rather than burying it.
pub fn render_registered(classification: AgentClassification, session_id: &str) -> String {
    let tail = match classification {
        AgentClassification::Managed => {
            "registered with punar-agentd · exact network rule verified".to_string()
        }
        other => format!(
            "registered with punar-agentd · the registry could not confirm the managed \
             scope, so this session is recorded as {}",
            other.as_str()
        ),
    };
    format!(
        "REGISTRY · {} · {} · {tail}\n",
        classification.as_str().to_uppercase(),
        session_id.to_uppercase()
    )
}

/// The one-line epilogue.
pub fn render_ended(session_id: &str, outcome: &Outcome) -> String {
    format!(
        "SESSION ENDED · {} · {}\n",
        session_id.to_uppercase(),
        outcome.describe()
    )
}

/// The `--json` object: the same facts as the human block, including the
/// enforcement labels — the honesty travels with the data (M6 section 7).
pub fn render_launch_json(s: &Session, classification: AgentClassification) -> Value {
    let rows: Vec<Value> = s
        .authority
        .rows
        .iter()
        .map(|r: &AuthorityRow| {
            json!({
                "zone": r.zone,
                "decision": r.decision,
                "enforcement": r.enforcement,
            })
        })
        .collect();
    json!({
        "v": 1,
        "command": "agent",
        "result": "launched",
        "session_id": s.session_id,
        "agent": s.agent,
        "adapter": s.adapter,
        "version": s.version,
        "mock": s.mock,
        "project": s.project,
        "environment": s.environment,
        "scope_unit": s.scope_unit,
        "adapter_definition": s.definition_source,
        "workspace": {
            "src": s.workdir,
            "dst": SANDBOX_WORKSPACE,
            "mode": s.grade.as_str(),
            "enforcement": "mount_namespace",
        },
        "classification": classification.as_str(),
        "authority": {
            "policy_citation": s.authority.policy_citation,
            "rows": rows,
        },
        "enforcement": {
            "authority": "filesystem enforced (mount namespace) · network enforced (agent scope) · credentials M9",
            "isolation": "mount_pid_ipc_uts",
            "network": "exact_session_nftables_cgroup_v2",
            "ledger": "M8",
        },
    })
}

/// How the agent process finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Exited(u8),
    Signaled(i32),
}

impl Outcome {
    fn describe(&self) -> String {
        match self {
            Outcome::Exited(code) => format!("exit {code}"),
            Outcome::Signaled(signal) => format!("terminated by signal {signal}"),
        }
    }

    /// The code `punar-env` exits with: the agent's own code passed
    /// through verbatim, or the shell convention 128+n for a signal.
    pub fn exit_code(&self) -> u8 {
        match self {
            Outcome::Exited(code) => *code,
            Outcome::Signaled(signal) => (128 + signal).clamp(0, 255) as u8,
        }
    }
}

// ---------------------------------------------------------------------------
// The launch itself
// ---------------------------------------------------------------------------

fn exact_gate_path(session_id: &str, file: &str) -> PathBuf {
    PathBuf::from(format!(
        "/run/user/{}/punar-agent-sessions/{session_id}/{file}",
        rustix::process::getuid().as_raw()
    ))
}

fn validate_gate_file(path: &Path, session_id: &str, file: &str) -> Result<(), EnvError> {
    let expected = exact_gate_path(session_id, file);
    if path != expected {
        return Err(EnvError::Runtime(format!(
            "the internal agent gate refused handoff path {} (expected {}).\n\
             The adapter was not released. Next step: launch agents only through `punar-env agent`.",
            path.display(),
            expected.display()
        )));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        EnvError::Runtime(format!(
            "the internal agent gate could not inspect {}: {error}.\n\
             The adapter was not released.",
            path.display()
        ))
    })?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > 256 * 1024
    {
        return Err(EnvError::Runtime(format!(
            "the internal agent gate refused {} because it is not a private, direct, bounded file owned by this uid.\n\
             The adapter was not released.",
            path.display()
        )));
    }
    Ok(())
}

fn write_private_json(path: &Path, value: &impl Serialize) -> Result<(), EnvError> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        EnvError::Runtime(format!(
            "the managed-agent gate handoff could not be encoded: {error}.\n\
             The adapter was not launched."
        ))
    })?;
    // The peer polls for the final name and parses it immediately, so the
    // final name must only ever appear complete: write a private sibling,
    // commit it, then link it into place. A hard link fails if the final
    // name already exists, preserving create-new semantics.
    let staged = path.with_extension("partial");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged)
        .map_err(|error| {
            EnvError::Runtime(format!(
                "the managed-agent gate handoff {} could not be created privately: {error}.\n\
                 The adapter was not launched.",
                path.display()
            ))
        })?;
    file.write_all(&bytes).map_err(|error| {
        EnvError::Runtime(format!(
            "the managed-agent gate handoff {} could not be written: {error}.\n\
             The adapter was not launched.",
            path.display()
        ))
    })?;
    file.sync_all().map_err(|error| {
        EnvError::Runtime(format!(
            "the managed-agent gate handoff {} could not be committed: {error}.\n\
             The adapter was not launched.",
            path.display()
        ))
    })?;
    drop(file);
    let published = std::fs::hard_link(&staged, path).map_err(|error| {
        EnvError::Runtime(format!(
            "the managed-agent gate handoff {} could not be published: {error}.\n\
             The adapter was not launched.",
            path.display()
        ))
    });
    let _ = std::fs::remove_file(&staged);
    published
}

fn prepare_gate_spec(
    isolation: &SessionIsolation,
    session: &Session,
    project_path: &Path,
    sandbox_argv: &[OsString],
    nonce: &str,
) -> Result<PathBuf, EnvError> {
    let sandbox_argv = sandbox_argv
        .iter()
        .map(|argument| {
            argument.clone().into_string().map_err(|_| {
                EnvError::Runtime(
                    "managed AI isolation refused a non-UTF-8 Bubblewrap argument.\n\
                     The fixed gate uses an exact JSON handoff and will not reinterpret lossy paths.\n\
                     Next step: use a UTF-8 project path and retry."
                        .to_string(),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let spec = AgentGateSpec {
        v: GATE_SPEC_VERSION,
        nonce: nonce.to_string(),
        registration: session.register_params(0),
        project_path: project_path.to_path_buf(),
        home_path: isolation.home_destination().to_path_buf(),
        sandbox_argv,
    };
    let path = isolation.gate_spec_path();
    write_private_json(&path, &spec)?;
    Ok(path)
}

fn read_gate_spec(path: &Path, session_id: &str, nonce: &str) -> Result<AgentGateSpec, EnvError> {
    validate_gate_file(path, session_id, "gate.json")?;
    let bytes = fs::read(path).map_err(|error| {
        EnvError::Runtime(format!(
            "the internal agent gate could not read {}: {error}.\n\
             The adapter was not released.",
            path.display()
        ))
    })?;
    let spec: AgentGateSpec = serde_json::from_slice(&bytes).map_err(|error| {
        EnvError::Runtime(format!(
            "the internal agent gate refused a malformed handoff: {error}.\n\
             The adapter was not released."
        ))
    })?;
    validate_gate_spec_contents(&spec, session_id, nonce)?;
    Ok(spec)
}

fn validate_gate_spec_contents(
    spec: &AgentGateSpec,
    session_id: &str,
    nonce: &str,
) -> Result<(), EnvError> {
    let command_separator = spec
        .sandbox_argv
        .iter()
        .rposition(|argument| argument == "--");
    if spec.v != GATE_SPEC_VERSION
        || spec.nonce != nonce
        || spec.registration.session_id != session_id
        || spec.registration.process_id != 0
        || spec.sandbox_argv.first().map(String::as_str) != Some(BWRAP_PATH)
        || command_separator.is_none_or(|index| index + 1 >= spec.sandbox_argv.len())
        || !spec
            .sandbox_argv
            .iter()
            .any(|argument| argument == "--clearenv")
        || spec.sandbox_argv.iter().any(|argument| {
            matches!(
                argument.as_str(),
                "/run/punar-agentd"
                    | "/run/punar-agentd/agentd.sock"
                    | "/run/punar-netd"
                    | "/run/punar-netd/netd.sock"
                    | "/run/punard"
                    | "/run/punard/punard.sock"
                    | "/run/punar-secrets"
                    | "/run/punar-secrets/secrets.sock"
            )
        })
    {
        return Err(EnvError::Runtime(
            "the internal agent gate handoff did not match its exact version, nonce, session, fixed Bubblewrap executable, closed environment, command separator, and control/broker-socket exclusions.\n\
             The adapter was not released. Next step: launch agents only through `punar-env agent`."
                .to_string(),
        ));
    }
    Ok(())
}

fn require_gate_process(session_id: &str) -> Result<(), EnvError> {
    isolation::require_launch_tools()?;
    let executable = fs::read_link("/proc/self/exe").map_err(|error| {
        EnvError::Runtime(format!(
            "the internal agent gate could not prove its executable identity: {error}.\n\
             The adapter was not released."
        ))
    })?;
    if executable != Path::new(PUNAR_ENV_PATH) {
        return Err(EnvError::Runtime(format!(
            "the internal agent gate is running as {}, not the fixed trusted {}.\n\
             The adapter was not released.",
            executable.display(),
            PUNAR_ENV_PATH
        )));
    }
    let unit = scope_unit(session_id);
    let cgroup = fs::read_to_string("/proc/self/cgroup").map_err(|error| {
        EnvError::Runtime(format!(
            "the internal agent gate could not read its cgroup: {error}.\n\
             The adapter was not released."
        ))
    })?;
    if !cgroup_has_scope(&cgroup, &unit) {
        return Err(EnvError::Runtime(format!(
            "the internal agent gate is not attributed to exact scope {unit}.\n\
             The adapter was not released; an unattributed managed session is forbidden."
        )));
    }
    Ok(())
}

fn wait_for_gate_release(session_id: &str, nonce: &str) -> Result<(), EnvError> {
    let path = exact_gate_path(session_id, "gate.release.json");
    let deadline = Instant::now() + GATE_WAIT;
    loop {
        if path.exists() {
            validate_gate_file(&path, session_id, "gate.release.json")?;
            let bytes = fs::read(&path).map_err(|error| {
                EnvError::Runtime(format!(
                    "the internal gate could not read its parent release: {error}.\n\
                     The adapter was not released."
                ))
            })?;
            let release: AgentGateRelease = serde_json::from_slice(&bytes).map_err(|error| {
                EnvError::Runtime(format!(
                    "the internal gate refused a malformed parent release: {error}.\n\
                     The adapter was not released."
                ))
            })?;
            if release.v != GATE_SPEC_VERSION
                || release.nonce != nonce
                || release.session_id != session_id
            {
                return Err(EnvError::Runtime(
                    "the internal gate refused a release for a different version, nonce, or session.\n\
                     The adapter was not released."
                        .to_string(),
                ));
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(EnvError::Runtime(format!(
                "the internal gate received no exact-session parent release within {} seconds.\n\
                 A timeout never releases adapter code; the registration will be ended.",
                GATE_WAIT.as_secs()
            )));
        }
        std::thread::sleep(GATE_POLL_INTERVAL);
    }
}

/// Fixed trusted program executed inside the transient scope.  No adapter
/// instruction can execute until every statement below has succeeded.
pub fn run_agent_gate(path: &Path, session_id: &str, nonce: &str) -> Result<u8, EnvError> {
    if !punar_common::agent::session_id_ok(session_id)
        || nonce.len() != 32
        || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(EnvError::Runtime(
            "the internal agent gate refused an invalid session identity or nonce.\n\
             The adapter was not released."
                .to_string(),
        ));
    }
    require_gate_process(session_id)?;
    let mut spec = read_gate_spec(path, session_id, nonce)?;
    // Re-evaluate the project hierarchy from inside the trusted in-scope gate;
    // no adapter code has run, and a changed/symlinked/broadened path fails.
    isolation::validate_project_mount(&spec.project_path, &spec.home_path)?;
    let pid = std::process::id();
    spec.registration.process_id = pid;

    let agentd = agentd::Client::discover();
    let registration = match agentd.register(spec.registration.clone()) {
        Ok(result) if result.classification == AgentClassification::Managed => result,
        Ok(result) => {
            return Err(EnvError::Runtime(format!(
                "the AI agent registry classified the held launch as {}, not managed.\n\
                 The adapter was not released and its scope will be stopped.",
                result.classification.as_str()
            )));
        }
        Err(AgentdError::Server { code, message }) => {
            return Err(EnvError::Runtime(format!(
                "the AI agent registry refused the pre-exec gate ({code}).\n{message}"
            )));
        }
        Err(other) => return Err(EnvError::Runtime(other.message())),
    };

    let network = match netd::Client::discover().session_ready(session_id) {
        Ok(result)
            if result.session_id == session_id
                && result.project == spec.registration.project
                && result.state == NetworkSessionReadyState::Ready
                && result.enforcement == NetworkSessionEnforcement::NftablesCgroupV2 =>
        {
            result
        }
        Ok(result) => {
            let _ = agentd.end(session_id);
            return Err(EnvError::Runtime(format!(
                "punar-netd returned a readiness proof for session {} / project {} with state {:?} and enforcement {:?}, not this exact managed launch.\n\
                 The adapter was not released and its scope will be stopped.",
                result.session_id, result.project, result.state, result.enforcement
            )));
        }
        Err(error) => {
            let _ = agentd.end(session_id);
            return Err(EnvError::Runtime(match error {
                netd::NetdError::Server { code, message } => format!(
                    "punar-netd refused the exact-session pre-exec barrier ({code}).\n{message}"
                ),
                other => other.message(),
            }));
        }
    };

    let ready_path = exact_gate_path(session_id, "gate.ready.json");
    let ready = AgentGateReady {
        v: GATE_SPEC_VERSION,
        nonce: nonce.to_string(),
        session_id: session_id.to_string(),
        process_id: pid,
        classification: registration.classification,
        project: network.project,
        network_state: network.state,
        network_enforcement: network.enforcement,
    };
    if let Err(error) = write_private_json(&ready_path, &ready) {
        let _ = agentd.end(session_id);
        return Err(error);
    }

    if let Err(error) = wait_for_gate_release(session_id, nonce) {
        let _ = fs::remove_file(&ready_path);
        let _ = agentd.end(session_id);
        return Err(error);
    }

    // Last possible check before exec.  A hostile same-UID host peer remains
    // outside this slice's threat boundary (ADR-004), but neither adapter nor
    // a less-privileged process gets a validation-to-mount window.
    if let Err(error) = isolation::validate_project_mount(&spec.project_path, &spec.home_path) {
        let _ = fs::remove_file(&ready_path);
        let _ = agentd.end(session_id);
        return Err(error);
    }

    // Bubblewrap is the sole executable target and receives a completely
    // empty inherited environment. This prevents LD_PRELOAD/loader variables
    // from running user code before Bubblewrap applies `--clearenv` itself.
    let error = Command::new(BWRAP_PATH)
        .args(&spec.sandbox_argv[1..])
        .env_clear()
        .exec();
    let _ = fs::remove_file(&ready_path);
    let _ = agentd.end(session_id);
    Err(EnvError::Runtime(format!(
        "the fixed Bubblewrap boundary could not execute after the exact-session gate succeeded: {error}.\n\
         No unsandboxed adapter was launched. Next step: repair the Punar bubblewrap package."
    )))
}

fn wait_for_gate_ready(
    path: &Path,
    nonce: &str,
    session: &Session,
    child: &mut Child,
) -> Result<AgentClassification, EnvError> {
    let deadline = Instant::now() + GATE_WAIT;
    loop {
        if path.exists() {
            validate_gate_file(path, &session.session_id, "gate.ready.json")?;
            let bytes = fs::read(path).map_err(|error| {
                EnvError::Runtime(format!(
                    "the managed-agent gate proof could not be read: {error}.\n\
                     The scope will be stopped; no readiness is inferred."
                ))
            })?;
            let proof: AgentGateReady = serde_json::from_slice(&bytes).map_err(|error| {
                EnvError::Runtime(format!(
                    "the managed-agent gate proof was malformed: {error}.\n\
                     The scope will be stopped; no readiness is inferred."
                ))
            })?;
            let gate_cgroup = fs::read_to_string(format!("/proc/{}/cgroup", proof.process_id))
                .unwrap_or_default();
            let gate_executable = fs::read_link(format!("/proc/{}/exe", proof.process_id)).ok();
            if proof.v == GATE_SPEC_VERSION
                && proof.nonce == nonce
                && proof.session_id == session.session_id
                && proof.process_id != 0
                && proof.classification == AgentClassification::Managed
                && proof.project == session.project
                && proof.network_state == NetworkSessionReadyState::Ready
                && proof.network_enforcement == NetworkSessionEnforcement::NftablesCgroupV2
                && cgroup_has_scope(&gate_cgroup, &session.scope_unit)
                && gate_executable.as_deref() == Some(Path::new(PUNAR_ENV_PATH))
            {
                return Ok(AgentClassification::Managed);
            }
            return Err(EnvError::Runtime(
                "the managed-agent gate proof did not match this exact session, project, classification, and kernel enforcement.\n\
                 The scope will be stopped; no count, status, or timeout is accepted as readiness."
                    .to_string(),
            ));
        }
        if let Some(status) = child.try_wait().unwrap_or(None) {
            return Err(EnvError::Runtime(format!(
                "the trusted managed-agent gate exited ({}) before proving exact-session network enforcement.\n\
                 The adapter was never released. Next step: inspect `systemctl --user status {}` and the punar-agentd/punar-netd journals.",
                outcome_of(&status).describe(),
                session.scope_unit
            )));
        }
        if Instant::now() >= deadline {
            return Err(EnvError::Runtime(format!(
                "the trusted managed-agent gate did not produce an exact-session proof within {} seconds.\n\
                 A timeout never releases adapter code; the scope will be stopped.\n\
                 Next step: inspect punar-agentd and punar-netd readiness.",
                GATE_WAIT.as_secs()
            )));
        }
        std::thread::sleep(GATE_POLL_INTERVAL);
    }
}

fn release_gate(
    isolation: &SessionIsolation,
    session_id: &str,
    nonce: &str,
) -> Result<(), EnvError> {
    write_private_json(
        &isolation.gate_release_path(),
        &AgentGateRelease {
            v: GATE_SPEC_VERSION,
            nonce: nonce.to_string(),
            session_id: session_id.to_string(),
        },
    )
}

/// `punar-env agent <name>`: resolve, launch, register, wait, deregister.
/// Returns the agent's exit code, passed through verbatim.
pub fn op_agent(dir: &Path, m: &Manifest, name: &str, json: bool) -> Result<u8, EnvError> {
    // 1. Resolve the agent against the manifest, then against the
    //    installed adapters.
    require_declared(m, name)?;
    let adapters_dir = adapter::adapters_dir();
    let found = adapter::find(&adapters_dir, name)?;
    let definition_source = found.source.display().to_string();
    let definition = found.definition;

    // 2. Session identity.
    let session_id = mint_session_id()?;

    // 3. Authority — display-level, from the manifest and the named
    //    policy source.
    let citation = authority::citation();
    let authority = authority::summary(m, &citation);

    // 4./9. The command: the adapter's argv, or the mock stand-in. A real
    // third-party version command is deliberately not executed here: doing
    // that before the managed scope and sandbox would be an unconfined agent
    // launch. Version remains honestly unknown until package provenance can
    // supply it without executing third-party code.
    let launched = definition.launch_argv(adapter::mock_requested());
    require_agent_runtime_supported(&definition.name, launched.mock)?;
    let version = reported_version(launched.mock);

    // Prepare the kernel boundary before printing a launch block. Missing or
    // damaged bubblewrap, an unsafe runtime directory, or an unresolved agent
    // is a hard error; there is no host-filesystem fallback.
    isolation::require_launch_tools()?;
    let isolation = SessionIsolation::prepare(&session_id)?;
    isolation::validate_project_mount(dir, isolation.home_destination())?;
    // punar-netd locates this session's policy at ~/<project.name>. A launch
    // from any other directory would be enforced against deny_all with only
    // a daemon-side warning while the launch block claims an exact rule, so
    // the mismatch is refused here, before any scope exists.
    isolation::require_netd_locatable_project(dir, isolation.home_destination(), &m.project.name)?;
    let resolved_command = isolation::resolve_command(&launched.argv)?;
    let grade = project_grade(m);
    let sandbox_argv = isolation.command_argv(dir, grade, &resolved_command, launched.mock);

    let session = Session {
        session_id: session_id.clone(),
        agent: definition.name.clone(),
        adapter: definition.adapter.clone(),
        version,
        project: m.project.name.clone(),
        // Managed host launch never probes PATH-resolved Podman before the
        // boundary. Container state is unrelated to this agent lifecycle.
        environment: ENVIRONMENT_HOST.to_string(),
        scope_unit: scope_unit(&session_id),
        definition_source,
        workdir: dir.display().to_string(),
        grade,
        mock: launched.mock,
        authority,
        citation,
    };

    let nonce = mint_gate_nonce()?;
    let gate_spec = prepare_gate_spec(&isolation, &session, dir, &sandbox_argv, &nonce)?;

    // Create the scope with the fixed Punar gate as its only initial command.
    // Adapter argv exists only in the private handoff; it never reaches
    // systemd-run or any shell.
    let argv = systemd_run_argv(
        &session.session_id,
        &session.agent,
        &session.project,
        &gate_spec,
        &nonce,
    );
    let mut child = Command::new(SYSTEMD_RUN_PATH)
        .args(&argv[1..])
        .current_dir("/")
        .env_clear()
        .env(
            "XDG_RUNTIME_DIR",
            format!("/run/user/{}", rustix::process::getuid().as_raw()),
        )
        .spawn()
        .map_err(|e| spawn_error(&e, &argv[0]))?;

    // The gate registers its own in-scope PID, asks netd for exact kernel
    // readback, and only then execs Bubblewrap. The parent accepts solely the
    // private exact-session proof; no status/count/polling shortcut releases
    // adapter code.
    let client = agentd::Client::discover();
    let classification = match wait_for_gate_ready(
        &isolation.gate_ready_path(),
        &nonce,
        &session,
        &mut child,
    ) {
        Ok(classification) => classification,
        Err(error) => {
            let stopped = abort_scope(&mut child, &client, &session);
            if let Err(cleanup) = isolation.cleanup() {
                return Err(EnvError::Runtime(format!("{error}\n{cleanup}")));
            }
            if !stopped {
                return Err(EnvError::Runtime(format!(
                    "{error}\nThe fixed systemctl teardown of {} also failed; the direct lifecycle process was terminated and reaped, but the user manager must be inspected before retrying.",
                    session.scope_unit
                )));
            }
            return Err(error);
        }
    };

    // This exact, nonce-bound file is the gate's only release condition. A
    // write failure follows the same stop/reap/end path; timeout or generic
    // daemon status can never substitute for it.
    if let Err(error) = release_gate(&isolation, &session.session_id, &nonce) {
        let stopped = abort_scope(&mut child, &client, &session);
        let cleanup = isolation.cleanup();
        if !stopped {
            return Err(EnvError::Runtime(format!(
                "{error}\nThe exact scope teardown also failed; inspect {} before retrying.",
                session.scope_unit
            )));
        }
        cleanup?;
        return Err(error);
    }

    if json {
        println!("{}", render_launch_json(&session, classification));
    } else {
        print!("{}", render_launch(&session));
        print!("{}", render_registered(classification, &session.session_id));
    }

    // While the agent runs, a SIGTERM/SIGINT for punar-env is forwarded to
    // the session so the scope ends with it (and `agents.end` still runs).
    forward_signals_to(child.id());

    let status = child.wait().map_err(|e| {
        EnvError::Runtime(format!(
            "the agent session could not be waited on: {e}.\n\
             Next step: check the session's scope with \
             `systemctl --user status {}`.",
            session.scope_unit
        ))
    })?;
    let outcome = outcome_of(&status);

    // Deregister. A failure here is reported, never hidden: the session
    // has really ended, and the next scan reaps it (milestone-7.md 5.2).
    if let Err(error) = client.end(&session.session_id) {
        eprintln!(
            "warning: the agent session {} could not be marked ended in the registry.\n{}",
            session.session_id,
            error.message()
        );
    }
    if !json {
        print!("{}", render_ended(&session.session_id, &outcome));
    }
    isolation.cleanup()?;
    Ok(outcome.exit_code())
}

fn abort_scope(child: &mut Child, client: &agentd::Client, session: &Session) -> bool {
    let stop = Command::new(SYSTEMCTL_PATH)
        .args(&stop_scope_argv(&session.scope_unit)[1..])
        .env_clear()
        .env(
            "XDG_RUNTIME_DIR",
            format!("/run/user/{}", rustix::process::getuid().as_raw()),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    kill_child(child);
    let _ = child.wait();
    let _ = client.end(&session.session_id);
    stop.is_ok_and(|status| status.success())
}

/// A mock has a fixed, explicit label. A real third-party agent stays
/// `unknown`: executing an adapter's version command before the scope exists
/// would run third-party code outside the very boundary this command promises.
fn reported_version(mock: bool) -> String {
    if mock {
        VERSION_MOCK.to_string()
    } else {
        VERSION_UNKNOWN.to_string()
    }
}

fn outcome_of(status: &std::process::ExitStatus) -> Outcome {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => Outcome::Exited(code.clamp(0, 255) as u8),
        (None, Some(signal)) => Outcome::Signaled(signal),
        (None, None) => Outcome::Exited(1),
    }
}

fn kill_child(child: &mut Child) {
    if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
    }
}

/// Forward SIGTERM/SIGINT to the agent session. A signalled `punar-env`
/// must not orphan a running agent: the agent is asked to stop, `wait`
/// returns, and the normal `agents.end` path runs.
fn forward_signals_to(pid: u32) {
    let signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
    ]);
    let Ok(mut signals) = signals else {
        eprintln!(
            "warning: punar-env could not install signal handlers; stopping punar-env \
             will leave the agent session running in its scope until it is stopped."
        );
        return;
    };
    std::thread::spawn(move || {
        for _signal in signals.forever() {
            if let Some(pid) = rustix::process::Pid::from_raw(pid as i32) {
                let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
            }
        }
    });
}

fn spawn_error(error: &std::io::Error, program: &std::ffi::OsStr) -> EnvError {
    let program = program.to_string_lossy();
    if error.kind() == std::io::ErrorKind::NotFound {
        return EnvError::Runtime(format!(
            "the fixed executable '{program}' is unavailable.\n\
             A managed agent session runs in a transient systemd scope, which is what \
             makes its activity attributable (SPEC section 22); there is no unattributed \
             fallback.\n\
             Next step: repair the signed Punar image package that owns this absolute path, \
             and confirm that the user systemd manager is running."
        ));
    }
    EnvError::Runtime(format!(
        "the agent session could not be started: {error}.\n\
         Next step: check that a user systemd manager is running \
         (`systemctl --user status`) and rerun."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest;

    const ATLAS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/projects/atlas/project-environment.yaml"
    ));

    fn atlas() -> Manifest {
        manifest::parse_str(ATLAS).unwrap().manifest
    }

    fn session() -> Session {
        let citation = Citation::personal();
        let m = atlas();
        Session {
            session_id: "agt_4f21c09ab3e1".to_string(),
            agent: "claude-code".to_string(),
            adapter: "claude_code".to_string(),
            version: "mock".to_string(),
            project: "atlas".to_string(),
            environment: "host".to_string(),
            scope_unit: scope_unit("agt_4f21c09ab3e1"),
            definition_source: "/usr/share/punar/agents/adapters/claude-code.json".to_string(),
            workdir: "/home/punar/atlas".to_string(),
            grade: project_grade(&m),
            mock: true,
            authority: authority::summary(&m, &citation),
            citation,
        }
    }

    #[test]
    fn declared_membership_is_the_first_gate() {
        assert!(require_declared(&atlas(), "claude-code").is_ok());
        let err = require_declared(&atlas(), "rogue-agent").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not declared"), "{msg}");
        assert!(msg.contains("claude-code · codex"), "{msg}");
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn session_ids_match_the_registry_pattern() {
        let id = mint_session_id().expect("/dev/urandom is readable");
        assert!(punar_common::agent::session_id_ok(&id), "{id}");
        assert_eq!(id.len(), "agt_".len() + 12);
        assert!(id[4..].chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(id, mint_session_id().unwrap(), "ids are not a counter");
    }

    /// Systemd receives only the fixed trusted gate and its private handoff
    /// identity. Adapter argv never reaches this pre-confinement parser.
    #[test]
    fn systemd_run_argv_is_fixed_and_never_a_shell_string() {
        let spec = Path::new("/run/user/1000/punar-agent-sessions/agt_4f21c09ab3e1/gate.json");
        let argv = systemd_run_argv(
            "agt_4f21c09ab3e1",
            "claude-code",
            "atlas",
            spec,
            "00112233445566778899aabbccddeeff",
        );
        assert_eq!(
            argv,
            vec![
                std::ffi::OsString::from(SYSTEMD_RUN_PATH),
                std::ffi::OsString::from("--user"),
                std::ffi::OsString::from("--scope"),
                std::ffi::OsString::from("--quiet"),
                std::ffi::OsString::from("--collect"),
                std::ffi::OsString::from("--unit=punar-agent-agt_4f21c09ab3e1"),
                std::ffi::OsString::from(
                    "--description=Punar managed AI agent session agt_4f21c09ab3e1 \
                     (claude-code, project atlas)",
                ),
                std::ffi::OsString::from("--"),
                std::ffi::OsString::from(PUNAR_ENV_PATH),
                std::ffi::OsString::from("__agent-gate"),
                std::ffi::OsString::from("--spec"),
                spec.as_os_str().to_os_string(),
                std::ffi::OsString::from("--session-id"),
                std::ffi::OsString::from("agt_4f21c09ab3e1"),
                std::ffi::OsString::from("--nonce"),
                std::ffi::OsString::from("00112233445566778899aabbccddeeff"),
            ]
        );
        assert!(!argv.iter().any(|a| {
            matches!(
                a.to_str(),
                Some("-c" | "/bin/sh" | "/usr/bin/bwrap" | "claude")
            )
        }));
    }

    /// Even hostile adapter text cannot be represented on the systemd side
    /// of the private gate handoff.
    #[test]
    fn adapter_arguments_cannot_be_smuggled_into_the_launcher() {
        let argv = systemd_run_argv(
            "agt_000000000000",
            "generic-shell",
            "atlas",
            Path::new("/run/user/1000/punar-agent-sessions/agt_000000000000/gate.json"),
            "00112233445566778899aabbccddeeff",
        );
        let separator = argv.iter().position(|a| a == "--").expect("separator");
        assert!(
            argv[..separator]
                .iter()
                .all(|a| !a.to_string_lossy().contains("rm -rf")
                    && !a.to_string_lossy().contains("evil")),
            "{argv:?}"
        );
        assert_eq!(argv[separator + 1], PUNAR_ENV_PATH);
        assert!(!argv.iter().any(|argument| {
            argument
                .to_string_lossy()
                .contains("rm -rf / ; --unit=punar-agent-evil")
        }));
    }

    #[test]
    fn scope_units_and_cgroup_evidence_agree() {
        let unit = scope_unit("agt_4f21c09ab3e1");
        assert_eq!(unit, "punar-agent-agt_4f21c09ab3e1.scope");
        let cgroup = format!("0::/user.slice/user-1000.slice/user@1000.service/app.slice/{unit}\n");
        assert!(cgroup_has_scope(&cgroup, &unit));
        assert!(!cgroup_has_scope(
            "0::/user.slice/user-1000.slice/session-1.scope\n",
            &unit
        ));
        assert!(!cgroup_has_scope("", &unit));
        assert!(!cgroup_has_scope(
            &format!("0::/app.slice/{unit}-evil\n"),
            &unit
        ));
    }

    #[test]
    fn stop_argv_targets_only_this_session_scope() {
        assert_eq!(
            stop_scope_argv("punar-agent-agt_1.scope"),
            vec![SYSTEMCTL_PATH, "--user", "stop", "punar-agent-agt_1.scope"]
        );
    }

    #[test]
    fn gate_spec_accepts_only_fixed_bwrap_and_excludes_control_and_broker_sockets() {
        let nonce = "00112233445566778899aabbccddeeff";
        let mut spec = AgentGateSpec {
            v: GATE_SPEC_VERSION,
            nonce: nonce.to_string(),
            registration: session().register_params(0),
            project_path: PathBuf::from("/home/punar/atlas"),
            home_path: PathBuf::from("/home/punar"),
            sandbox_argv: vec![
                BWRAP_PATH.to_string(),
                "--clearenv".to_string(),
                "--".to_string(),
                "/usr/bin/true".to_string(),
            ],
        };
        validate_gate_spec_contents(&spec, "agt_4f21c09ab3e1", nonce).unwrap();

        spec.sandbox_argv[0] = "/tmp/bwrap".to_string();
        assert!(validate_gate_spec_contents(&spec, "agt_4f21c09ab3e1", nonce).is_err());
        spec.sandbox_argv[0] = BWRAP_PATH.to_string();
        for forbidden in [
            "/run/punar-agentd/agentd.sock",
            "/run/punar-netd/netd.sock",
            "/run/punard/punard.sock",
            "/run/punar-secrets/secrets.sock",
        ] {
            spec.sandbox_argv.insert(2, forbidden.to_string());
            assert!(
                validate_gate_spec_contents(&spec, "agt_4f21c09ab3e1", nonce).is_err(),
                "gate accepted forbidden socket {forbidden}"
            );
            spec.sandbox_argv.remove(2);
        }
        assert!(
            validate_gate_spec_contents(
                &spec,
                "agt_4f21c09ab3e1",
                "ffffffffffffffffffffffffffffffff"
            )
            .is_err()
        );
    }

    /// The launch block, snapshot-exact: the MOCK label, the attribution
    /// lines, the authority register with its policy citation, and the
    /// enforcement milestone on every single row.
    #[test]
    fn launch_block_matches_the_target_render() {
        let out = render_launch(&session());
        let expected = format!(
            "PUNAR-ENV · AGENT SESSION · AGT_4F21C09AB3E1\n\
             {}\n\
             MOCK AGENT · dev/CI stand-in — not a real AI agent\n\
             Agent         claude-code · mock · adapter claude_code\n\
             Session       agt_4f21c09ab3e1\n\
             Scope         punar-agent-agt_4f21c09ab3e1.scope · attribution via cgroup\n\
             Project       atlas · environment host\n\
             Workspace     /home/punar/atlas → /workspace · read_write · enforced by mount namespace\n\
             Isolation     mount + PID + IPC + UTS · private home/tmp/runtime\n\
             \n\
             AUTHORITY · WHAT IT MAY ACCESS · POLICY · PERSONAL DEFAULTS\n\
             \x20 filesystem  project      read_write   enforced (mount namespace)\n\
             \x20 network     internet     allow        enforced (agent scope)\n\
             \x20 network     corp_dev     allow        enforced (agent scope)\n\
             \x20 network     corp_prod    deny         enforced (agent scope)\n\
             \x20 credentials github       allow        declared · M9\n\
             \x20 credentials aws_dev      request      declared · M9\n\
             \x20 credentials aws_prod     deny         declared · M9\n\
             \n\
             NETWORK · ENFORCED · exact nftables cgroup-v2 session rule verified · container: deny only\n\
             CREDENTIALS · DECLARED · M9 secret broker · nothing is brokered in M7\n\
             TOOLS · M11+ · no tool gateway mediates this session yet\n",
            "─".repeat(RULE_WIDTH)
        );
        assert_eq!(out, expected);
    }

    /// The mock label appears only over a mock session — never over a real
    /// agent (SPEC 1.22).
    #[test]
    fn the_mock_label_is_printed_only_for_mock_sessions() {
        let mut real = session();
        real.mock = false;
        real.version = "1.4.2".to_string();
        let out = render_launch(&real);
        assert!(!out.contains("MOCK"), "{out}");
        assert!(out.contains("claude-code · 1.4.2 · adapter claude_code"));
        assert!(render_launch(&session()).contains(MOCK_LABEL));
    }

    /// Unmanaged-first: an unenrolled launch names no organization
    /// anywhere, and cites personal defaults.
    #[test]
    fn a_personal_launch_shows_no_org_chrome() {
        let out = render_launch(&session()).to_lowercase();
        assert!(!out.contains("organization"));
        assert!(!out.contains("acme"));
        assert!(out.contains("policy · personal defaults"));
    }

    #[test]
    fn an_enrolled_launch_cites_the_org_policy() {
        let mut s = session();
        s.citation = Citation {
            id: "eng-ai-v3".to_string(),
            org_name: Some("Acme Engineering".to_string()),
        };
        s.authority.policy_citation = "eng-ai-v3".to_string();
        let out = render_launch(&s);
        assert!(out.contains("POLICY · ENG-AI-V3"), "{out}");
    }

    #[test]
    fn the_registry_and_epilogue_lines_state_what_happened() {
        assert_eq!(
            render_registered(AgentClassification::Managed, "agt_4f21c09ab3e1"),
            "REGISTRY · MANAGED · AGT_4F21C09AB3E1 · registered with punar-agentd · exact network rule verified\n"
        );
        // The honest downgrade the daemon may compute is printed, and
        // explained — a session that is not managed never looks managed.
        let downgraded = render_registered(AgentClassification::Observed, "agt_1");
        assert!(
            downgraded.starts_with("REGISTRY · OBSERVED · AGT_1 ·"),
            "{downgraded}"
        );
        assert!(
            downgraded.contains("could not confirm the managed scope"),
            "{downgraded}"
        );
        assert_eq!(
            render_ended("agt_4f21c09ab3e1", &Outcome::Exited(0)),
            "SESSION ENDED · AGT_4F21C09AB3E1 · exit 0\n"
        );
        assert_eq!(
            render_ended("agt_1", &Outcome::Signaled(15)),
            "SESSION ENDED · AGT_1 · terminated by signal 15\n"
        );
    }

    #[test]
    fn exit_codes_pass_the_agents_own_result_through() {
        assert_eq!(Outcome::Exited(42).exit_code(), 42);
        assert_eq!(Outcome::Exited(0).exit_code(), 0);
        assert_eq!(Outcome::Signaled(15).exit_code(), 143);
    }

    #[test]
    fn json_carries_the_same_facts_including_the_labels() {
        let v = render_launch_json(&session(), AgentClassification::Managed);
        assert_eq!(v["v"], 1);
        assert_eq!(v["command"], "agent");
        assert_eq!(v["session_id"], "agt_4f21c09ab3e1");
        assert_eq!(v["agent"], "claude-code");
        assert_eq!(v["adapter"], "claude_code");
        assert_eq!(v["version"], "mock");
        assert_eq!(v["mock"], true);
        assert_eq!(v["project"], "atlas");
        assert_eq!(v["environment"], "host");
        assert_eq!(v["scope_unit"], "punar-agent-agt_4f21c09ab3e1.scope");
        assert_eq!(
            v["adapter_definition"],
            "/usr/share/punar/agents/adapters/claude-code.json"
        );
        assert_eq!(v["classification"], "managed");
        assert_eq!(v["workspace"]["dst"], "/workspace");
        assert_eq!(v["workspace"]["enforcement"], "mount_namespace");
        assert_eq!(v["authority"]["policy_citation"], "personal-defaults");
        assert_eq!(v["authority"]["rows"][0]["zone"], "filesystem.project");
        assert_eq!(
            v["authority"]["rows"][0]["enforcement"],
            "enforced (mount namespace)"
        );
        assert_eq!(
            v["authority"]["rows"][1]["enforcement"],
            "enforced (agent scope)"
        );
        assert_eq!(v["enforcement"]["ledger"], "M8");
        assert_eq!(
            v["enforcement"]["network"],
            "exact_session_nftables_cgroup_v2"
        );
        // No row may be published without its enforcement label.
        for row in v["authority"]["rows"].as_array().unwrap() {
            assert!(!row["enforcement"].as_str().unwrap().is_empty(), "{row}");
        }
    }

    #[test]
    fn real_agent_version_is_never_probed_before_isolation() {
        assert_eq!(reported_version(false), "unknown");
        assert_eq!(reported_version(true), "mock");
    }

    #[test]
    fn real_claude_is_explicitly_blocked_until_package_and_state_are_audited() {
        let error = require_agent_runtime_supported("claude-code", false).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("package/runtime closure"), "{message}");
        assert!(
            message.contains("persistent authentication state"),
            "{message}"
        );
        assert!(message.contains("Nothing was launched"), "{message}");
        assert!(require_agent_runtime_supported("claude-code", true).is_ok());
        assert!(require_agent_runtime_supported("generic-shell", false).is_ok());
    }
}
