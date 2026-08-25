//! `punar-env agent <name>` — the managed AI agent session (SPEC section
//! 27's launch flow; docs/development/milestone-7.md section 5).
//!
//! What "managed" means here is exactly what can be proven: the agent runs
//! in a transient systemd **scope** named after its session id, so the
//! kernel's own cgroup line attributes every process in that session
//! (SPEC section 22), and `punar-agentd` reads that cgroup before it
//! grants the `managed` classification. `punar-env` never *claims*
//! managed — it launches into the scope, registers with the real pid, and
//! reports whatever classification the daemon computed.
//!
//! Fail-closed by design (milestone-7.md section 5.1): if the registry is
//! unreachable or refuses the registration, the scope is stopped and the
//! launch fails. An unregistered "managed" session is a contradiction this
//! command refuses to create.
//!
//! Honest about the rest of the ten steps: workspace access is the project
//! directory the session runs in; network context, the secret broker and
//! the tool gateway are **not** configured in M7 and are printed as
//! labeled lines (SPEC 1.22), and every authority row wears its
//! enforcement milestone. Launching the agent *inside* the M6 podman
//! container is deferred (milestone-7.md section 5.6): the agent runs on
//! the host in the project directory, and the environment row names the
//! container only when it is actually running.

use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use punar_common::agent::{
    AgentClassification, AgentsRegisterParams, AuthorityRow, AuthoritySummary,
};
use serde_json::{Value, json};

use crate::adapter::{self, MOCK_LABEL};
use crate::agentd::{self, AgentdError};
use crate::authority::{self, Citation};
use crate::engine::{ContainerState, EnvError, observe, project_grade};
use crate::manifest::{FilesystemAccess, Manifest};
use crate::podman::{Podman, container_name};
use crate::render::RULE_WIDTH;

/// Sentinel environment for a session that runs on the host (the M7 case;
/// milestone-7.md section 5.6).
const ENVIRONMENT_HOST: &str = "host";

/// Version reported for a mock session — never a version string that could
/// be mistaken for a real agent build.
const VERSION_MOCK: &str = "mock";

/// Version reported when the adapter has no probe, or the probe failed.
const VERSION_UNKNOWN: &str = "unknown";

/// How long to wait for systemd to place the agent in its scope before
/// giving up. A bounded readiness wait on a one-shot launch — not a
/// background polling loop (SPEC section 6.3).
const SCOPE_WAIT: Duration = Duration::from_secs(5);
const SCOPE_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// The transient scope unit for a session: the SPEC section 22
/// attribution chain, spelled once.
pub fn scope_unit(session_id: &str) -> String {
    format!("punar-agent-{session_id}.scope")
}

/// The `systemd-run` argv for a managed session. **Fixed argv** (M6
/// section 3.2): one string per argument, no host shell anywhere, and the
/// agent's own argv is appended after `--` so nothing in it can be read as
/// an option to systemd-run.
pub fn systemd_run_argv(
    session_id: &str,
    agent: &str,
    project: &str,
    command: &[String],
) -> Vec<String> {
    let mut argv = vec![
        "systemd-run".to_string(),
        "--user".to_string(),
        "--scope".to_string(),
        "--quiet".to_string(),
        "--collect".to_string(),
        format!("--unit=punar-agent-{session_id}"),
        format!(
            "--description=Punar managed AI agent session {session_id} \
             ({agent}, project {project})"
        ),
        "--".to_string(),
    ];
    argv.extend(command.iter().cloned());
    argv
}

/// `systemctl --user stop <scope>` — the fail-closed teardown.
fn stop_scope_argv(unit: &str) -> Vec<String> {
    vec![
        "systemctl".to_string(),
        "--user".to_string(),
        "stop".to_string(),
        unit.to_string(),
    ]
}

/// Whether a `/proc/<pid>/cgroup` body places the process in `unit` — the
/// same evidence `punar-agentd` checks before granting `managed`.
pub fn cgroup_has_scope(cgroup: &str, unit: &str) -> bool {
    cgroup.lines().any(|line| line.contains(unit))
}

/// Mint a session identity: `agt_` + 12 lowercase hex characters from the
/// OS RNG (milestone-7.md section 5.1 step 2). The launcher mints it
/// because the scope must carry the id *before* registration can verify
/// the scope; `punar-agentd` remains the authority that accepts it.
pub fn mint_session_id() -> Result<String, EnvError> {
    let mut file = std::fs::File::open("/dev/urandom").map_err(|e| {
        EnvError::Runtime(format!(
            "cannot open /dev/urandom to create the agent session identity: {e}.\n\
             Every managed session needs an unguessable id (SPEC sections 19.2, 22); \
             punar-env will not fall back to a predictable one.\n\
             Next step: check that /dev/urandom is present and readable."
        ))
    })?;
    let mut bytes = [0u8; 6];
    file.read_exact(&mut bytes).map_err(|e| {
        EnvError::Runtime(format!(
            "cannot read randomness for the agent session identity: {e}.\n\
             Next step: check that /dev/urandom is present and readable."
        ))
    })?;
    let mut id = String::from("agt_");
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(id, "{byte:02x}");
    }
    Ok(id)
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
    out.push_str(&format!("{} · {}\n", s.workdir, s.grade.as_str()));

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

    // Steps 6–8 of the SPEC section 27 flow are not configured in M7, and
    // say so rather than being quietly skipped.
    out.push_str("\nNETWORK · DECLARED · enforcement M12 · this session uses your own network\n");
    out.push_str("CREDENTIALS · DECLARED · M9 secret broker · nothing is brokered in M7\n");
    out.push_str("TOOLS · M9+ · no tool gateway mediates this session yet\n");
    out
}

/// The registry line, printed once the daemon has accepted the session and
/// reported the classification it **computed** from the scope cgroup. A
/// classification other than `managed` is the honest downgrade the daemon
/// decided on, and the line says what that means rather than burying it.
pub fn render_registered(classification: AgentClassification, session_id: &str) -> String {
    let tail = match classification {
        AgentClassification::Managed => "registered with punar-agentd".to_string(),
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
        "workspace": { "src": s.workdir, "mode": s.grade.as_str() },
        "classification": classification.as_str(),
        "authority": {
            "policy_citation": s.authority.policy_citation,
            "rows": rows,
        },
        "enforcement": {
            "authority": "display-level in M7 · credentials M9 · network M12",
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

/// `punar-env agent <name>`: resolve, launch, register, wait, deregister.
/// Returns the agent's exit code, passed through verbatim.
pub fn op_agent(
    podman: &dyn Podman,
    dir: &Path,
    m: &Manifest,
    name: &str,
    json: bool,
) -> Result<u8, EnvError> {
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

    // 4./9. The command: the adapter's argv, or the mock stand-in.
    let launched = definition.launch_argv(adapter::mock_requested());
    let version = if launched.mock {
        VERSION_MOCK.to_string()
    } else {
        probe_version(&definition)
    };

    let session = Session {
        session_id: session_id.clone(),
        agent: definition.name.clone(),
        adapter: definition.adapter.clone(),
        version,
        project: m.project.name.clone(),
        environment: environment_of(podman, m),
        scope_unit: scope_unit(&session_id),
        definition_source,
        workdir: dir.display().to_string(),
        grade: project_grade(m),
        mock: launched.mock,
        authority,
        citation,
    };

    // 10. Display the authority summary before handing over the terminal.
    if !json {
        print!("{}", render_launch(&session));
    }

    // 4./5. Create the scope and launch, working directory = the project.
    let argv = systemd_run_argv(
        &session.session_id,
        &session.agent,
        &session.project,
        &launched.argv,
    );
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(dir)
        .spawn()
        .map_err(|e| spawn_error(&e, &argv[0]))?;

    // 10a. Register with the real pid, once the scope exists.
    let client = agentd::Client::discover();
    let classification = match register_when_attributed(&client, &session, &mut child) {
        Ok(classification) => classification,
        Err(error) => {
            // Fail closed: stop the scope, reap the child, refuse to have
            // created an unregistered "managed" session.
            let _ = Command::new("systemctl")
                .args(&stop_scope_argv(&session.scope_unit)[1..])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            kill_child(&mut child);
            let _ = child.wait();
            return Err(error);
        }
    };

    if json {
        println!("{}", render_launch_json(&session, classification));
    } else {
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
    Ok(outcome.exit_code())
}

/// Wait (bounded) until the kernel places the agent process in its scope,
/// then register. Attribution is evidence, so registration never happens
/// before the evidence exists.
fn register_when_attributed(
    client: &agentd::Client,
    session: &Session,
    child: &mut Child,
) -> Result<AgentClassification, EnvError> {
    let pid = child.id();
    let deadline = Instant::now() + SCOPE_WAIT;
    loop {
        if let Some(status) = child.try_wait().unwrap_or(None) {
            return Err(EnvError::Runtime(format!(
                "the agent exited ({}) before its session could be registered.\n\
                 Nothing was recorded in the AI agent registry, because there was no \
                 session to record.\n\
                 Next step: check the agent command in the adapter definition, and run \
                 `systemctl --user status {}` for the scope's own log.",
                outcome_of(&status).describe(),
                session.scope_unit
            )));
        }
        let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
        if cgroup_has_scope(&cgroup, &session.scope_unit) {
            break;
        }
        if Instant::now() >= deadline {
            return Err(EnvError::Runtime(format!(
                "the agent process {pid} did not appear in its session scope {} within {} \
                 seconds.\n\
                 Attribution (SPEC section 22) is what makes a session managed, so \
                 punar-env will not register a session it cannot attribute.\n\
                 Next step: check the user manager with `systemctl --user status {}`.",
                session.scope_unit,
                SCOPE_WAIT.as_secs(),
                session.scope_unit
            )));
        }
        std::thread::sleep(SCOPE_POLL_INTERVAL);
    }

    match client.register(session.register_params(pid)) {
        Ok(result) => Ok(result.classification),
        Err(AgentdError::Server { code, message }) => Err(EnvError::Runtime(format!(
            "the AI agent registry refused this session ({code}).\n{message}"
        ))),
        Err(other) => Err(EnvError::Runtime(other.message())),
    }
}

/// Probe the adapter's version command; anything that is not a clean
/// answer means `"unknown"` — never a guess.
fn probe_version(definition: &adapter::AgentDefinition) -> String {
    let Some(argv) = definition.version_argv() else {
        return VERSION_UNKNOWN.to_string();
    };
    let output = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::null())
        .output();
    match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .unwrap_or(VERSION_UNKNOWN)
            .to_string(),
        _ => VERSION_UNKNOWN.to_string(),
    }
}

/// The `environment` field: the M6 container name while that container is
/// actually running, else the `host` sentinel. Podman being absent or
/// unhappy is not a launch failure — it just means `host`.
fn environment_of(podman: &dyn Podman, m: &Manifest) -> String {
    let container = container_name(&m.project.name);
    match observe(podman, &container) {
        Ok((ContainerState::Running, true)) => container,
        _ => ENVIRONMENT_HOST.to_string(),
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

fn spawn_error(error: &std::io::Error, program: &str) -> EnvError {
    if error.kind() == std::io::ErrorKind::NotFound {
        return EnvError::Runtime(format!(
            "'{program}' is not available (executable not found in PATH).\n\
             A managed agent session runs in a transient systemd scope, which is what \
             makes its activity attributable (SPEC section 22); there is no unattributed \
             fallback.\n\
             Next step: run on a Punar system with a user systemd manager."
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

    /// Fixed argv, and the agent's own argv strictly after `--`: nothing a
    /// definition contains can be read as an option to systemd-run, and no
    /// host shell is involved at any point.
    #[test]
    fn systemd_run_argv_is_fixed_and_never_a_shell_string() {
        let argv = systemd_run_argv(
            "agt_4f21c09ab3e1",
            "claude-code",
            "atlas",
            &["/usr/lib/punar/punar-mock-agent".to_string()],
        );
        assert_eq!(
            argv,
            vec![
                "systemd-run",
                "--user",
                "--scope",
                "--quiet",
                "--collect",
                "--unit=punar-agent-agt_4f21c09ab3e1",
                "--description=Punar managed AI agent session agt_4f21c09ab3e1 \
                 (claude-code, project atlas)",
                "--",
                "/usr/lib/punar/punar-mock-agent",
            ]
        );
        assert!(!argv.iter().any(|a| a == "-c" || a == "/bin/sh"));
    }

    /// A hostile-looking command from a (badly) staged adapter still rides
    /// its own argv slots after `--`; it is never concatenated, never
    /// interpreted, and cannot reach systemd-run's option parser.
    #[test]
    fn adapter_arguments_cannot_be_smuggled_into_the_launcher() {
        let argv = systemd_run_argv(
            "agt_000000000000",
            "generic-shell",
            "atlas",
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                "rm -rf / ; --unit=punar-agent-evil".to_string(),
            ],
        );
        let separator = argv.iter().position(|a| a == "--").expect("separator");
        assert!(
            argv[..separator]
                .iter()
                .all(|a| !a.contains("rm -rf") && !a.contains("evil")),
            "{argv:?}"
        );
        assert_eq!(argv[separator + 1], "/bin/sh");
        assert_eq!(argv.last().unwrap(), "rm -rf / ; --unit=punar-agent-evil");
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
    }

    #[test]
    fn stop_argv_targets_only_this_session_scope() {
        assert_eq!(
            stop_scope_argv("punar-agent-agt_1.scope"),
            vec!["systemctl", "--user", "stop", "punar-agent-agt_1.scope"]
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
             Workspace     /home/punar/atlas · read_write\n\
             \n\
             AUTHORITY · WHAT IT MAY ACCESS · POLICY · PERSONAL DEFAULTS\n\
             \x20 filesystem  project      read_write   declared · M9\n\
             \x20 network     internet     allow        declared · M12\n\
             \x20 network     corp_dev     allow        declared · M12\n\
             \x20 network     corp_prod    deny         declared · M12\n\
             \x20 credentials github       allow        declared · M9\n\
             \x20 credentials aws_dev      request      declared · M9\n\
             \x20 credentials aws_prod     deny         declared · M9\n\
             \n\
             NETWORK · DECLARED · enforcement M12 · this session uses your own network\n\
             CREDENTIALS · DECLARED · M9 secret broker · nothing is brokered in M7\n\
             TOOLS · M9+ · no tool gateway mediates this session yet\n",
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
            "REGISTRY · MANAGED · AGT_4F21C09AB3E1 · registered with punar-agentd\n"
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
        assert_eq!(v["authority"]["policy_citation"], "personal-defaults");
        assert_eq!(v["authority"]["rows"][0]["zone"], "filesystem.project");
        assert_eq!(v["authority"]["rows"][0]["enforcement"], "declared · M9");
        assert_eq!(v["enforcement"]["ledger"], "M8");
        // No row may be published without its enforcement label.
        for row in v["authority"]["rows"].as_array().unwrap() {
            assert!(
                row["enforcement"].as_str().unwrap().starts_with("declared"),
                "{row}"
            );
        }
    }

    #[test]
    fn version_is_unknown_when_the_adapter_has_no_probe() {
        let definition: adapter::AgentDefinition = serde_json::from_str(
            r#"{"name":"x","adapter":"generic","adapter_config":{"command":["/bin/true"]}}"#,
        )
        .unwrap();
        assert_eq!(probe_version(&definition), "unknown");
    }

    #[test]
    fn version_probe_failures_never_invent_a_version() {
        let definition: adapter::AgentDefinition = serde_json::from_str(
            r#"{"name":"x","adapter":"generic","adapter_config":{
                 "command":["/bin/true"],
                 "version_command":["/nonexistent/punar-version-probe"]}}"#,
        )
        .unwrap();
        assert_eq!(probe_version(&definition), "unknown");
    }
}
