//! `punar-env` — the developer environment manager (SPEC sections 11.6,
//! 16, 17; Milestone 6, docs/development/milestone-6.md).
//!
//! A project directory with a ProjectEnvironment manifest becomes a
//! rootless Podman container: the project bind-mounted at `/workspace`
//! per the declared filesystem grade, `--network none` always in M6.
//! Everything else the manifest *declares* — toolchains, services,
//! network zones, credential grants, AI agents — is parsed, validated,
//! and displayed with its enforcement milestone, never silently faked
//! (SPEC 1.22).
//!
//! No daemon, no root, no punard IPC in M6: `punar-env` runs as the
//! invoking user (uid 0 is refused), holds no state of its own, and
//! drives the podman CLI with fixed argv — never a host shell string.
//!
//! Milestone 7 makes `agent` real: `punar-env agent <name>` resolves the
//! declared agent against a staged gateway adapter (SPEC section 26),
//! mints the `agt_` session identity, launches the agent in a transient
//! systemd scope named after it (SPEC section 22 attribution), registers
//! the session with `punar-agentd`, and deregisters when it ends
//! (docs/development/milestone-7.md section 5). Managed host agents also run
//! inside a bubblewrap mount/PID/IPC/UTS boundary: the declared project grade
//! is enforced, while network and credential rows retain their own explicit
//! enforcement state (SPEC 1.22).
//!
//! Exit codes (Plate D-014): 0 success · 1 runtime/podman/registry error ·
//! 2 usage (clap). `shell` and `agent` pass their child's exit code
//! through verbatim.

#![forbid(unsafe_code)]

mod adapter;
mod agentd;
mod authority;
mod engine;
mod isolation;
mod manifest;
mod netd;
mod podman;
mod render;
mod session;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::engine::{CmdOutput, EnvError, container_state_of};
use crate::podman::{CliPodman, container_name};
use crate::render::{StatusData, Style};

#[derive(Parser)]
#[command(
    name = "punar-env",
    version,
    about = "Developer environment manager (SPEC section 17) — project manifests to rootless \
             Podman containers"
)]
struct Cli {
    /// Print a machine-readable JSON object instead of the human view.
    #[arg(long, global = true)]
    json: bool,

    /// Project directory (default: the current directory).
    #[arg(short = 'C', long = "dir", global = true, value_name = "PATH")]
    dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Internal pre-exec barrier used only as the fixed command inside a
    /// managed systemd scope. It never accepts an executable or shell text.
    #[command(name = "__agent-gate", hide = true)]
    AgentGate {
        #[arg(long, value_name = "PATH")]
        spec: PathBuf,
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        nonce: String,
    },
    /// Scaffold a punar-env.yaml manifest; idempotent — never rewrites.
    Init {
        /// Project name (default: the directory name, lowercased).
        #[arg(long)]
        name: Option<String>,
    },
    /// Create and start the project environment container.
    Up,
    /// Open a shell inside the environment, or run one command with -c
    /// (its exit code is passed through verbatim).
    Shell {
        /// Command for the container's /bin/sh (the container's own shell
        /// interprets it; the host never does).
        #[arg(short = 'c', value_name = "CMD")]
        command: Option<String>,
    },
    /// Show environment state and the declared manifest, permission
    /// grants labeled with their enforcement milestones.
    Status,
    /// Remove the environment container; project files are never touched.
    Destroy,
    /// Launch a managed AI agent session for this project: a systemd
    /// scope named for the session id, registered with the AI agent
    /// registry, deregistered when the agent exits (Milestone 7).
    Agent {
        /// Agent name; must be declared in the manifest's ai.agents list
        /// and have a staged gateway adapter.
        name: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(e.exit_code())
        }
    }
}

fn run(cli: Cli) -> Result<u8, EnvError> {
    refuse_root()?;

    // The trusted gate runs before project/manifest/Podman setup.  Its only
    // input is the private, exact-session specification prepared by the outer
    // launcher; third-party adapter code is still unable to execute here.
    if let Command::AgentGate {
        spec,
        session_id,
        nonce,
    } = &cli.command
    {
        if cli.json || cli.dir.is_some() {
            return Err(EnvError::Usage(
                "the internal managed-agent gate does not accept --json or --dir".to_string(),
            ));
        }
        return session::run_agent_gate(spec, session_id, nonce);
    }
    let dir = project_dir(cli.dir)?;

    // init resolves (or scaffolds) the manifest itself.
    if let Command::Init { name } = &cli.command {
        let out = engine::op_init(&dir, name.as_deref())?;
        return Ok(emit(&out, cli.json));
    }

    let loaded = engine::load_manifest(&dir)?;
    for warning in &loaded.warnings {
        eprintln!("warning: {}: {warning}", loaded.file.display());
    }
    let m = loaded.manifest;
    let podman = CliPodman;

    match cli.command {
        Command::AgentGate { .. } => unreachable!("handled before project resolution"),
        Command::Init { .. } => unreachable!("handled above"),
        Command::Up => {
            let out = engine::op_up(&podman, &dir, &m)?;
            Ok(emit(&out, cli.json))
        }
        Command::Shell { command } => {
            if cli.json {
                return Err(EnvError::Usage(
                    "shell is an interactive session; --json applies to init, up, status, \
                     destroy and agent.\n\
                     Next step: drop --json, or use `punar-env status --json` for machine \
                     output."
                        .to_string(),
                ));
            }
            engine::op_shell(&podman, &m, command.as_deref())
        }
        Command::Status => {
            let container = container_name(&m.project.name);
            let state = container_state_of(&podman, &container)?;
            let data = StatusData {
                container,
                state,
                src: dir.display().to_string(),
                manifest: m,
            };
            if cli.json {
                println!("{}", render::render_json(&data));
            } else {
                print!("{}", render::render_human(&data, &Style::detect()));
            }
            Ok(0)
        }
        Command::Destroy => {
            let out = engine::op_destroy(&podman, &m)?;
            Ok(emit(&out, cli.json))
        }
        Command::Agent { name } => {
            // The managed launch path (M7): the agent's own exit code is
            // passed through verbatim, exactly like `shell`.
            session::op_agent(&dir, &m, &name, cli.json)
        }
    }
}

fn emit(out: &CmdOutput, json: bool) -> u8 {
    for warning in &out.warnings {
        eprintln!("warning: {warning}");
    }
    if json {
        println!("{}", out.json);
    } else {
        println!("{}", out.line);
    }
    0
}

/// Rootless podman as root would create root-owned container state and
/// defeat the M1 subuid design — hard error (M6 plan section 3.1).
fn refuse_root() -> Result<(), EnvError> {
    if rustix::process::geteuid().is_root() {
        return Err(EnvError::Runtime(
            "punar-env must run as a regular user, not root.\n\
             Developer environments are rootless podman containers owned by the invoking \
             user; running as root would create root-owned container state and defeat the \
             rootless design (subuid mapping, Milestone 1).\n\
             Next step: rerun from your own user session, without sudo."
                .to_string(),
        ));
    }
    Ok(())
}

/// Resolve and canonicalize the project directory.
fn project_dir(flag: Option<PathBuf>) -> Result<PathBuf, EnvError> {
    let dir = match flag {
        Some(dir) => dir,
        None => std::env::current_dir().map_err(|e| {
            EnvError::Runtime(format!(
                "cannot determine the current directory: {e}.\n\
                 Next step: pass the project directory explicitly with -C <path>."
            ))
        })?,
    };
    dir.canonicalize().map_err(|e| {
        EnvError::Usage(format!(
            "'{}' is not a usable project directory: {e}.\n\
             Next step: pass an existing directory with -C <path>.",
            dir.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole SPEC section 17 command surface parses (and only it).
    #[test]
    fn command_surface_parses() {
        let examples: &[&[&str]] = &[
            &["punar-env", "init"],
            &["punar-env", "init", "--name", "atlas"],
            &["punar-env", "up"],
            &["punar-env", "shell"],
            &[
                "punar-env",
                "shell",
                "-c",
                "cat /etc/punar-env-base-release",
            ],
            &["punar-env", "status"],
            &["punar-env", "status", "--json"],
            &["punar-env", "--json", "status"],
            &["punar-env", "destroy"],
            &["punar-env", "agent", "claude-code"],
            &[
                "punar-env",
                "__agent-gate",
                "--spec",
                "/run/user/1000/punar-agent-sessions/agt_4f21c09ab3e1/gate.json",
                "--session-id",
                "agt_4f21c09ab3e1",
                "--nonce",
                "00112233445566778899aabbccddeeff",
            ],
            &["punar-env", "-C", "/home/punar/atlas", "up"],
            &["punar-env", "--dir", "/home/punar/atlas", "status"],
        ];
        for example in examples {
            assert!(
                Cli::try_parse_from(example.iter()).is_ok(),
                "failed to parse {example:?}"
            );
        }
        for bad in [
            ["punar-env", "provision"].as_slice(),
            ["punar-env", "agent"].as_slice(),
            ["punar-env", "shell", "--tty"].as_slice(),
            ["punar-env", "__agent-gate", "--spec", "/tmp/gate"].as_slice(),
            [
                "punar-env",
                "__agent-gate",
                "--spec",
                "/tmp/gate",
                "--session-id",
                "agt_4f21c09ab3e1",
                "--nonce",
                "00112233445566778899aabbccddeeff",
                "/bin/sh",
            ]
            .as_slice(),
        ] {
            assert!(Cli::try_parse_from(bad.iter()).is_err(), "{bad:?}");
        }
    }

    /// `--help` names the milestone that owns managed agent sessions
    /// (SPEC 1.22 — the surface always says where it stands).
    #[test]
    fn help_names_the_milestone_that_owns_agent_sessions() {
        use clap::CommandFactory;
        let mut cmd = Cli::command();
        let help = cmd.render_long_help().to_string();
        assert!(help.contains("Milestone 7"), "{help}");
        assert!(help.contains("registry"), "{help}");
    }

    #[test]
    fn usage_errors_exit_2_and_runtime_errors_exit_1() {
        assert_eq!(EnvError::Usage(String::new()).exit_code(), 2);
        assert_eq!(EnvError::Runtime(String::new()).exit_code(), 1);
    }
}
