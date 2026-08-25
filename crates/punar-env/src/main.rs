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
//! Exit codes (Plate D-014): 0 success · 1 runtime/podman error · 2 usage
//! (clap). `shell` passes the container command's exit code through
//! verbatim; `agent` is the labeled Milestone 7 stub and exits 1.

#![forbid(unsafe_code)]

mod engine;
mod manifest;
mod podman;
mod render;

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
    /// Launch an AI agent session in this environment (Milestone 7).
    Agent {
        /// Agent name; must be declared in the manifest's ai.agents list.
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
            // The labeled M7 stub: the ai.agents membership check is real,
            // the launch is not, and says so (SPEC 1.22). Always exits 1.
            Err(engine::op_agent(&m, &name))
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
        ] {
            assert!(Cli::try_parse_from(bad.iter()).is_err(), "{bad:?}");
        }
    }

    /// `--help` labels the agent stub with its milestone (SPEC 1.22).
    #[test]
    fn help_labels_the_agent_stub_with_milestone_7() {
        use clap::CommandFactory;
        let mut cmd = Cli::command();
        let help = cmd.render_long_help().to_string();
        assert!(help.contains("Milestone 7"), "{help}");
    }

    #[test]
    fn usage_errors_exit_2_and_runtime_errors_exit_1() {
        assert_eq!(EnvError::Usage(String::new()).exit_code(), 2);
        assert_eq!(EnvError::Runtime(String::new()).exit_code(), 1);
    }
}
