//! Rootless podman, driven through the CLI with **fixed argv** — one
//! string per argument via `std::process::Command`, never a host shell
//! string (M6 plan section 3.2). The only place a user string rides a
//! `-c` is *inside the container* (`punar-env shell -c`), where the
//! container's own `/bin/sh` interprets it — the documented meaning of
//! the flag; the host never interpolates.
//!
//! Every argv is built by a pure function here and unit-tested as an
//! exact vector; the [`Podman`] trait keeps the process boundary mockable
//! so host tests need no podman.

use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

/// The offline base image reference `up` checks, loads, and runs. The tag
/// carries the milestone; binary and archive ship in the same OS image, so
/// they cannot skew (M6 plan section 6.2).
pub const IMAGE_REF: &str = "localhost/punar-env-base:m6";
/// Where the OS image stages the deterministic OCI archive (mode 0644).
pub const ARCHIVE_PATH: &str = "/usr/share/punar/oci/punar-env-base.tar";
/// Ownership label: `status`/`destroy` refuse containers without it.
pub const MANAGED_BY_LABEL: &str = "dev.punar.managed-by";
/// Ownership label value.
pub const MANAGED_BY_VALUE: &str = "punar-env";
/// Project label.
pub const PROJECT_LABEL: &str = "dev.punar.project";
/// Sleep-forever PID 1: sessions come and go via `podman exec`, so PID 1
/// never needs to reap anything.
pub const PID1_COMMAND: &str = "exec sleep 2147483647";

/// Container name for a validated project name.
pub fn container_name(project: &str) -> String {
    format!("punar-env-{project}")
}

/// Captured result of one non-interactive podman invocation.
#[derive(Debug, Clone)]
pub struct Exec {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Exec {
    pub fn ok(&self) -> bool {
        self.code == 0
    }
}

/// The process boundary. `argv[0]` is the program (`podman`); the real
/// implementation spawns it, tests substitute a scripted mock.
pub trait Podman {
    /// Run capturing stdout/stderr (queries, create, rm, load, …).
    fn output(&self, argv: &[String]) -> io::Result<Exec>;
    /// Run with inherited stdio (interactive shell, `shell -c`) and return
    /// the child's exit code — passed through verbatim to our caller.
    fn interactive(&self, argv: &[String]) -> io::Result<i32>;
}

/// The real podman CLI.
pub struct CliPodman;

impl Podman for CliPodman {
    fn output(&self, argv: &[String]) -> io::Result<Exec> {
        let out = Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(Stdio::null())
            .output()?;
        Ok(Exec {
            code: out.status.code().unwrap_or(1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    fn interactive(&self, argv: &[String]) -> io::Result<i32> {
        let status = Command::new(&argv[0]).args(&argv[1..]).status()?;
        // A signal-killed child has no code; report the generic runtime 1.
        Ok(status.code().unwrap_or(1))
    }
}

fn argv(tokens: &[&str]) -> Vec<String> {
    tokens.iter().map(|t| (*t).to_string()).collect()
}

/// `podman image exists <ref>` — exit 0 iff present.
pub fn args_image_exists() -> Vec<String> {
    argv(&["podman", "image", "exists", IMAGE_REF])
}

/// `podman load -i <staged archive>` — first-use load of the offline base.
pub fn args_image_load() -> Vec<String> {
    argv(&["podman", "load", "-i", ARCHIVE_PATH])
}

/// Inspect one container's state and ownership label in a single
/// tab-separated line; nonzero exit means the container does not exist.
pub fn args_inspect(container: &str) -> Vec<String> {
    argv(&[
        "podman",
        "container",
        "inspect",
        container,
        "--format",
        "{{.State.Status}}\t{{index .Config.Labels \"dev.punar.managed-by\"}}",
    ])
}

/// `podman run` for the environment container: labeled, `--network none`
/// always in M6 (M6 plan section 5.3), project bind-mounted at /workspace
/// per the filesystem grade — `mount` carries the prebuilt `--mount` value,
/// or `None` for the `deny` grade (no project view).
pub fn args_run(container: &str, project: &str, mount: Option<&str>) -> Vec<String> {
    let mut out = argv(&["podman", "run", "-d", "--name"]);
    out.push(container.to_string());
    out.push("--label".to_string());
    out.push(format!("{MANAGED_BY_LABEL}={MANAGED_BY_VALUE}"));
    out.push("--label".to_string());
    out.push(format!("{PROJECT_LABEL}={project}"));
    out.push("--network".to_string());
    out.push("none".to_string());
    if let Some(mount) = mount {
        out.push("--mount".to_string());
        out.push(mount.to_string());
    }
    out.extend(argv(&[
        "--workdir",
        "/workspace",
        IMAGE_REF,
        "/bin/sh",
        "-c",
        PID1_COMMAND,
    ]));
    out
}

/// The `--mount` value for a project directory and grade; `read` mounts
/// read-only, `deny` yields no mount at all (handled by the caller).
pub fn mount_value(src: &Path, read_only: bool) -> String {
    let ro = if read_only { ",ro" } else { "" };
    format!("type=bind,src={},dst=/workspace{ro}", src.display())
}

/// `podman start <container>` — resume a stopped environment.
pub fn args_start(container: &str) -> Vec<String> {
    argv(&["podman", "start", container])
}

/// Interactive shell: `podman exec -i -t <container> /bin/sh`.
pub fn args_exec_interactive(container: &str) -> Vec<String> {
    argv(&["podman", "exec", "-i", "-t", container, "/bin/sh"])
}

/// `shell -c`: non-interactive, the command string is a single argv token
/// interpreted by the **container's** shell, never the host's.
pub fn args_exec_command(container: &str, command: &str) -> Vec<String> {
    argv(&["podman", "exec", container, "/bin/sh", "-c", command])
}

/// `podman rm -f <container>` — destroy exactly the one labeled container.
pub fn args_rm(container: &str) -> Vec<String> {
    argv(&["podman", "rm", "-f", container])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Table-driven exact-argv assertions (M6 plan section 3.2): the whole
    /// podman surface, one fixed vector each — no shell, no interpolation.
    #[test]
    fn argv_vectors_are_exact() {
        let cases: Vec<(Vec<String>, Vec<&str>)> = vec![
            (
                args_image_exists(),
                vec!["podman", "image", "exists", "localhost/punar-env-base:m6"],
            ),
            (
                args_image_load(),
                vec![
                    "podman",
                    "load",
                    "-i",
                    "/usr/share/punar/oci/punar-env-base.tar",
                ],
            ),
            (
                args_inspect("punar-env-atlas"),
                vec![
                    "podman",
                    "container",
                    "inspect",
                    "punar-env-atlas",
                    "--format",
                    "{{.State.Status}}\t{{index .Config.Labels \"dev.punar.managed-by\"}}",
                ],
            ),
            (
                args_run(
                    "punar-env-atlas",
                    "atlas",
                    Some("type=bind,src=/home/punar/atlas,dst=/workspace"),
                ),
                vec![
                    "podman",
                    "run",
                    "-d",
                    "--name",
                    "punar-env-atlas",
                    "--label",
                    "dev.punar.managed-by=punar-env",
                    "--label",
                    "dev.punar.project=atlas",
                    "--network",
                    "none",
                    "--mount",
                    "type=bind,src=/home/punar/atlas,dst=/workspace",
                    "--workdir",
                    "/workspace",
                    "localhost/punar-env-base:m6",
                    "/bin/sh",
                    "-c",
                    "exec sleep 2147483647",
                ],
            ),
            (
                // deny grade: no mount tokens at all.
                args_run("punar-env-atlas", "atlas", None),
                vec![
                    "podman",
                    "run",
                    "-d",
                    "--name",
                    "punar-env-atlas",
                    "--label",
                    "dev.punar.managed-by=punar-env",
                    "--label",
                    "dev.punar.project=atlas",
                    "--network",
                    "none",
                    "--workdir",
                    "/workspace",
                    "localhost/punar-env-base:m6",
                    "/bin/sh",
                    "-c",
                    "exec sleep 2147483647",
                ],
            ),
            (
                args_start("punar-env-atlas"),
                vec!["podman", "start", "punar-env-atlas"],
            ),
            (
                args_exec_interactive("punar-env-atlas"),
                vec!["podman", "exec", "-i", "-t", "punar-env-atlas", "/bin/sh"],
            ),
            (
                args_exec_command("punar-env-atlas", "cat /etc/punar-env-base-release"),
                vec![
                    "podman",
                    "exec",
                    "punar-env-atlas",
                    "/bin/sh",
                    "-c",
                    "cat /etc/punar-env-base-release",
                ],
            ),
            (
                args_rm("punar-env-atlas"),
                vec!["podman", "rm", "-f", "punar-env-atlas"],
            ),
        ];
        for (built, expected) in cases {
            assert_eq!(built, expected, "argv mismatch");
        }
    }

    /// A hostile shell string in `shell -c` stays one argv token — nothing
    /// on the host ever interprets it.
    #[test]
    fn shell_command_string_is_a_single_token() {
        let hostile = "echo pwned; rm -rf / && $(reboot)";
        let argv = args_exec_command("punar-env-atlas", hostile);
        assert_eq!(argv.iter().filter(|a| a.contains("pwned")).count(), 1);
        assert_eq!(argv.last().unwrap(), hostile);
    }

    /// Paths with spaces ride as whole argv tokens in `--mount` values.
    #[test]
    fn mount_value_keeps_paths_whole() {
        let src = PathBuf::from("/home/punar/my project");
        assert_eq!(
            mount_value(&src, false),
            "type=bind,src=/home/punar/my project,dst=/workspace"
        );
        assert_eq!(
            mount_value(&src, true),
            "type=bind,src=/home/punar/my project,dst=/workspace,ro"
        );
    }

    #[test]
    fn container_names_derive_deterministically() {
        assert_eq!(container_name("atlas"), "punar-env-atlas");
    }
}
