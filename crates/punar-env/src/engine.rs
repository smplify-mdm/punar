//! The environment operations behind each CLI verb, written against the
//! [`Podman`] trait so host tests need no podman. Podman is the single
//! source of truth for environment state — no state file, nothing to
//! corrupt, nothing to drift (M6 plan section 3.1).
//!
//! Errors speak SPEC section 73: what happened, why, and the next step —
//! never a bare errno.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::manifest::{
    self, CANONICAL_FILENAME, FilesystemAccess, Manifest, Resolution, SCAFFOLD, SCAFFOLD_NAME_LINE,
};
use crate::podman::{
    self, ARCHIVE_PATH, IMAGE_REF, MANAGED_BY_LABEL, MANAGED_BY_VALUE, Podman, container_name,
};

/// Failure taxonomy → D-014 exit codes: `Usage` exits 2, `Runtime` exits 1.
#[derive(Debug, thiserror::Error)]
pub enum EnvError {
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Runtime(String),
}

impl EnvError {
    pub fn exit_code(&self) -> u8 {
        match self {
            EnvError::Usage(_) => 2,
            EnvError::Runtime(_) => 1,
        }
    }
}

/// Observed container state, derived from podman on every call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerState {
    NotCreated,
    Running,
    Stopped,
}

impl ContainerState {
    pub fn as_str(self) -> &'static str {
        match self {
            ContainerState::NotCreated => "not created",
            ContainerState::Running => "running",
            ContainerState::Stopped => "stopped",
        }
    }
}

impl fmt::Display for ContainerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One command's result: the human line, the machine object, exit 0.
/// `warnings` carries forward-compat manifest warnings for commands that
/// load the manifest themselves (init); printed to stderr by the caller.
#[derive(Debug)]
pub struct CmdOutput {
    pub line: String,
    pub json: serde_json::Value,
    pub warnings: Vec<String>,
}

/// A loaded manifest with its file and forward-compat warnings.
pub struct Loaded {
    pub file: PathBuf,
    pub manifest: Manifest,
    pub warnings: Vec<String>,
}

/// Resolve and load the manifest for `dir` (SPEC section 73 voice on every
/// failure).
pub fn load_manifest(dir: &Path) -> Result<Loaded, EnvError> {
    let file = match manifest::resolve(dir) {
        Resolution::Found(file) => file,
        Resolution::Missing => {
            return Err(EnvError::Runtime(format!(
                "no environment manifest in {}.\n\
                 punar-env looks for {} (accepted alternates: punar-env.yml, \
                 project-environment.yaml).\n\
                 Next step: run `punar-env init` here to scaffold one.",
                dir.display(),
                CANONICAL_FILENAME
            )));
        }
        Resolution::Conflict(names) => {
            return Err(EnvError::Usage(format!(
                "multiple environment manifests in {}: {}.\n\
                 punar-env refuses to guess which declaration governs this project.\n\
                 Next step: keep exactly one (canonical name: {}).",
                dir.display(),
                names.join(", "),
                CANONICAL_FILENAME
            )));
        }
    };
    let src = std::fs::read_to_string(&file).map_err(|e| {
        EnvError::Runtime(format!(
            "cannot read {}: {e}.\nNext step: check the file's permissions.",
            file.display()
        ))
    })?;
    let parsed =
        manifest::parse_str(&src).map_err(|problems| invalid_manifest(&file, &problems))?;
    Ok(Loaded {
        file,
        manifest: parsed.manifest,
        warnings: parsed.warnings,
    })
}

fn invalid_manifest(file: &Path, problems: &[String]) -> EnvError {
    let mut listed = String::new();
    for p in problems {
        listed.push_str("\n  ");
        listed.push_str(p);
    }
    EnvError::Runtime(format!(
        "manifest {} is not a valid ProjectEnvironment ({}):{listed}\n\
         Schema: schemas/project/project-environment.json (SPEC section 17).\n\
         Next step: fix the listed fields; `punar-env init` in an empty directory \
         shows a valid example shape.",
        file.display(),
        manifest::API_VERSION,
    ))
}

fn podman_missing() -> EnvError {
    EnvError::Runtime(
        "podman is not available (executable not found in PATH).\n\
         punar-env drives rootless podman (pinned 6.1.0 in the Punar desktop image) to run \
         project environments; there is no fallback engine.\n\
         Next step: run on a Punar system, or install podman and rerun."
            .to_string(),
    )
}

fn spawn_err(e: io::Error) -> EnvError {
    if e.kind() == io::ErrorKind::NotFound {
        podman_missing()
    } else {
        EnvError::Runtime(format!(
            "podman could not be started: {e}.\nNext step: check that podman runs at all \
             (`podman info`) and rerun."
        ))
    }
}

fn unmanaged_conflict(container: &str) -> EnvError {
    EnvError::Runtime(format!(
        "container '{container}' already exists but is not managed by punar-env \
         (label {MANAGED_BY_LABEL}={MANAGED_BY_VALUE} missing or different).\n\
         punar-env only ever touches containers it created, so this name collision blocks \
         the environment.\n\
         Next step: rename or remove the existing container (`podman rm {container}`), \
         then rerun."
    ))
}

/// Observe the environment container. Managed-ness is only meaningful when
/// the container exists.
pub fn observe(podman: &dyn Podman, container: &str) -> Result<(ContainerState, bool), EnvError> {
    let exec = podman
        .output(&podman::args_inspect(container))
        .map_err(spawn_err)?;
    if !exec.ok() {
        return Ok((ContainerState::NotCreated, true));
    }
    let line = exec.stdout.lines().next().unwrap_or("");
    let (status, label) = line.split_once('\t').unwrap_or((line, ""));
    let state = if status.trim() == "running" {
        ContainerState::Running
    } else {
        ContainerState::Stopped
    };
    Ok((state, label.trim() == MANAGED_BY_VALUE))
}

/// Observed state for `status`, with the ownership check applied: a name
/// collision with an unmanaged container is reported, never rendered as
/// if it were ours.
pub fn container_state_of(
    podman: &dyn Podman,
    container: &str,
) -> Result<ContainerState, EnvError> {
    let (state, managed) = observe(podman, container)?;
    if state != ContainerState::NotCreated && !managed {
        return Err(unmanaged_conflict(container));
    }
    Ok(state)
}

/// `punar-env init` — scaffold or confirm; **never rewrites a byte**.
pub fn op_init(dir: &Path, name_flag: Option<&str>) -> Result<CmdOutput, EnvError> {
    match manifest::resolve(dir) {
        Resolution::Conflict(names) => Err(EnvError::Usage(format!(
            "multiple environment manifests in {}: {}.\n\
             punar-env refuses to guess which declaration governs this project.\n\
             Next step: keep exactly one (canonical name: {}).",
            dir.display(),
            names.join(", "),
            CANONICAL_FILENAME
        ))),
        Resolution::Found(file) => {
            // Present → parse + validate, confirm, and leave every byte
            // alone (m6-check asserts byte-identity around this path).
            let loaded = load_manifest(dir)?;
            let file_name = file
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let project = loaded.manifest.project.name.clone();
            Ok(CmdOutput {
                line: format!("already initialized · {file_name} · project {project}"),
                json: serde_json::json!({
                    "v": 1,
                    "command": "init",
                    "result": "already-initialized",
                    "file": file_name,
                    "project": project,
                }),
                warnings: loaded.warnings,
            })
        }
        Resolution::Missing => {
            let name = match name_flag {
                Some(name) => name.to_string(),
                None => derive_name(dir)?,
            };
            if !manifest::is_valid_name(&name) {
                return Err(EnvError::Usage(format!(
                    "'{name}' is not a usable project name.\n\
                     punar-env derives the container name punar-env-<name>; use lowercase \
                     letters, digits, '.', '_' or '-' (starting and ending alphanumeric, at \
                     most 50 characters).\n\
                     Next step: pass a conforming name with --name."
                )));
            }
            let content = SCAFFOLD.replace(SCAFFOLD_NAME_LINE, &format!("  name: {name}"));
            let file = dir.join(CANONICAL_FILENAME);
            std::fs::write(&file, &content).map_err(|e| {
                EnvError::Runtime(format!(
                    "cannot write {}: {e}.\nNext step: check the directory's permissions.",
                    file.display()
                ))
            })?;
            Ok(CmdOutput {
                line: format!("initialized · {CANONICAL_FILENAME} · project {name}"),
                json: serde_json::json!({
                    "v": 1,
                    "command": "init",
                    "result": "initialized",
                    "file": CANONICAL_FILENAME,
                    "project": name,
                }),
                warnings: Vec::new(),
            })
        }
    }
}

fn derive_name(dir: &Path) -> Result<String, EnvError> {
    let raw = dir
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if manifest::is_valid_name(&raw) {
        Ok(raw)
    } else {
        Err(EnvError::Usage(format!(
            "cannot derive a project name from directory '{raw}'.\n\
             Project names become the container name punar-env-<name>: lowercase letters, \
             digits, '.', '_' or '-', starting and ending alphanumeric.\n\
             Next step: rerun as `punar-env init --name <name>`."
        )))
    }
}

/// `punar-env up` — ensure the base image, then create or resume the one
/// labeled container. Idempotent.
pub fn op_up(podman: &dyn Podman, dir: &Path, m: &Manifest) -> Result<CmdOutput, EnvError> {
    let project = &m.project.name;
    let container = container_name(project);

    ensure_image(podman)?;

    let (state, managed) = observe(podman, &container)?;
    if state != ContainerState::NotCreated && !managed {
        return Err(unmanaged_conflict(&container));
    }
    match state {
        ContainerState::Running => Ok(CmdOutput {
            line: format!("already up · {container}"),
            json: up_json(project, &container, "already-up"),
            warnings: Vec::new(),
        }),
        ContainerState::Stopped => {
            let exec = podman
                .output(&podman::args_start(&container))
                .map_err(spawn_err)?;
            if !exec.ok() {
                return Err(EnvError::Runtime(format!(
                    "podman could not start the existing container '{container}' \
                     (exit {}):\n{}\n\
                     Next step: inspect it (`podman logs {container}`), or remove it with \
                     `punar-env destroy` and rerun `punar-env up`.",
                    exec.code,
                    exec.stderr.trim()
                )));
            }
            Ok(CmdOutput {
                line: format!("started · {container}"),
                json: up_json(project, &container, "started"),
                warnings: Vec::new(),
            })
        }
        ContainerState::NotCreated => {
            let mount = workspace_mount(dir, m)?;
            let exec = podman
                .output(&podman::args_run(&container, project, mount.as_deref()))
                .map_err(spawn_err)?;
            if !exec.ok() {
                return Err(EnvError::Runtime(format!(
                    "podman could not create the environment container '{container}' \
                     (exit {}):\n{}\n\
                     Next step: check `podman info` for rootless storage problems and rerun.",
                    exec.code,
                    exec.stderr.trim()
                )));
            }
            let grade = project_grade(m);
            let line = match mount {
                Some(_) => format!(
                    "up · {container} · {} → /workspace ({})",
                    dir.display(),
                    grade.as_str()
                ),
                None => format!("up · {container} · no workspace mount (filesystem.project: deny)"),
            };
            Ok(CmdOutput {
                line,
                json: up_json(project, &container, "created"),
                warnings: Vec::new(),
            })
        }
    }
}

fn up_json(project: &str, container: &str, result: &str) -> serde_json::Value {
    serde_json::json!({
        "v": 1,
        "command": "up",
        "result": result,
        "project": project,
        "container": container,
    })
}

/// The declared `permissions.filesystem.project` grade; the schema keeps
/// the map open, but an absent `project` zone means no grant → `deny`.
pub fn project_grade(m: &Manifest) -> FilesystemAccess {
    m.permissions
        .filesystem
        .get("project")
        .copied()
        .unwrap_or(FilesystemAccess::Deny)
}

/// The `--mount` value for the project directory, or `None` for `deny` —
/// the one permission grant M6 actually realizes (M6 plan section 5.4).
fn workspace_mount(dir: &Path, m: &Manifest) -> Result<Option<String>, EnvError> {
    let grade = project_grade(m);
    if grade == FilesystemAccess::Deny {
        return Ok(None);
    }
    let src = dir.display().to_string();
    if src.contains(',') {
        // podman's `--mount` grammar splits on commas; a comma in the
        // path cannot be expressed. Refuse honestly instead of mounting
        // the wrong thing.
        return Err(EnvError::Runtime(format!(
            "the project directory path '{src}' contains a comma, which podman's --mount \
             option cannot express.\n\
             Next step: move or link the project to a comma-free path and rerun."
        )));
    }
    Ok(Some(podman::mount_value(
        dir,
        grade == FilesystemAccess::Read,
    )))
}

/// Preconditions shared by `shell`: the environment must be up.
fn require_running(podman: &dyn Podman, container: &str) -> Result<(), EnvError> {
    let (state, managed) = observe(podman, container)?;
    match state {
        ContainerState::Running if managed => Ok(()),
        ContainerState::Running => Err(unmanaged_conflict(container)),
        other => Err(EnvError::Runtime(format!(
            "environment not up · run punar-env up\n\
             container '{container}' is {other}; a shell needs a running environment."
        ))),
    }
}

/// `punar-env shell [-c CMD]` — the container command's exit code is
/// passed through verbatim (M6 plan section 3.3).
pub fn op_shell(podman: &dyn Podman, m: &Manifest, command: Option<&str>) -> Result<u8, EnvError> {
    let container = container_name(&m.project.name);
    require_running(podman, &container)?;
    let argv = match command {
        Some(cmd) => podman::args_exec_command(&container, cmd),
        None => podman::args_exec_interactive(&container),
    };
    let code = podman.interactive(&argv).map_err(spawn_err)?;
    Ok(code.clamp(0, 255) as u8)
}

/// `punar-env destroy` — removes only the labeled container; project
/// files are never touched. Idempotent.
pub fn op_destroy(podman: &dyn Podman, m: &Manifest) -> Result<CmdOutput, EnvError> {
    let project = &m.project.name;
    let container = container_name(project);
    let (state, managed) = observe(podman, &container)?;
    if state == ContainerState::NotCreated {
        return Ok(CmdOutput {
            line: format!("nothing to destroy · {container}"),
            json: serde_json::json!({
                "v": 1,
                "command": "destroy",
                "result": "nothing-to-destroy",
                "project": project,
                "container": container,
            }),
            warnings: Vec::new(),
        });
    }
    if !managed {
        return Err(unmanaged_conflict(&container));
    }
    let exec = podman
        .output(&podman::args_rm(&container))
        .map_err(spawn_err)?;
    if !exec.ok() {
        return Err(EnvError::Runtime(format!(
            "podman could not remove the container '{container}' (exit {}):\n{}\n\
             Next step: `podman rm -f {container}` by hand, then rerun.",
            exec.code,
            exec.stderr.trim()
        )));
    }
    Ok(CmdOutput {
        line: format!("destroyed · {container} · project files untouched"),
        json: serde_json::json!({
            "v": 1,
            "command": "destroy",
            "result": "destroyed",
            "project": project,
            "container": container,
        }),
        warnings: Vec::new(),
    })
}

/// Ensure `localhost/punar-env-base:m6` is loadable — first `up` loads the
/// archive the OS image staged (offline CI: no registry, ever).
fn ensure_image(podman: &dyn Podman) -> Result<(), EnvError> {
    let exists = podman
        .output(&podman::args_image_exists())
        .map_err(spawn_err)?;
    if exists.ok() {
        return Ok(());
    }
    let load = podman
        .output(&podman::args_image_load())
        .map_err(spawn_err)?;
    if !load.ok() {
        return Err(EnvError::Runtime(format!(
            "the offline base image {IMAGE_REF} is not loaded and loading {ARCHIVE_PATH} \
             failed (exit {}):\n{}\n\
             The archive is staged by the Punar image build; environments never pull from a \
             registry in M6.\n\
             Next step: check that the file exists and is readable, then rerun `punar-env up`.",
            load.code,
            load.stderr.trim()
        )));
    }
    Ok(())
}

/// `punar-env agent <name>` — the labeled M7 stub: the membership check
/// against `ai.agents` is real, the launch is not, and says so (SPEC 1.22).
pub fn op_agent(m: &Manifest, name: &str) -> EnvError {
    if m.ai.agents.iter().any(|a| a == name) {
        EnvError::Runtime(format!(
            "agent sessions arrive in Milestone 7 (AI Agent Registry); '{name}' is declared \
             in this environment's manifest"
        ))
    } else {
        EnvError::Runtime(format!(
            "agent '{name}' is not declared in this environment's manifest.\n\
             Declared agents: {}.\n\
             Next step: add it to ai.agents, or use a declared agent — agent sessions \
             themselves arrive in Milestone 7 (AI Agent Registry).",
            m.ai.agents.join(" · ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    const ATLAS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/projects/atlas/project-environment.yaml"
    ));

    fn atlas() -> Manifest {
        manifest::parse_str(ATLAS).unwrap().manifest
    }

    /// Scripted podman: records every argv, pops one canned result per
    /// `output` call, returns a fixed code for `interactive`.
    struct Mock {
        calls: RefCell<Vec<Vec<String>>>,
        script: RefCell<VecDeque<Exec2>>,
        interactive_code: i32,
    }

    enum Exec2 {
        Out(i32, &'static str),
    }

    impl Mock {
        fn new(script: Vec<Exec2>) -> Self {
            Mock {
                calls: RefCell::new(Vec::new()),
                script: RefCell::new(script.into()),
                interactive_code: 0,
            }
        }

        fn programs(&self) -> Vec<String> {
            self.calls
                .borrow()
                .iter()
                .map(|argv| argv[..3.min(argv.len())].join(" "))
                .collect()
        }
    }

    impl Podman for Mock {
        fn output(&self, argv: &[String]) -> io::Result<podman::Exec> {
            self.calls.borrow_mut().push(argv.to_vec());
            let Exec2::Out(code, stdout) = self
                .script
                .borrow_mut()
                .pop_front()
                .expect("mock script exhausted");
            Ok(podman::Exec {
                code,
                stdout: stdout.to_string(),
                stderr: String::new(),
            })
        }

        fn interactive(&self, argv: &[String]) -> io::Result<i32> {
            self.calls.borrow_mut().push(argv.to_vec());
            Ok(self.interactive_code)
        }
    }

    #[test]
    fn up_loads_image_and_creates_when_absent() {
        let mock = Mock::new(vec![
            Exec2::Out(1, ""),         // image exists → no
            Exec2::Out(0, ""),         // load
            Exec2::Out(1, ""),         // inspect → not created
            Exec2::Out(0, "abcdef\n"), // run
        ]);
        let out = op_up(&mock, Path::new("/home/punar/atlas"), &atlas()).unwrap();
        assert!(out.line.starts_with("up · punar-env-atlas"), "{}", out.line);
        assert!(
            out.line
                .contains("/home/punar/atlas → /workspace (read_write)")
        );
        assert_eq!(
            mock.programs(),
            vec![
                "podman image exists",
                "podman load -i",
                "podman container inspect",
                "podman run -d",
            ]
        );
        // The run argv carries --network none and the rw bind mount.
        let calls = mock.calls.borrow();
        let run = calls.last().unwrap();
        assert!(run.windows(2).any(|w| w == ["--network", "none"]));
        assert!(
            run.contains(&"type=bind,src=/home/punar/atlas,dst=/workspace".to_string()),
            "{run:?}"
        );
    }

    #[test]
    fn up_is_idempotent_when_running() {
        let mock = Mock::new(vec![
            Exec2::Out(0, ""),                     // image exists
            Exec2::Out(0, "running\tpunar-env\n"), // inspect
        ]);
        let out = op_up(&mock, Path::new("/home/punar/atlas"), &atlas()).unwrap();
        assert_eq!(out.line, "already up · punar-env-atlas");
        assert_eq!(out.json["result"], "already-up");
    }

    #[test]
    fn up_restarts_a_stopped_container() {
        let mock = Mock::new(vec![
            Exec2::Out(0, ""),
            Exec2::Out(0, "exited\tpunar-env\n"),
            Exec2::Out(0, "punar-env-atlas\n"), // start
        ]);
        let out = op_up(&mock, Path::new("/home/punar/atlas"), &atlas()).unwrap();
        assert_eq!(out.line, "started · punar-env-atlas");
    }

    #[test]
    fn up_refuses_a_name_collision_with_an_unmanaged_container() {
        let mock = Mock::new(vec![
            Exec2::Out(0, ""),
            Exec2::Out(0, "running\t\n"), // exists, no ownership label
        ]);
        let err = op_up(&mock, Path::new("/home/punar/atlas"), &atlas()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not managed by punar-env"), "{msg}");
        assert!(msg.contains("Next step"), "{msg}");
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn shell_passes_the_container_exit_code_through() {
        let mut mock = Mock::new(vec![Exec2::Out(0, "running\tpunar-env\n")]);
        mock.interactive_code = 42;
        let code = op_shell(&mock, &atlas(), Some("exit 42")).unwrap();
        assert_eq!(code, 42);
        let calls = mock.calls.borrow();
        assert_eq!(
            *calls.last().unwrap(),
            vec![
                "podman",
                "exec",
                "punar-env-atlas",
                "/bin/sh",
                "-c",
                "exit 42"
            ]
        );
    }

    #[test]
    fn shell_requires_a_running_environment() {
        let mock = Mock::new(vec![Exec2::Out(1, "")]);
        let err = op_shell(&mock, &atlas(), None).unwrap_err();
        assert!(
            err.to_string()
                .contains("environment not up · run punar-env up")
        );
    }

    #[test]
    fn destroy_removes_only_the_managed_container_and_is_idempotent() {
        let mock = Mock::new(vec![
            Exec2::Out(0, "running\tpunar-env\n"),
            Exec2::Out(0, "punar-env-atlas\n"), // rm -f
        ]);
        let out = op_destroy(&mock, &atlas()).unwrap();
        assert!(out.line.starts_with("destroyed · punar-env-atlas"));
        assert_eq!(
            *mock.calls.borrow().last().unwrap(),
            vec!["podman", "rm", "-f", "punar-env-atlas"]
        );

        let mock = Mock::new(vec![Exec2::Out(1, "")]);
        let out = op_destroy(&mock, &atlas()).unwrap();
        assert_eq!(out.line, "nothing to destroy · punar-env-atlas");
        assert_eq!(out.json["result"], "nothing-to-destroy");
    }

    #[test]
    fn agent_stub_is_honest_in_both_directions() {
        let declared = op_agent(&atlas(), "claude-code");
        assert!(declared.to_string().contains("Milestone 7"));
        assert!(declared.to_string().contains("'claude-code' is declared"));
        assert_eq!(declared.exit_code(), 1);

        let undeclared = op_agent(&atlas(), "rogue-agent");
        let msg = undeclared.to_string();
        assert!(msg.contains("not declared"), "{msg}");
        assert!(msg.contains("claude-code · codex"), "{msg}");
    }

    #[test]
    fn deny_grade_means_no_mount() {
        let src = ATLAS.replace("project: read_write", "project: deny");
        let m = manifest::parse_str(&src).unwrap().manifest;
        let mock = Mock::new(vec![
            Exec2::Out(0, ""),
            Exec2::Out(1, ""),
            Exec2::Out(0, "abcdef\n"),
        ]);
        let out = op_up(&mock, Path::new("/home/punar/atlas"), &m).unwrap();
        assert!(out.line.contains("no workspace mount"), "{}", out.line);
        let calls = mock.calls.borrow();
        assert!(
            !calls
                .last()
                .unwrap()
                .iter()
                .any(|a| a.contains("type=bind"))
        );
    }

    #[test]
    fn comma_paths_are_refused_honestly() {
        let mock = Mock::new(vec![Exec2::Out(0, ""), Exec2::Out(1, "")]);
        let err = op_up(&mock, Path::new("/home/punar/a,b"), &atlas()).unwrap_err();
        assert!(err.to_string().contains("comma"), "{err}");
    }

    /// init idempotence: a present manifest is confirmed and never
    /// rewritten — byte-identity asserted around the call.
    #[test]
    fn init_never_rewrites_and_scaffolds_a_valid_manifest() {
        let dir = std::env::temp_dir().join(format!("punar-env-init-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Scaffold path: empty dir, name from --name.
        let out = op_init(&dir, Some("atlas")).unwrap();
        assert_eq!(out.line, "initialized · punar-env.yaml · project atlas");
        let written = std::fs::read_to_string(dir.join(CANONICAL_FILENAME)).unwrap();
        let parsed = manifest::parse_str(&written).expect("scaffold output must validate");
        assert!(parsed.warnings.is_empty());
        assert_eq!(parsed.manifest.project.name, "atlas");

        // Idempotence: bytes before == bytes after.
        let before = std::fs::read(dir.join(CANONICAL_FILENAME)).unwrap();
        let out = op_init(&dir, None).unwrap();
        assert_eq!(
            out.line,
            "already initialized · punar-env.yaml · project atlas"
        );
        let after = std::fs::read(dir.join(CANONICAL_FILENAME)).unwrap();
        assert_eq!(before, after, "init must never rewrite a byte");

        // Unknown fields warn (surfaced through CmdOutput), never fail —
        // and still never trigger a rewrite.
        let mut with_future = String::from_utf8(before.clone()).unwrap();
        with_future.push_str("future_block: anything\n");
        std::fs::write(dir.join(CANONICAL_FILENAME), &with_future).unwrap();
        let out = op_init(&dir, None).unwrap();
        assert!(out.line.starts_with("already initialized"), "{}", out.line);
        assert!(
            out.warnings.iter().any(|w| w.contains("future_block")),
            "{:?}",
            out.warnings
        );
        let after = std::fs::read_to_string(dir.join(CANONICAL_FILENAME)).unwrap();
        assert_eq!(after, with_future);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn init_rejects_underivable_directory_names() {
        let dir = std::env::temp_dir().join(format!("Punar ENV {}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let err = op_init(&dir, None).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("--name"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
