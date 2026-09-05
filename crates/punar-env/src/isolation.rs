//! Kernel-enforced filesystem isolation for managed host AI sessions.
//!
//! The project container and the host agent are deliberately separate
//! processes, but they must have the same least-authority filesystem shape.
//! Bubblewrap gives the host agent a private mount/PID/IPC/UTS namespace while
//! leaving its systemd cgroup untouched.  That last property matters: agentd
//! can still attribute the outer lifecycle process and every sandbox child to
//! `punar-agent-<session>.scope`.
//!
//! Nothing from the real home or user runtime directory is mounted.  The
//! session gets fresh directories below `/run/user/$UID`, `/tmp` is a private
//! tmpfs, and the declared project is the only host-owned writable tree.  A
//! resolver files are exposed individually; Punar control/broker sockets and
//! the user's D-Bus and systemd sockets are never mounted.

use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use crate::engine::EnvError;
use crate::manifest::FilesystemAccess;

/// The product image pins this path.  Using PATH here would let a same-user
/// executable replace the isolation primitive before any boundary exists.
pub const BWRAP_PATH: &str = "/usr/bin/bwrap";

/// Every host-side executable in the managed launch chain is pinned.  These
/// names are part of the image contract; a PATH lookup would happen before
/// the sandbox exists and is therefore never acceptable here.
pub const SYSTEMD_RUN_PATH: &str = "/usr/bin/systemd-run";
pub const SYSTEMCTL_PATH: &str = "/usr/bin/systemctl";
pub const PUNAR_ENV_PATH: &str = "/usr/bin/punar-env";
/// coreutils `env`, used only for its signal-disposition options: the gate
/// execs Bubblewrap through `env --ignore-signal=TERM` so a scope stop cannot
/// kill the monitor before the adapter, and the adapter starts behind
/// `env --default-signal=TERM` so it alone sees the default disposition.
/// punar-env forbids unsafe code, and setting a disposition is otherwise a
/// raw `signal(2)` call; `env` is a canonical root-owned tool like the rest.
pub const ENV_PATH: &str = "/usr/bin/env";

/// A stable path inside every managed-agent namespace.
pub const SANDBOX_WORKSPACE: &str = "/workspace";

const SANDBOX_AGENT: &str = "/run/punar-agent-bin/agent";

/// The command that will execute inside the namespace.  A system executable
/// remains at its canonical `/usr` path.  A user-installed agent is exposed as
/// one read-only file at [`SANDBOX_AGENT`], never by mounting its home tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCommand {
    argv: Vec<OsString>,
    private_executable: Option<PathBuf>,
}

impl ResolvedCommand {
    fn argv(&self) -> &[OsString] {
        &self.argv
    }
}

/// Host directories created for one session.  They live in the user's
/// logout-scoped runtime directory, are mode 0700, and are removed when the
/// lifecycle anchor exits.  `Drop` is a crash-path best effort; the normal
/// path calls [`SessionIsolation::cleanup`] and reports a failure.
#[derive(Debug)]
pub struct SessionIsolation {
    root: PathBuf,
    home: PathBuf,
    runtime: PathBuf,
    denied_workspace: PathBuf,
    home_destination: PathBuf,
    runtime_destination: PathBuf,
    user_name: String,
    session_id: String,
    cleaned: bool,
}

impl SessionIsolation {
    /// Validate bubblewrap and create fresh, non-reused state for one session.
    pub fn prepare(session_id: &str) -> Result<Self, EnvError> {
        require_bubblewrap(Path::new(BWRAP_PATH))?;

        let uid = rustix::process::getuid().as_raw();
        let runtime_root = PathBuf::from(format!("/run/user/{uid}"));
        require_private_runtime(&runtime_root, uid)?;

        let (home_destination, user_name) = validated_home_destination()?;
        let sessions = runtime_root.join("punar-agent-sessions");
        create_or_validate_private_dir(&sessions, uid)?;

        let root = sessions.join(session_id);
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(&root).map_err(|error| {
            EnvError::Runtime(format!(
                "cannot create fresh isolation state for agent session {session_id}: {error}.\n\
                 The launcher never reuses a session home or runtime directory.\n\
                 Next step: inspect {} and remove only the stale directory named {session_id}.",
                sessions.display()
            ))
        })?;

        let home = root.join("home");
        let runtime = root.join("runtime");
        let denied_workspace = root.join("no-workspace");
        let prepared = (|| {
            for path in [&home, &runtime, &denied_workspace] {
                create_private_child(path)?;
            }
            for relative in [
                ".config",
                ".cache",
                ".local",
                ".local/share",
                ".local/state",
            ] {
                create_private_child(&home.join(relative))?;
            }
            Ok::<(), EnvError>(())
        })();
        if let Err(error) = prepared {
            let _ = fs::remove_dir_all(&root);
            return Err(error);
        }

        Ok(Self {
            root,
            home,
            runtime,
            denied_workspace,
            home_destination,
            runtime_destination: runtime_root,
            user_name,
            session_id: session_id.to_string(),
            cleaned: false,
        })
    }

    /// Construct the exact bubblewrap argv.  Every adapter argument remains a
    /// separate item after `--`; no shell parses this command.
    pub fn command_argv(
        &self,
        project: &Path,
        grade: FilesystemAccess,
        command: &ResolvedCommand,
        mock: bool,
    ) -> Vec<OsString> {
        bubblewrap_argv(
            &SandboxMounts {
                home_source: self.home.clone(),
                runtime_source: self.runtime.clone(),
                denied_workspace_source: self.denied_workspace.clone(),
                home_destination: self.home_destination.clone(),
                runtime_destination: self.runtime_destination.clone(),
                user_name: self.user_name.clone(),
                session_id: self.session_id.clone(),
            },
            project,
            grade,
            command,
            mock,
        )
    }

    /// Parent/gate handoff paths.  They sit beside, rather than inside, the
    /// directories mounted into Bubblewrap.  Adapter code therefore cannot
    /// forge a readiness proof or reread the launch specification.
    pub fn gate_spec_path(&self) -> PathBuf {
        self.root.join("gate.json")
    }

    pub fn gate_ready_path(&self) -> PathBuf {
        self.root.join("gate.ready.json")
    }

    pub fn gate_release_path(&self) -> PathBuf {
        self.root.join("gate.release.json")
    }

    pub fn home_destination(&self) -> &Path {
        &self.home_destination
    }

    /// Remove the isolated home/runtime after the agent has ended.  A failure
    /// is surfaced because silently retaining agent-created state would make
    /// the "per-session" promise false.
    pub fn cleanup(mut self) -> Result<(), EnvError> {
        match fs::remove_dir_all(&self.root) {
            Ok(()) => {
                self.cleaned = true;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.cleaned = true;
                Ok(())
            }
            Err(error) => Err(EnvError::Runtime(format!(
                "agent session ended, but its isolated state could not be removed: {error}.\n\
                 State: {}. It contains only this session's private home/runtime, never the real home.\n\
                 Next step: remove that exact directory, or log out to let /run/user cleanup remove it.",
                self.root.display()
            ))),
        }
    }
}

impl Drop for SessionIsolation {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

#[derive(Debug, Clone)]
struct SandboxMounts {
    home_source: PathBuf,
    runtime_source: PathBuf,
    denied_workspace_source: PathBuf,
    home_destination: PathBuf,
    runtime_destination: PathBuf,
    user_name: String,
    session_id: String,
}

fn push_arg(args: &mut Vec<OsString>, arg: impl AsRef<OsStr>) {
    args.push(arg.as_ref().to_os_string());
}

fn push_pair(args: &mut Vec<OsString>, option: impl AsRef<OsStr>, value: impl AsRef<OsStr>) {
    push_arg(args, option);
    push_arg(args, value);
}

fn push_mount(
    args: &mut Vec<OsString>,
    option: impl AsRef<OsStr>,
    source: impl AsRef<OsStr>,
    destination: impl AsRef<OsStr>,
) {
    push_arg(args, option);
    push_arg(args, source);
    push_arg(args, destination);
}

/// Pure argv builder.  Kept separate from directory preparation so unit tests
/// can pin every mount and environment decision without needing namespaces.
fn bubblewrap_argv(
    mounts: &SandboxMounts,
    project: &Path,
    grade: FilesystemAccess,
    command: &ResolvedCommand,
    mock: bool,
) -> Vec<OsString> {
    let mut args = Vec::new();
    push_arg(&mut args, BWRAP_PATH);
    for fixed in [
        "--die-with-parent",
        "--new-session",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
    ] {
        push_arg(&mut args, fixed);
    }
    push_pair(&mut args, "--hostname", "punar-agent");
    push_pair(&mut args, "--cap-drop", "ALL");
    push_arg(&mut args, "--clearenv");

    // Only immutable OS trees are visible.  The empty namespace root contains
    // no /home, /opt, /srv, /mnt, /media, /var, or host /tmp to wander into.
    push_mount(&mut args, "--ro-bind", "/usr", "/usr");
    push_pair(&mut args, "--symlink", "usr/bin");
    push_arg(&mut args, "/bin");
    push_pair(&mut args, "--symlink", "usr/sbin");
    push_arg(&mut args, "/sbin");
    push_pair(&mut args, "--symlink", "usr/lib");
    push_arg(&mut args, "/lib");
    push_pair(&mut args, "--symlink", "usr/lib64");
    push_arg(&mut args, "/lib64");
    push_mount(&mut args, "--ro-bind", "/etc", "/etc");
    push_pair(&mut args, "--proc", "/proc");
    push_pair(&mut args, "--dev", "/dev");

    // An empty /run plus resolver files only. In particular, /run/user/$UID
    // from the host is never bound, and every Punar control/broker socket
    // remains outside the adapter namespace.
    for path in ["/run", "/run/systemd", "/run/systemd/resolve", "/run/user"] {
        push_pair(&mut args, "--dir", path);
    }
    for path in [
        "/run/systemd/resolve/stub-resolv.conf",
        "/run/systemd/resolve/resolv.conf",
    ] {
        push_mount(&mut args, "--ro-bind-try", path, path);
    }
    push_mount(
        &mut args,
        "--bind",
        &mounts.runtime_source,
        &mounts.runtime_destination,
    );

    push_pair(&mut args, "--dir", "/home");
    push_mount(
        &mut args,
        "--bind",
        &mounts.home_source,
        &mounts.home_destination,
    );
    push_pair(&mut args, "--tmpfs", "/tmp");

    if let Some(source) = &command.private_executable {
        push_pair(&mut args, "--dir", "/run/punar-agent-bin");
        push_mount(&mut args, "--ro-bind", source, SANDBOX_AGENT);
    }

    match grade {
        FilesystemAccess::ReadWrite => push_mount(&mut args, "--bind", project, SANDBOX_WORKSPACE),
        FilesystemAccess::Read => push_mount(&mut args, "--ro-bind", project, SANDBOX_WORKSPACE),
        FilesystemAccess::Deny => push_mount(
            &mut args,
            "--ro-bind",
            &mounts.denied_workspace_source,
            SANDBOX_WORKSPACE,
        ),
    }

    let home = mounts.home_destination.to_string_lossy();
    let config = format!("{home}/.config");
    let cache = format!("{home}/.cache");
    let data = format!("{home}/.local/share");
    let state = format!("{home}/.local/state");
    let runtime = mounts.runtime_destination.to_string_lossy();
    for (key, value) in [
        ("HOME", home.as_ref()),
        ("USER", mounts.user_name.as_str()),
        ("LOGNAME", mounts.user_name.as_str()),
        ("PATH", "/usr/local/sbin:/usr/local/bin:/usr/bin:/bin"),
        ("LANG", "C.UTF-8"),
        ("LC_ALL", "C.UTF-8"),
        ("TERM", "xterm-256color"),
        ("TMPDIR", "/tmp"),
        ("XDG_CONFIG_HOME", config.as_str()),
        ("XDG_CACHE_HOME", cache.as_str()),
        ("XDG_DATA_HOME", data.as_str()),
        ("XDG_STATE_HOME", state.as_str()),
        ("XDG_RUNTIME_DIR", runtime.as_ref()),
        ("PUNAR_AGENT_SESSION_ID", mounts.session_id.as_str()),
        ("PUNAR_PROJECT_DIR", SANDBOX_WORKSPACE),
    ] {
        push_arg(&mut args, "--setenv");
        push_arg(&mut args, key);
        push_arg(&mut args, value);
    }

    // These switches only drive the loudly-labelled offline mock in VM tests.
    // Never forward arbitrary PUNAR_*, proxy, token, SSH, or D-Bus variables.
    if mock {
        for key in [
            "PUNAR_MOCK_AGENT_CHILDREN",
            "PUNAR_MOCK_AGENT_NET",
            "PUNAR_MOCK_AGENT_ISOLATION",
        ] {
            if std::env::var(key).is_ok_and(|value| value == "1") {
                push_arg(&mut args, "--setenv");
                push_arg(&mut args, key);
                push_arg(&mut args, "1");
            }
        }
    }

    push_pair(&mut args, "--chdir", SANDBOX_WORKSPACE);
    push_arg(&mut args, "--");
    // The adapter starts behind canonical `env` (read-only /usr is in the
    // namespace), which restores the default SIGTERM disposition the gate
    // ignored before exec'ing Bubblewrap and then execs the adapter argv
    // verbatim: no shell, no PATH lookup, no environment change.
    push_arg(&mut args, ENV_PATH);
    push_arg(&mut args, "--default-signal=TERM");
    push_arg(&mut args, "--");
    args.extend(command.argv().iter().cloned());
    args
}

/// Resolve the adapter's first argv item without a shell.  Relative paths with
/// a slash are refused; bare names use the invoking user's PATH, but only
/// absolute PATH entries are searched.  The result is canonical and executable
/// before bubblewrap is asked to mount or execute it.
pub fn resolve_command(command: &[String]) -> Result<ResolvedCommand, EnvError> {
    if command.is_empty() {
        return Err(EnvError::Runtime(
            "the agent adapter command is empty.\n\
             Next step: fix adapter_config.command; managed launch requires an argv array."
                .to_string(),
        ));
    }
    let requested = Path::new(&command[0]);
    let candidate = if requested.is_absolute() {
        requested.to_path_buf()
    } else if requested.components().count() == 1 {
        resolve_in_path(requested.as_os_str()).ok_or_else(|| {
            EnvError::Runtime(format!(
                "the agent executable '{}' was not found in any absolute PATH directory.\n\
                 The launcher will not run a different command or fall back outside isolation.\n\
                 Next step: install the agent, or correct adapter_config.command.",
                command[0]
            ))
        })?
    } else {
        return Err(EnvError::Runtime(format!(
            "the agent executable '{}' is a relative path containing '/'.\n\
             Managed launch accepts an absolute executable or a bare PATH name, never a path \
             whose meaning depends on the launcher's working directory.\n\
             Next step: use an absolute path in adapter_config.command.",
            command[0]
        )));
    };

    let canonical = candidate.canonicalize().map_err(|error| {
        EnvError::Runtime(format!(
            "the agent executable {} cannot be resolved: {error}.\n\
             Next step: reinstall the agent or correct adapter_config.command.",
            candidate.display()
        ))
    })?;
    let metadata = fs::metadata(&canonical).map_err(|error| {
        EnvError::Runtime(format!(
            "the agent executable {} cannot be inspected: {error}.",
            canonical.display()
        ))
    })?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(EnvError::Runtime(format!(
            "the agent executable {} is not an executable regular file.\n\
             Next step: reinstall the agent from its trusted source.",
            canonical.display()
        )));
    }

    let system = canonical.starts_with("/usr/");
    let mut argv: Vec<OsString> = command.iter().map(OsString::from).collect();
    if system {
        argv[0] = canonical.into_os_string();
        Ok(ResolvedCommand {
            argv,
            private_executable: None,
        })
    } else {
        argv[0] = OsString::from(SANDBOX_AGENT);
        Ok(ResolvedCommand {
            argv,
            private_executable: Some(canonical),
        })
    }
}

fn resolve_in_path(program: &OsStr) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join(program))
        .find(|candidate| {
            fs::metadata(candidate).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
}

/// Validate one pre-sandbox executable and every directory that selects it.
///
/// Production calls use trusted uid 0 and `/` as the trust root.  Keeping the
/// trust root explicit lets unit tests build a complete owned hierarchy
/// without pretending that the host's world-writable `/tmp` is trusted.
fn validate_trusted_executable(
    path: &Path,
    trusted_uid: u32,
    trust_root: &Path,
) -> Result<(), String> {
    if !path.is_absolute() || !trust_root.is_absolute() {
        return Err("the executable and trust root must be absolute paths".to_string());
    }
    let canonical_root = trust_root
        .canonicalize()
        .map_err(|error| format!("the trust root cannot be canonicalized: {error}"))?;
    if canonical_root != trust_root {
        return Err(format!(
            "the trust root {} is not canonical (resolved to {})",
            trust_root.display(),
            canonical_root.display()
        ));
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("the executable cannot be canonicalized: {error}"))?;
    if canonical != path {
        return Err(format!(
            "the executable path is not canonical (resolved to {})",
            canonical.display()
        ));
    }
    if !path.starts_with(trust_root) {
        return Err(format!(
            "the executable is outside trusted root {}",
            trust_root.display()
        ));
    }

    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("the executable cannot be inspected: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("the executable is not a direct regular file".to_string());
    }
    if metadata.uid() != trusted_uid {
        return Err(format!(
            "the executable is owned by uid {}, expected {trusted_uid}",
            metadata.uid()
        ));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o111 == 0 {
        return Err("the regular file is not executable".to_string());
    }
    if mode & 0o022 != 0 {
        return Err(format!(
            "the executable is writable by group or others (mode {:o})",
            mode & 0o7777
        ));
    }

    let mut ancestor = path
        .parent()
        .ok_or_else(|| "the executable has no parent directory".to_string())?;
    loop {
        let metadata = fs::symlink_metadata(ancestor).map_err(|error| {
            format!(
                "ancestor {} cannot be inspected: {error}",
                ancestor.display()
            )
        })?;
        let mode = metadata.permissions().mode();
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(format!(
                "ancestor {} is not a direct directory",
                ancestor.display()
            ));
        }
        if metadata.uid() != trusted_uid {
            return Err(format!(
                "ancestor {} is owned by uid {}, expected {trusted_uid}",
                ancestor.display(),
                metadata.uid()
            ));
        }
        if mode & 0o022 != 0 {
            return Err(format!(
                "ancestor {} is writable by group or others (mode {:o})",
                ancestor.display(),
                mode & 0o7777
            ));
        }
        if ancestor == trust_root {
            break;
        }
        ancestor = ancestor.parent().ok_or_else(|| {
            format!(
                "the executable hierarchy did not reach trust root {}",
                trust_root.display()
            )
        })?;
    }
    Ok(())
}

/// Validate all immutable host tools before creating a scope.  Validation is
/// intentionally repeated on each launch so a damaged update fails closed.
pub fn require_launch_tools() -> Result<(), EnvError> {
    for (label, path) in [
        ("bubblewrap", BWRAP_PATH),
        ("systemd-run", SYSTEMD_RUN_PATH),
        ("systemctl", SYSTEMCTL_PATH),
        ("punar-env gate", PUNAR_ENV_PATH),
        ("coreutils env", ENV_PATH),
    ] {
        validate_trusted_executable(Path::new(path), 0, Path::new("/")).map_err(|reason| {
            EnvError::Runtime(format!(
                "managed AI isolation is unavailable: {label} at {path} failed the immutable tool check: {reason}.\n\
                 There is no PATH lookup or unsandboxed fallback.\n\
                 Next step: repair the signed Punar image package that owns {path}, then retry."
            ))
        })?;
    }
    Ok(())
}

fn require_bubblewrap(path: &Path) -> Result<(), EnvError> {
    validate_trusted_executable(path, 0, Path::new("/")).map_err(|reason| {
        EnvError::Runtime(format!(
            "managed AI isolation is unavailable: {} failed the immutable tool check: {reason}.\n\
             There is no unsandboxed fallback.\n\
             Next step: repair the Punar bubblewrap package and retry.",
            path.display()
        ))
    })
}

/// Refuse a project mount whose canonical target would expose a broad system
/// tree, the entire account, or a credential/configuration subtree.  This is
/// checked independently of manifest policy immediately before argv creation.
pub fn validate_project_mount(project: &Path, home: &Path) -> Result<(), EnvError> {
    if !project.is_absolute() {
        return Err(unsafe_project(project, "the path is not absolute"));
    }
    let canonical = project.canonicalize().map_err(|error| {
        unsafe_project(
            project,
            &format!("the path cannot be canonicalized: {error}"),
        )
    })?;
    if canonical != project {
        return Err(unsafe_project(
            project,
            &format!(
                "the path is not canonical (resolved to {})",
                canonical.display()
            ),
        ));
    }
    let metadata = fs::symlink_metadata(project).map_err(|error| {
        unsafe_project(project, &format!("the path cannot be inspected: {error}"))
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(unsafe_project(
            project,
            "the path is not a direct directory",
        ));
    }

    let canonical_home = home.canonicalize().map_err(|error| {
        unsafe_project(
            project,
            &format!("the account home cannot be canonicalized: {error}"),
        )
    })?;
    // `home.starts_with(project)` rejects `/`, `/home`, HOME, and any other
    // ancestor capable of exposing more than the declared project.  Requiring
    // the reverse strict relationship keeps external/broad trees out too.
    if canonical_home.starts_with(project) {
        return Err(unsafe_project(
            project,
            "the project is the account home or one of its ancestors",
        ));
    }

    if !project.starts_with(&canonical_home) {
        return Err(unsafe_project(
            project,
            "the canonical project is not strictly below the invoking user's home",
        ));
    }

    for root in [
        "/etc", "/usr", "/run", "/var", "/proc", "/sys", "/dev", "/boot", "/root", "/opt", "/srv",
        "/mnt", "/media",
    ] {
        if project.starts_with(root) {
            return Err(unsafe_project(
                project,
                &format!("the canonical target is inside reserved control root {root}"),
            ));
        }
    }
    for sensitive in [".ssh", ".aws", ".gnupg", ".config", ".local", ".cache"] {
        let root = canonical_home.join(sensitive);
        if project.starts_with(&root) {
            return Err(unsafe_project(
                project,
                &format!("the canonical target is inside sensitive account state {sensitive}"),
            ));
        }
    }

    let uid = rustix::process::getuid().as_raw();
    let mut directory = project;
    loop {
        let metadata = fs::symlink_metadata(directory).map_err(|error| {
            unsafe_project(
                project,
                &format!(
                    "ancestor {} cannot be inspected: {error}",
                    directory.display()
                ),
            )
        })?;
        let mode = metadata.permissions().mode();
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(unsafe_project(
                project,
                &format!("ancestor {} is not a direct directory", directory.display()),
            ));
        }
        if metadata.uid() != uid {
            return Err(unsafe_project(
                project,
                &format!(
                    "ancestor {} is owned by uid {}, expected invoking uid {uid}",
                    directory.display(),
                    metadata.uid()
                ),
            ));
        }
        if mode & 0o022 != 0 {
            return Err(unsafe_project(
                project,
                &format!(
                    "ancestor {} is writable by group or others (mode {:o})",
                    directory.display(),
                    mode & 0o7777
                ),
            ));
        }
        if directory == canonical_home {
            break;
        }
        directory = directory.parent().ok_or_else(|| {
            unsafe_project(project, "the ancestor walk did not reach the account home")
        })?;
    }
    Ok(())
}

/// punar-netd resolves a managed session's manifest and policy at
/// `<account home>/<project name>` (its `ProjectLocator`). Any other layout
/// is compiled as `deny_all` with a warning the launcher never sees, so the
/// launcher refuses it outright: a session that prints an exact enforced
/// rule must be the session netd actually located.
pub fn require_netd_locatable_project(
    project: &Path,
    home: &Path,
    name: &str,
) -> Result<(), EnvError> {
    let canonical_home = home.canonicalize().map_err(|error| {
        unsafe_project(
            project,
            &format!("the account home cannot be canonicalized: {error}"),
        )
    })?;
    let expected = canonical_home.join(name);
    if project != expected {
        return Err(EnvError::Usage(format!(
            "punar-env: refused project '{name}' at {}.\n\
             Why: punar-netd locates a managed session's network policy at {}, so a launch \
             from any other directory would run against a deny-all fallback while the launch \
             block claims an exact rule.\n\
             Next step: keep the project at {} or change project.name in \
             project-environment.yaml to match its directory.",
            project.display(),
            expected.display(),
            expected.display()
        )));
    }
    Ok(())
}

fn unsafe_project(project: &Path, reason: &str) -> EnvError {
    EnvError::Runtime(format!(
        "managed AI isolation refused project directory {}: {reason}.\n\
         Binding a broad or ambiguous host tree at /workspace would defeat the session boundary.\n\
         Next step: choose one canonical project directory below your home, outside credential and configuration folders.",
        project.display()
    ))
}

fn require_private_runtime(path: &Path, uid: u32) -> Result<(), EnvError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        EnvError::Runtime(format!(
            "managed AI isolation needs the private user runtime directory {}: {error}.\n\
             There is no fallback to HOME or /tmp.\n\
             Next step: log in through the Punar desktop session and retry.",
            path.display()
        ))
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != uid {
        return Err(EnvError::Runtime(format!(
            "managed AI isolation refused {} because it is not a direct directory owned by uid {uid}.\n\
             Next step: log out, log back in, and retry.",
            path.display()
        )));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(EnvError::Runtime(format!(
            "managed AI isolation refused {} because group or other users can access it.\n\
             Next step: restore the login runtime directory to mode 0700 and retry.",
            path.display()
        )));
    }
    Ok(())
}

fn create_or_validate_private_dir(path: &Path, uid: u32) -> Result<(), EnvError> {
    if !path.exists() {
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        match builder.create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(EnvError::Runtime(format!(
                    "cannot create managed-agent state directory {}: {error}.",
                    path.display()
                )));
            }
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        EnvError::Runtime(format!(
            "cannot inspect managed-agent state directory {}: {error}.",
            path.display()
        ))
    })?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(EnvError::Runtime(format!(
            "managed-agent state directory {} is not a private direct directory owned by uid {uid}.\n\
             Next step: restore it to owner uid {uid}, mode 0700, and retry.",
            path.display()
        )));
    }
    Ok(())
}

fn create_private_child(path: &Path) -> Result<(), EnvError> {
    let mut builder = DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(path).map_err(|error| {
        EnvError::Runtime(format!(
            "cannot prepare isolated agent directory {}: {error}.",
            path.display()
        ))
    })?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
        EnvError::Runtime(format!(
            "cannot protect isolated agent directory {}: {error}.",
            path.display()
        ))
    })
}

fn validated_home_destination() -> Result<(PathBuf, String), EnvError> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            EnvError::Runtime(
                "managed AI isolation needs an absolute HOME destination.\n\
                 The real home is never mounted; its path is used only so passwd-aware tools \
                 see the private replacement at the expected location."
                    .to_string(),
            )
        })?;
    let components: Vec<Component<'_>> = home.components().collect();
    let [
        Component::RootDir,
        Component::Normal(parent),
        Component::Normal(user),
    ] = components.as_slice()
    else {
        return Err(EnvError::Runtime(format!(
            "managed AI isolation refused HOME {} because Punar user homes must be /home/<user>.\n\
             Next step: correct the account home directory and retry.",
            home.display()
        )));
    };
    if *parent != OsStr::new("home") {
        return Err(EnvError::Runtime(format!(
            "managed AI isolation refused HOME {} because Punar user homes must be /home/<user>.\n\
             Next step: correct the account home directory and retry.",
            home.display()
        )));
    }
    let user_name = user
        .to_str()
        .filter(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
        .map(str::to_string);
    let Some(user_name) = user_name else {
        return Err(EnvError::Runtime(
            "managed AI isolation refused the account name because it is not a simple UTF-8 user name."
                .to_string(),
        ));
    };
    Ok((home, user_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn mounts(root: &Path) -> SandboxMounts {
        SandboxMounts {
            home_source: root.join("home"),
            runtime_source: root.join("runtime"),
            denied_workspace_source: root.join("no-workspace"),
            home_destination: PathBuf::from("/home/punar"),
            runtime_destination: PathBuf::from("/run/user/1000"),
            user_name: "punar".to_string(),
            session_id: "agt_4f21c09ab3e1".to_string(),
        }
    }

    fn command(argv: &[&str], private: Option<&Path>) -> ResolvedCommand {
        ResolvedCommand {
            argv: argv.iter().map(OsString::from).collect(),
            private_executable: private.map(PathBuf::from),
        }
    }

    fn strings(argv: &[OsString]) -> Vec<String> {
        argv.iter()
            .map(|item| item.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn argv_has_exact_namespace_mount_environment_and_separator_shape() {
        let root = Path::new("/run/user/1000/punar-agent-sessions/agt_4f21c09ab3e1");
        let argv = strings(&bubblewrap_argv(
            &mounts(root),
            Path::new("/home/punar/atlas"),
            FilesystemAccess::ReadWrite,
            &command(&["/usr/lib/punar/punar-mock-agent", "--fixed"], None),
            false,
        ));
        assert_eq!(argv[0], BWRAP_PATH);
        assert_eq!(
            &argv[1..9],
            [
                "--die-with-parent",
                "--new-session",
                "--unshare-pid",
                "--unshare-ipc",
                "--unshare-uts",
                "--hostname",
                "punar-agent",
                "--cap-drop",
            ]
        );
        assert_eq!(argv[9], "ALL");
        assert_eq!(argv[10], "--clearenv");

        for required in [
            ["--ro-bind", "/usr", "/usr"],
            ["--ro-bind", "/etc", "/etc"],
            ["--proc", "/proc", "--dev"],
            [
                "--bind",
                "/run/user/1000/punar-agent-sessions/agt_4f21c09ab3e1/runtime",
                "/run/user/1000",
            ],
            [
                "--bind",
                "/run/user/1000/punar-agent-sessions/agt_4f21c09ab3e1/home",
                "/home/punar",
            ],
            ["--tmpfs", "/tmp", "--bind"],
            ["--bind", "/home/punar/atlas", SANDBOX_WORKSPACE],
            ["--chdir", SANDBOX_WORKSPACE, "--"],
        ] {
            assert!(
                argv.windows(3).any(|window| window == required),
                "{required:?} missing from {argv:?}"
            );
        }
        assert!(
            argv.windows(3)
                .any(|window| window == ["--setenv", "HOME", "/home/punar"])
        );
        assert!(
            argv.windows(3)
                .any(|window| window == ["--setenv", "XDG_RUNTIME_DIR", "/run/user/1000"])
        );
        assert!(
            argv.windows(3)
                .any(|window| window == ["--setenv", "PUNAR_PROJECT_DIR", "/workspace"])
        );

        let separator = argv.iter().rposition(|item| item == "--").unwrap();
        assert_eq!(
            &argv[separator + 1..],
            ["/usr/lib/punar/punar-mock-agent", "--fixed"]
        );
    }

    #[test]
    fn real_home_sensitive_paths_and_user_session_sockets_are_never_mounted() {
        let argv = strings(&bubblewrap_argv(
            &mounts(Path::new("/run/private/session")),
            Path::new("/home/punar/atlas"),
            FilesystemAccess::ReadWrite,
            &command(&["/usr/bin/true"], None),
            false,
        ));
        let joined = argv.join("\n");
        for forbidden in [
            "/home/punar/.ssh",
            "/home/punar/.aws",
            "/home/punar/.config/systemd",
            "/run/user/1000/bus",
            "/run/user/1000/systemd",
            "/run/punar-agentd/agentd.sock",
            "/run/punar-netd/netd.sock",
            "/run/punard/punard.sock",
            "/run/punar-secrets/secrets.sock",
            "DBUS_SESSION_BUS_ADDRESS",
            "SSH_AUTH_SOCK",
            "AWS_",
        ] {
            assert!(
                !joined.contains(forbidden),
                "forbidden mount/env {forbidden}: {argv:?}"
            );
        }
        assert!(!argv.windows(3).any(|window| {
            matches!(window[0].as_str(), "--bind" | "--ro-bind" | "--ro-bind-try")
                && window[1] == "/run/user/1000"
        }));
    }

    #[test]
    fn every_filesystem_grade_maps_to_a_kernel_mount_decision() {
        let root = Path::new("/run/private/session");
        let command = command(&["/usr/bin/true"], None);
        let rw = strings(&bubblewrap_argv(
            &mounts(root),
            Path::new("/project"),
            FilesystemAccess::ReadWrite,
            &command,
            false,
        ));
        assert!(
            rw.windows(3)
                .any(|w| w == ["--bind", "/project", "/workspace"])
        );

        let read = strings(&bubblewrap_argv(
            &mounts(root),
            Path::new("/project"),
            FilesystemAccess::Read,
            &command,
            false,
        ));
        assert!(
            read.windows(3)
                .any(|w| w == ["--ro-bind", "/project", "/workspace"])
        );

        let deny = strings(&bubblewrap_argv(
            &mounts(root),
            Path::new("/project"),
            FilesystemAccess::Deny,
            &command,
            false,
        ));
        assert!(deny.windows(3).any(|w| {
            w == [
                "--ro-bind",
                "/run/private/session/no-workspace",
                "/workspace",
            ]
        }));
        assert!(!deny.iter().any(|item| item == "/project"));
    }

    #[test]
    fn a_user_installed_agent_exposes_only_its_resolved_file() {
        let argv = strings(&bubblewrap_argv(
            &mounts(Path::new("/run/private/session")),
            Path::new("/project"),
            FilesystemAccess::ReadWrite,
            &command(
                &[SANDBOX_AGENT, "--argument"],
                Some(Path::new("/home/punar/.local/bin/claude-real")),
            ),
            false,
        ));
        assert!(argv.windows(3).any(|window| {
            window
                == [
                    "--ro-bind",
                    "/home/punar/.local/bin/claude-real",
                    SANDBOX_AGENT,
                ]
        }));
        assert!(!argv.windows(3).any(|window| {
            matches!(window[0].as_str(), "--bind" | "--ro-bind" | "--ro-bind-try")
                && window[1] == "/home/punar"
        }));
        let separator = argv.iter().rposition(|item| item == "--").unwrap();
        assert_eq!(&argv[separator + 1..], [SANDBOX_AGENT, "--argument"]);
        // The signal-reset stage sits between Bubblewrap's separator and the
        // adapter, so only the adapter regains the default SIGTERM.
        assert_eq!(
            &argv[separator - 2..separator],
            [ENV_PATH, "--default-signal=TERM"]
        );
        assert_eq!(argv[separator - 3], "--");
    }

    #[test]
    fn every_supported_desktop_image_keeps_the_required_isolation_primitive() {
        const DESKTOP_PROFILES: [(&str, &str); 3] = [
            (
                "Arch x86_64",
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../os/images/mkosi.profiles/desktop/mkosi.conf"
                )),
            ),
            (
                "Arch ARM64",
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../os/images/arm64/mkosi.profiles/desktop/mkosi.conf"
                )),
            ),
            (
                "Debian x86_64",
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../os/images/amd64-debian/mkosi.profiles/desktop/mkosi.conf"
                )),
            ),
        ];
        for (profile, configuration) in DESKTOP_PROFILES {
            assert!(
                configuration
                    .lines()
                    .any(|line| line.trim() == "bubblewrap"),
                "{profile} dropped the fail-closed {BWRAP_PATH} runtime dependency"
            );
        }
    }

    #[test]
    fn missing_or_non_executable_bubblewrap_has_no_unsandboxed_fallback() {
        let root =
            std::env::temp_dir().join(format!("punar-env-bwrap-preflight-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let missing = require_bubblewrap(&root.join("missing")).unwrap_err();
        assert!(
            missing
                .to_string()
                .contains("There is no unsandboxed fallback"),
            "{missing}"
        );

        let inert = root.join("bwrap");
        fs::write(&inert, "not executable").unwrap();
        fs::set_permissions(&inert, fs::Permissions::from_mode(0o644)).unwrap();
        let unsafe_binary = require_bubblewrap(&inert).unwrap_err();
        assert!(unsafe_binary.to_string().contains("immutable tool check"));
        assert!(
            unsafe_binary
                .to_string()
                .contains("There is no unsandboxed fallback"),
            "{unsafe_binary}"
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn trusted_tool_check_rejects_writable_symlinked_and_unsafe_hierarchies() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().canonicalize().unwrap();
        let root = base.join(format!("punar-env-tool-trust-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(root.join("usr"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(root.join("usr/bin"), fs::Permissions::from_mode(0o755)).unwrap();
        let tool = root.join("usr/bin/tool");
        fs::write(&tool, "tool").unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
        let uid = rustix::process::getuid().as_raw();

        validate_trusted_executable(&tool, uid, &root).unwrap();

        fs::set_permissions(&tool, fs::Permissions::from_mode(0o775)).unwrap();
        let error = validate_trusted_executable(&tool, uid, &root).unwrap_err();
        assert!(error.contains("writable by group"), "{error}");
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();

        fs::set_permissions(root.join("usr"), fs::Permissions::from_mode(0o777)).unwrap();
        let error = validate_trusted_executable(&tool, uid, &root).unwrap_err();
        assert!(
            error.contains("ancestor") && error.contains("writable"),
            "{error}"
        );
        fs::set_permissions(root.join("usr"), fs::Permissions::from_mode(0o755)).unwrap();

        let link = root.join("usr/bin/tool-link");
        symlink(&tool, &link).unwrap();
        let error = validate_trusted_executable(&link, uid, &root).unwrap_err();
        assert!(error.contains("not canonical"), "{error}");
        let noncanonical = root.join("usr/bin/../bin/tool");
        let error = validate_trusted_executable(&noncanonical, uid, &root).unwrap_err();
        assert!(error.contains("not canonical"), "{error}");

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn netd_locatable_project_must_be_home_slash_name() {
        let base = std::env::temp_dir().canonicalize().unwrap();
        let root = base.join(format!("punar-env-netd-locate-{}", std::process::id()));
        let home = root.join("home");
        let atlas = home.join("atlas");
        let elsewhere = home.join("code").join("atlas");
        fs::create_dir_all(&atlas).unwrap();
        fs::create_dir_all(&elsewhere).unwrap();
        require_netd_locatable_project(&atlas, &home, "atlas").unwrap();
        let error = require_netd_locatable_project(&elsewhere, &home, "atlas").unwrap_err();
        assert!(
            error.to_string().contains("refused project 'atlas'"),
            "{error}"
        );
        let error = require_netd_locatable_project(&atlas, &home, "other").unwrap_err();
        assert!(
            error.to_string().contains("refused project 'other'"),
            "{error}"
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn project_mount_must_be_a_private_canonical_home_descendant() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().canonicalize().unwrap();
        let root = base.join(format!("punar-env-project-trust-{}", std::process::id()));
        let home = root.join("home");
        let source_root = home.join("src");
        let project = source_root.join("project");
        fs::create_dir_all(&project).unwrap();
        for directory in [&root, &home, &source_root, &project] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        validate_project_mount(&project, &home).unwrap();

        for broad in [Path::new("/"), Path::new("/home"), home.as_path()] {
            let error = validate_project_mount(broad, &home).unwrap_err();
            assert!(error.to_string().contains("refused project"), "{error}");
        }
        for control in ["/etc", "/usr", "/run", "/var"] {
            let error = validate_project_mount(Path::new(control), &home).unwrap_err();
            assert!(error.to_string().contains("refused project"), "{error}");
        }

        let ssh = home.join(".ssh/project");
        fs::create_dir_all(&ssh).unwrap();
        fs::set_permissions(home.join(".ssh"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(validate_project_mount(&ssh, &home).is_err());

        let link = home.join("linked-project");
        symlink(&project, &link).unwrap();
        let error = validate_project_mount(&link, &home).unwrap_err();
        assert!(error.to_string().contains("not canonical"), "{error}");
        // Canonicalizing a symlink to the entire home does not bypass the
        // broad-parent check either.
        let home_link = root.join("home-link");
        symlink(&home, &home_link).unwrap();
        let target = home_link.canonicalize().unwrap();
        assert!(validate_project_mount(&target, &home).is_err());

        fs::set_permissions(&source_root, fs::Permissions::from_mode(0o770)).unwrap();
        let error = validate_project_mount(&project, &home).unwrap_err();
        assert!(error.to_string().contains("writable by group"), "{error}");

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn hostile_adapter_arguments_cannot_reach_bwrap_options() {
        let argv = strings(&bubblewrap_argv(
            &mounts(Path::new("/run/private/session")),
            Path::new("/project"),
            FilesystemAccess::ReadWrite,
            &command(
                &["/usr/bin/agent", "--ro-bind", "/", "/", "; rm -rf /"],
                None,
            ),
            false,
        ));
        let separator = argv.iter().rposition(|item| item == "--").unwrap();
        assert_eq!(
            &argv[separator + 1..],
            ["/usr/bin/agent", "--ro-bind", "/", "/", "; rm -rf /"]
        );
        assert_eq!(
            argv[..separator]
                .windows(3)
                .filter(|window| *window == ["--ro-bind", "/", "/"])
                .count(),
            0
        );
    }

    #[test]
    fn private_environment_is_a_closed_allowlist() {
        let argv = strings(&bubblewrap_argv(
            &mounts(Path::new("/run/private/session")),
            Path::new("/project"),
            FilesystemAccess::ReadWrite,
            &command(&["/usr/bin/true"], None),
            false,
        ));
        let keys: Vec<&str> = argv
            .windows(3)
            .filter(|window| window[0] == "--setenv")
            .map(|window| window[1].as_str())
            .collect();
        assert_eq!(
            keys,
            [
                "HOME",
                "USER",
                "LOGNAME",
                "PATH",
                "LANG",
                "LC_ALL",
                "TERM",
                "TMPDIR",
                "XDG_CONFIG_HOME",
                "XDG_CACHE_HOME",
                "XDG_DATA_HOME",
                "XDG_STATE_HOME",
                "XDG_RUNTIME_DIR",
                "PUNAR_AGENT_SESSION_ID",
                "PUNAR_PROJECT_DIR",
            ]
        );
    }

    #[test]
    fn hostile_child_is_confined_when_running_on_a_bubblewrap_host() {
        if !cfg!(target_os = "linux") || !Path::new(BWRAP_PATH).is_file() {
            return;
        }
        let root =
            std::env::temp_dir().join(format!("punar-env-bwrap-hostile-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for path in [
            root.join("home"),
            root.join("runtime"),
            root.join("no-workspace"),
            root.join("project"),
            root.join("other-project"),
            root.join("real-home"),
        ] {
            fs::create_dir_all(path).unwrap();
        }
        let outside_secret = root.join("outside-secret");
        let other_project_secret = root.join("other-project/secret");
        let real_profile = root.join("real-home/.profile");
        fs::write(&outside_secret, "must-not-be-visible").unwrap();
        fs::write(&other_project_secret, "other-project").unwrap();
        fs::write(&real_profile, "host-profile").unwrap();
        fs::write(root.join("project/inside"), "project-data").unwrap();
        let mut test_mounts = mounts(&root);
        test_mounts.home_destination = PathBuf::from("/home/punar");
        test_mounts.runtime_destination = PathBuf::from("/run/user/1000");
        let script = format!(
            concat!(
                "set -eu; ",
                "test \"$(cat /workspace/inside)\" = project-data; ",
                "printf changed > /workspace/written; ",
                "printf private > \"$HOME/state\"; ",
                "printf ephemeral > \"$HOME/.profile\"; ",
                "printf temp > /tmp/session-only; ",
                "test ! -e /run/user/1000/bus; ",
                "test ! -e /run/user/1000/systemd/private; ",
                "test ! -e /run/punar-agentd/agentd.sock; ",
                "test ! -e /run/punar-netd/netd.sock; ",
                "test ! -e /run/punard/punard.sock; ",
                "test ! -e /run/punar-secrets/secrets.sock; ",
                "test ! -e /home/punar/.ssh/id_ed25519; ",
                "test ! -e /home/punar/.aws/credentials; ",
                "test ! -e {outside}; ",
                "test ! -e {other_project}; ",
                "test ! -e {real_profile}; ",
                "test ! -w /usr"
            ),
            outside = outside_secret.display(),
            other_project = other_project_secret.display(),
            real_profile = real_profile.display(),
        );
        let argv = bubblewrap_argv(
            &test_mounts,
            &root.join("project"),
            FilesystemAccess::ReadWrite,
            &command(&["/bin/sh", "-c", &script], None),
            false,
        );
        let output = Command::new(&argv[0]).args(&argv[1..]).output().unwrap();
        assert!(
            output.status.success(),
            "hostile child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(root.join("project/written")).unwrap(),
            "changed"
        );
        assert_eq!(
            fs::read_to_string(root.join("home/state")).unwrap(),
            "private"
        );
        assert_eq!(
            fs::read_to_string(outside_secret).unwrap(),
            "must-not-be-visible"
        );
        assert_eq!(
            fs::read_to_string(other_project_secret).unwrap(),
            "other-project"
        );
        assert_eq!(fs::read_to_string(real_profile).unwrap(), "host-profile");
        assert_eq!(
            fs::read_to_string(root.join("home/.profile")).unwrap(),
            "ephemeral"
        );
        let _ = fs::remove_dir_all(&root);
    }
}
