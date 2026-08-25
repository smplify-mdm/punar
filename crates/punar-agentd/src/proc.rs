//! The `/proc` reader behind registration verification (spec section 22)
//! and detection (spec section 23).
//!
//! # Injectable root
//!
//! Every read goes through [`ProcRoot`], whose root directory is
//! configuration (`/proc` in production, a fixture tree in tests). That is
//! the whole test seam: a fixture `/proc` is a directory of numeric
//! subdirectories holding `comm`, `cmdline`, `cgroup`, `status`, and an
//! `exe` symlink — the same five files the daemon reads on a real kernel,
//! so the parsing under test is the parsing that ships.
//!
//! # What is deliberately *not* kept
//!
//! The walker reads `cmdline` because the hero-demo suspect is a **shell
//! script**: for a script, `/proc/<pid>/exe` points at the interpreter
//! (`/bin/sh`), and the only place the script's own path appears is the
//! argument vector. But an AI agent's argument vector can contain a
//! *prompt*, and spec section 53 forbids logging prompt contents. So the
//! command line never leaves this module: [`ProcEntry`] keeps only the
//! absolute-path arguments (`argv_paths`), and only the single path that
//! actually matched a signature is ever stored, displayed, or audited.
//! Nothing anywhere in `punar-agentd` holds a full command line.
//!
//! This is a deliberate, narrower reading than the milestone plan's
//! "comm/exe/cmdline/uid/cgroup" shorthand — narrower in what is retained,
//! identical in what is inspected.

use std::path::PathBuf;

/// One process as the detector sees it. Cheap: five small reads, no
/// allocations beyond the strings kept below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcEntry {
    pub pid: u32,
    /// `/proc/<pid>/comm` — the kernel's 15-char task name.
    pub comm: String,
    /// `/proc/<pid>/exe` target, when readable (another user's process on
    /// a hardened kernel may hide it; agentd normally runs as root).
    pub exe: Option<String>,
    /// Absolute-path arguments only — see the module note on prompts.
    pub argv_paths: Vec<String>,
    /// Owner uid from `/proc/<pid>/status` (`Uid:` line, real uid).
    pub uid: Option<u32>,
    /// `/proc/<pid>/cgroup`, verbatim — the attribution chain (spec 22).
    pub cgroup: String,
}

impl ProcEntry {
    /// The best available path for display: the executable when the kernel
    /// gave one, else the first absolute argument, else the `comm` name.
    pub fn display_path(&self) -> String {
        self.exe
            .clone()
            .or_else(|| self.argv_paths.first().cloned())
            .unwrap_or_else(|| self.comm.clone())
    }

    /// Every path this process can be matched against: the executable and
    /// its absolute arguments (the script case).
    pub fn candidate_paths(&self) -> Vec<&str> {
        let mut paths: Vec<&str> = Vec::new();
        if let Some(exe) = self.exe.as_deref() {
            paths.push(exe);
        }
        paths.extend(self.argv_paths.iter().map(String::as_str));
        paths
    }

    /// Whether this process runs inside a managed agent scope
    /// (`punar-agent-<id>.scope`) — the cgroup half of spec section 22
    /// attribution.
    pub fn in_managed_scope(&self) -> bool {
        self.cgroup.contains("punar-agent-")
    }

    /// Whether the cgroup names this specific session's scope.
    pub fn in_scope_of(&self, session_id: &str) -> bool {
        self.cgroup.contains(&scope_unit_name(session_id))
    }
}

/// The transient systemd scope a managed session runs in
/// (`punar-env` creates it with `systemd-run --user --scope --unit=…`).
pub fn scope_unit_name(session_id: &str) -> String {
    format!("punar-agent-{session_id}.scope")
}

/// A `/proc` tree — the real one, or a fixture in tests.
#[derive(Debug, Clone)]
pub struct ProcRoot {
    root: PathBuf,
}

impl ProcRoot {
    pub fn new(root: impl Into<PathBuf>) -> ProcRoot {
        ProcRoot { root: root.into() }
    }

    fn pid_dir(&self, pid: u32) -> PathBuf {
        self.root.join(pid.to_string())
    }

    /// Whether the kernel still knows this pid.
    pub fn is_alive(&self, pid: u32) -> bool {
        self.pid_dir(pid).is_dir()
    }

    /// Every numeric entry in the tree, ascending. Non-numeric entries
    /// (`self`, `sys`, …) are skipped.
    pub fn pids(&self) -> Vec<u32> {
        let Ok(entries) = std::fs::read_dir(&self.root) else {
            return Vec::new();
        };
        let mut pids: Vec<u32> = entries
            .flatten()
            .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
            .collect();
        pids.sort_unstable();
        pids
    }

    /// Owner uid of a process: the real uid from the `status` file, with
    /// the directory's own owner as fallback (both are what `ps` uses).
    pub fn uid_of(&self, pid: u32) -> Option<u32> {
        let status = std::fs::read_to_string(self.pid_dir(pid).join("status")).ok();
        if let Some(status) = status {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("Uid:") {
                    if let Some(real) = rest.split_whitespace().next() {
                        if let Ok(uid) = real.parse() {
                            return Some(uid);
                        }
                    }
                }
            }
        }
        std::fs::metadata(self.pid_dir(pid))
            .ok()
            .map(|meta| std::os::unix::fs::MetadataExt::uid(&meta))
    }

    /// `/proc/<pid>/cgroup`, or the empty string when unreadable — an
    /// unreadable cgroup can only ever *fail* a managed check, never pass
    /// one (fail-closed attribution).
    pub fn cgroup_of(&self, pid: u32) -> String {
        std::fs::read_to_string(self.pid_dir(pid).join("cgroup")).unwrap_or_default()
    }

    /// Full entry for one pid, or `None` if it vanished mid-walk (a race
    /// the walk simply skips).
    pub fn entry(&self, pid: u32) -> Option<ProcEntry> {
        let dir = self.pid_dir(pid);
        if !dir.is_dir() {
            return None;
        }
        let comm = std::fs::read_to_string(dir.join("comm"))
            .map(|s| s.trim_end_matches('\n').to_string())
            .unwrap_or_default();
        let exe = std::fs::read_link(dir.join("exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
            // A dead process's exe link reads as "/path (deleted)".
            .map(|p| p.trim_end_matches(" (deleted)").to_string())
            .filter(|p| !p.is_empty());
        let argv_paths = std::fs::read(dir.join("cmdline"))
            .map(|bytes| absolute_args(&bytes))
            .unwrap_or_default();
        Some(ProcEntry {
            pid,
            comm,
            exe,
            argv_paths,
            uid: self.uid_of(pid),
            cgroup: self.cgroup_of(pid),
        })
    }

    /// One walk of the whole tree.
    pub fn walk(&self) -> Vec<ProcEntry> {
        self.pids()
            .into_iter()
            .filter_map(|pid| self.entry(pid))
            .collect()
    }
}

/// Extract the absolute-path arguments from a NUL-separated `cmdline`.
/// Everything else in the vector — flags, prompts, free text — is dropped
/// here and never held (module note; spec section 53).
fn absolute_args(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(bytes)
        .split('\0')
        .filter(|arg| arg.starts_with('/'))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::{fake_process, fixture_proc};

    #[test]
    fn walks_a_fixture_tree_and_parses_every_field() {
        let root = fixture_proc("walk");
        fake_process(
            &root,
            2143,
            "claude",
            "/usr/bin/claude",
            &["/usr/bin/claude"],
            1000,
            "/user.slice/user-1000.slice/user@1000.service/app.slice/punar-agent-agt_4f21c09ab3e1.scope",
        );
        fake_process(
            &root,
            2410,
            "foo-agent",
            "/usr/bin/dash",
            &["/bin/sh", "/home/punar/Downloads/foo-agent"],
            1000,
            "/user.slice/user-1000.slice/session-3.scope",
        );
        // Non-numeric entries are ignored.
        std::fs::create_dir_all(root.join("sys")).unwrap();

        let proc = ProcRoot::new(&root);
        assert_eq!(proc.pids(), vec![2143, 2410]);

        let claude = proc.entry(2143).unwrap();
        assert_eq!(claude.comm, "claude");
        assert_eq!(claude.exe.as_deref(), Some("/usr/bin/claude"));
        assert_eq!(claude.uid, Some(1000));
        assert!(claude.in_managed_scope());
        assert!(claude.in_scope_of("agt_4f21c09ab3e1"));
        assert!(!claude.in_scope_of("agt_deadbeef0000"));

        let suspect = proc.entry(2410).unwrap();
        assert_eq!(suspect.exe.as_deref(), Some("/usr/bin/dash"));
        // The script path survives only as an absolute argument.
        assert_eq!(
            suspect.argv_paths,
            vec![
                "/bin/sh".to_string(),
                "/home/punar/Downloads/foo-agent".to_string()
            ]
        );
        assert!(!suspect.in_managed_scope());
        assert!(proc.is_alive(2410));
        assert!(!proc.is_alive(9999));
        assert!(proc.entry(9999).is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn command_lines_are_filtered_down_to_paths_only() {
        // The prompt-shaped argument must not survive the read at all.
        let cmdline = b"claude\0--print\0summarize the secret quarterly numbers\0/srv/atlas\0";
        assert_eq!(absolute_args(cmdline), vec!["/srv/atlas".to_string()]);
    }

    #[test]
    fn scope_unit_name_matches_the_launcher_convention() {
        assert_eq!(
            scope_unit_name("agt_4f21c09ab3e1"),
            "punar-agent-agt_4f21c09ab3e1.scope"
        );
    }
}
