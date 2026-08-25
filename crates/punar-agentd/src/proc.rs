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

    /// The absolute cgroup path of this session's scope, as it appears
    /// after the hierarchy prefix in `/proc/<pid>/cgroup`
    /// (`/user.slice/…/punar-agent-<id>.scope`) — what the M8 ledger
    /// samples `cgroup.procs` and `pids.peak` from
    /// (`crate::ledger::classes`). `None` when this process is not in
    /// the session's scope, so the sampler can never be pointed at a
    /// cgroup that does not belong to the session.
    pub fn scope_path_of(&self, session_id: &str) -> Option<String> {
        let unit = scope_unit_name(session_id);
        self.cgroup.lines().find_map(|line| {
            if !line.contains(&unit) {
                return None;
            }
            // v2: "0::/user.slice/…"; v1: "N:controller:/user.slice/…".
            let path = line.rsplit_once(':').map(|(_, rest)| rest).unwrap_or(line);
            path.starts_with('/').then(|| path.trim().to_string())
        })
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

    /// `/proc/<pid>/comm` alone — the one field the AI Access Ledger
    /// reads about a process in an agent scope (milestone-8.md section
    /// 3.2). Deliberately narrower than [`ProcRoot::entry`]: the ledger
    /// must never touch `cmdline`, and the `comm` it does read is mapped
    /// through the class table and discarded, never stored.
    pub fn comm_of(&self, pid: u32) -> Option<String> {
        let comm = std::fs::read_to_string(self.pid_dir(pid).join("comm")).ok()?;
        let comm = comm.trim_end_matches('\n').trim().to_string();
        (!comm.is_empty()).then_some(comm)
    }

    /// Field 22 of `/proc/<pid>/stat` — the kernel's `starttime` in clock
    /// ticks since boot. Paired with the pid it makes a dedup key that
    /// pid reuse cannot forge, so a long session cannot inflate a class
    /// count by recycling numbers.
    ///
    /// The `comm` field of `stat` is parenthesized and may itself contain
    /// spaces or `)`, so parsing starts after the **last** `)`, which is
    /// the only correct way to read this file.
    pub fn starttime_of(&self, pid: u32) -> Option<u64> {
        let stat = std::fs::read_to_string(self.pid_dir(pid).join("stat")).ok()?;
        let tail = &stat[stat.rfind(')')? + 1..];
        // After the closing paren, field 3 (state) is the first token, so
        // starttime (field 22) is token index 19.
        tail.split_whitespace().nth(19)?.parse().ok()
    }

    /// `/proc/sys/kernel/random/boot_id` — the kernel's per-boot UUID
    /// (milestone-10.md section 4.1).
    ///
    /// Read **once per pass**, not once per pid: it cannot change while
    /// the daemon runs. It scopes a detection identity to this boot, which
    /// is what makes `starttime` — a count of ticks *since boot* — a
    /// usable identity field at all. `None` when the kernel does not
    /// expose it; the caller then uses the empty string, and the identity
    /// degrades to `(exe, uid, pid, starttime)`, which is still
    /// pid-reuse-safe within one boot.
    pub fn boot_id(&self) -> Option<String> {
        let text = std::fs::read_to_string(self.root.join("sys/kernel/random/boot_id")).ok()?;
        let id = text.trim().to_string();
        (!id.is_empty()).then_some(id)
    }

    /// The `btime` line of `/proc/stat` — wall-clock Unix seconds at
    /// boot. Combined with a process's `starttime` ticks it gives the
    /// process's **own** start time (milestone-10.md section 6.4), which
    /// is what a detection record's `started_at` means from M10 onward.
    /// `None` when unreadable; the caller falls back to the observation
    /// time and says so rather than inventing a start.
    pub fn boot_time_unix(&self) -> Option<u64> {
        let stat = std::fs::read_to_string(self.root.join("stat")).ok()?;
        stat.lines()
            .find_map(|line| line.strip_prefix("btime "))
            .and_then(|value| value.trim().parse().ok())
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
        assert_eq!(
            claude.scope_path_of("agt_4f21c09ab3e1").as_deref(),
            Some(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/punar-agent-agt_4f21c09ab3e1.scope"
            )
        );
        assert_eq!(claude.scope_path_of("agt_deadbeef0000"), None);

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
    fn stat_parsing_survives_a_comm_containing_spaces_and_parens() {
        let root = fixture_proc("stat");
        let dir = root.join("77");
        std::fs::create_dir_all(&dir).unwrap();
        // A real /proc/<pid>/stat line: fields 1..=22, with a hostile comm.
        let fields: Vec<String> = (3..=22)
            .map(|n| match n {
                3 => "S".to_string(),
                22 => "918273".to_string(),
                other => other.to_string(),
            })
            .collect();
        std::fs::write(
            dir.join("stat"),
            format!("77 (we ird) name) {}\n", fields.join(" ")),
        )
        .unwrap();
        std::fs::write(dir.join("comm"), "we ird) name\n").unwrap();

        let proc = ProcRoot::new(&root);
        assert_eq!(proc.starttime_of(77), Some(918_273));
        assert_eq!(proc.comm_of(77).as_deref(), Some("we ird) name"));
        assert_eq!(proc.starttime_of(78), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The two system-wide reads M10 adds: once per pass, never per pid.
    #[test]
    fn kernel_boot_facts_are_read_once_and_degrade_honestly() {
        let root = fixture_proc("bootfacts");
        let proc = ProcRoot::new(&root);
        assert_eq!(
            proc.boot_id().as_deref(),
            Some(crate::testsupport::FIXTURE_BOOT_ID)
        );
        assert_eq!(
            proc.boot_time_unix(),
            Some(crate::testsupport::FIXTURE_BTIME)
        );

        // A kernel that exposes neither must not make the daemon invent
        // one: both degrade to None.
        let bare = fixture_proc("bootfacts-bare");
        std::fs::remove_file(bare.join("sys/kernel/random/boot_id")).unwrap();
        std::fs::write(bare.join("stat"), "cpu 1 2 3\n").unwrap();
        let bare_proc = ProcRoot::new(&bare);
        assert_eq!(bare_proc.boot_id(), None);
        assert_eq!(bare_proc.boot_time_unix(), None);

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&bare);
    }

    #[test]
    fn scope_unit_name_matches_the_launcher_convention() {
        assert_eq!(
            scope_unit_name("agt_4f21c09ab3e1"),
            "punar-agent-agt_4f21c09ab3e1.scope"
        );
    }
}
