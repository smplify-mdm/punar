//! Source **A** of the ledger: the agent scope's cgroup, and the
//! `comm` → process-class table that turns what it names into a class
//! (milestone-8.md section 3.2; spec sections 21.1, 22).
//!
//! # Why this is not tracing
//!
//! Punar already owns this mediation point: `punar-env` creates the
//! transient scope `punar-agent-<id>.scope`, and `agents.register`
//! already reads `/proc/<pid>/cgroup` to *prove* the managed
//! classification (M7 section 4.3). Sampling `cgroup.procs` of that same
//! scope adds one `read(2)` per active session per update point. There is
//! no eBPF, no fanotify, no ptrace, no `LD_PRELOAD`, and no audit-subsystem
//! rule anywhere in this file — spec 1.14 says to prefer aggregation over
//! broad tracing, and this is what that looks like.
//!
//! # What is read, and what is kept
//!
//! Read: the scope's `cgroup.procs` and `pids.peak`, then for each pid
//! `/proc/<pid>/comm` and `starttime`. Kept: a **class name** and a
//! count. The pid, the `comm`, and the start time are dedup state in
//! memory for the session's lifetime and are never persisted — a pid is
//! not ledger data, and an unmapped `comm` becomes the literal class
//! `unknown` rather than itself, so a script named `deploy-prod-hotfix.sh`
//! cannot reach the ledger through this path.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use punar_common::ledger::CLASS_UNKNOWN;

use crate::proc::ProcRoot;

/// The shipped table, compiled in as the fallback so agentd classifies
/// correctly even before `/usr/share/punar/agents/process-classes.json`
/// is staged — and so the two copies cannot drift (the installed file is
/// this file).
const BUILTIN_PROCESS_CLASSES: &str = include_str!("../../data/process-classes.json");

/// `comm` → class. A closed vocabulary supplied as **data**, the M7
/// adapters-as-data precedent; anything unlisted is [`CLASS_UNKNOWN`].
#[derive(Debug, Clone)]
pub struct ClassTable {
    classes: BTreeMap<String, String>,
    /// Non-fatal problems worth printing once at startup rather than
    /// swallowing (the `SignatureSet::load` precedent).
    pub warnings: Vec<String>,
}

impl Default for ClassTable {
    fn default() -> ClassTable {
        ClassTable::builtin()
    }
}

impl ClassTable {
    /// The compiled-in table. Infallible: a broken build-time constant
    /// would be a compile-time problem, and the parse is proven by a test.
    pub fn builtin() -> ClassTable {
        let (classes, warnings) = parse(BUILTIN_PROCESS_CLASSES, "<built-in>");
        ClassTable { classes, warnings }
    }

    /// Load the staged table, falling back to the built-in one when the
    /// file is missing or unreadable — a missing data file degrades the
    /// vocabulary, it does not stop the daemon.
    pub fn load(path: &Path) -> ClassTable {
        let Ok(text) = std::fs::read_to_string(path) else {
            return ClassTable::builtin();
        };
        let (classes, mut warnings) = parse(&text, &path.display().to_string());
        if classes.is_empty() {
            let mut table = ClassTable::builtin();
            warnings.push(format!(
                "{}: no usable class mappings; using the built-in table",
                path.display()
            ));
            table.warnings.extend(warnings);
            return table;
        }
        ClassTable { classes, warnings }
    }

    /// Map one `comm` to its class. The `comm` itself is dropped here and
    /// never returned to the caller in any other form.
    pub fn class_of(&self, comm: &str) -> &str {
        self.classes
            .get(comm)
            .map(String::as_str)
            .unwrap_or(CLASS_UNKNOWN)
    }

    /// How many mappings the table holds (preflight/diagnostics).
    pub fn len(&self) -> usize {
        self.classes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }
}

/// Parse `{"v":1,"classes":{"git":"git",…}}`. Entries whose class name
/// would not be a valid `process_classes` value are dropped with a
/// warning rather than silently trusted: the data file is an input, and
/// the schema pattern is the contract.
fn parse(text: &str, origin: &str) -> (BTreeMap<String, String>, Vec<String>) {
    let mut warnings = Vec::new();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        warnings.push(format!("{origin}: not valid JSON; ignored"));
        return (BTreeMap::new(), warnings);
    };
    let mut classes = BTreeMap::new();
    let Some(map) = value.get("classes").and_then(serde_json::Value::as_object) else {
        warnings.push(format!("{origin}: no \"classes\" object; ignored"));
        return (classes, warnings);
    };
    for (comm, class) in map {
        let Some(class) = class.as_str() else {
            warnings.push(format!("{origin}: class for {comm:?} is not a string"));
            continue;
        };
        if punar_common::ledger::ResourceClass::new(
            punar_common::ledger::ResourceCategory::ProcessClasses,
            class,
        )
        .is_err()
        {
            warnings.push(format!(
                "{origin}: {class:?} is not a valid process class; mapping dropped"
            ));
            continue;
        }
        classes.insert(comm.clone(), class.to_string());
    }
    (classes, warnings)
}

/// One sampling point's view of a scope: the distinct processes alive in
/// it right now, and the kernel's peak-concurrency counter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeSample {
    /// `(pid, starttime)` — the dedup key pid reuse cannot forge.
    pub processes: Vec<(u32, u64)>,
    /// The class of each entry in `processes`, same order.
    pub classes: Vec<String>,
    /// `pids.peak` of the scope when the kernel exposes it. **Peak
    /// concurrent pids**, never a spawn total.
    pub peak: Option<u64>,
}

/// The cgroup filesystem — the real one, or a fixture tree in tests.
///
/// The injectable root is the whole test seam, matching
/// [`crate::proc::ProcRoot`]: a fixture cgroup is a directory holding
/// `cgroup.procs` and `pids.peak`, the same two files the sampler reads
/// on a real kernel.
#[derive(Debug, Clone)]
pub struct CgroupRoot {
    root: PathBuf,
}

impl CgroupRoot {
    pub fn new(root: impl Into<PathBuf>) -> CgroupRoot {
        CgroupRoot { root: root.into() }
    }

    /// The scope directory for a cgroup path as it appears in
    /// `/proc/<pid>/cgroup` (`/user.slice/…/punar-agent-<id>.scope`).
    fn scope_dir(&self, relative: &str) -> PathBuf {
        self.root.join(relative.trim_start_matches('/'))
    }

    /// Pids currently in the scope, or `None` when the directory is not
    /// readable (the scope died, or agentd is not privileged) — which is
    /// the caller's cue to fall back to `/proc`.
    pub fn procs(&self, relative: &str) -> Option<Vec<u32>> {
        let text = std::fs::read_to_string(self.scope_dir(relative).join("cgroup.procs")).ok()?;
        Some(
            text.lines()
                .filter_map(|line| line.trim().parse::<u32>().ok())
                .collect(),
        )
    }

    /// `pids.peak` of the scope, when the kernel exposes it (the `pids`
    /// controller must be enabled). `None` is reported honestly rather
    /// than substituted with the current count.
    pub fn peak(&self, relative: &str) -> Option<u64> {
        let text = std::fs::read_to_string(self.scope_dir(relative).join("pids.peak")).ok()?;
        text.trim().parse().ok()
    }
}

/// Read one sample of a session's scope.
///
/// Primary path: the scope's own `cgroup.procs`. Fallback, when that
/// directory cannot be read: walk `/proc` and keep the pids whose
/// `cgroup` names this session's scope. Both are the *same* kernel-attested
/// mediation point read two ways — the fallback is not a weaker claim, it
/// just costs a directory walk and cannot report `pids.peak`.
pub fn sample_scope(
    cgroups: &CgroupRoot,
    proc: &ProcRoot,
    table: &ClassTable,
    scope_path: Option<&str>,
    session_id: &str,
) -> ScopeSample {
    let (pids, peak) = match scope_path.and_then(|rel| cgroups.procs(rel).map(|p| (rel, p))) {
        Some((rel, pids)) => (pids, cgroups.peak(rel)),
        None => (
            proc.pids()
                .into_iter()
                .filter(|pid| {
                    proc.cgroup_of(*pid)
                        .contains(&crate::proc::scope_unit_name(session_id))
                })
                .collect(),
            None,
        ),
    };

    let mut sample = ScopeSample {
        peak,
        ..ScopeSample::default()
    };
    for pid in pids {
        // A pid that vanished between the two reads is skipped, not
        // guessed at.
        let Some(comm) = proc.comm_of(pid) else {
            continue;
        };
        // No starttime (a kernel that hid `stat`, or a race) degrades the
        // dedup key to `(pid, 0)`, which is still stable for this pid.
        let starttime = proc.starttime_of(pid).unwrap_or(0);
        sample.classes.push(table.class_of(&comm).to_string());
        sample.processes.push((pid, starttime));
    }
    sample
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::{
        fake_process, fixture_cgroup_scope, fixture_proc, managed_cgroup, temp_dir,
    };

    #[test]
    fn the_builtin_table_parses_and_covers_the_schema_examples() {
        let table = ClassTable::builtin();
        assert!(table.warnings.is_empty(), "{:?}", table.warnings);
        assert!(!table.is_empty());
        assert_eq!(table.class_of("git"), "git");
        assert_eq!(table.class_of("bash"), "shell");
        assert_eq!(table.class_of("sh"), "shell");
        assert_eq!(table.class_of("node"), "node");
        assert_eq!(table.class_of("cargo"), "cargo");
        assert_eq!(table.class_of("punar-mock-agent"), "agent");
    }

    /// The privacy property of the mapping: an unmapped `comm` becomes
    /// the literal class `unknown`, never itself. This is what stops a
    /// script *name* — which can be as revealing as a path — from
    /// reaching the ledger.
    #[test]
    fn an_unmapped_comm_becomes_unknown_and_never_itself() {
        let table = ClassTable::builtin();
        for hostile in [
            "deploy-prod-hotfix.sh",
            "exfiltrate",
            "acme-merger-model",
            "",
        ] {
            assert_eq!(table.class_of(hostile), CLASS_UNKNOWN, "{hostile}");
        }
    }

    #[test]
    fn a_staged_table_overrides_the_builtin_and_rejects_bad_classes() {
        let dir = temp_dir("classtable");
        let path = dir.join("process-classes.json");
        std::fs::write(
            &path,
            r#"{"v":1,"classes":{"git":"vcs","weird":"/usr/bin/weird","n":7}}"#,
        )
        .unwrap();
        let table = ClassTable::load(&path);
        assert_eq!(table.class_of("git"), "vcs", "the staged table wins");
        assert_eq!(
            table.class_of("weird"),
            CLASS_UNKNOWN,
            "a path-shaped class is dropped, not stored"
        );
        assert_eq!(table.warnings.len(), 2, "{:?}", table.warnings);

        // Missing file: the built-in table, no drama.
        let fallback = ClassTable::load(&dir.join("absent.json"));
        assert_eq!(fallback.class_of("git"), "git");
        // Unparsable file: the built-in table plus a warning.
        std::fs::write(&path, "not json").unwrap();
        let broken = ClassTable::load(&path);
        assert_eq!(broken.class_of("git"), "git");
        assert!(!broken.warnings.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sampling_reads_the_scope_cgroup_and_classifies_by_comm() {
        let dir = temp_dir("sample-cgroup");
        let proc_root = fixture_proc("sample");
        let session = "agt_4f21c09ab3e1";
        for (pid, comm) in [(2143u32, "punar-mock-agent"), (2200, "git"), (2201, "bash")] {
            fake_process(
                &proc_root,
                pid,
                comm,
                "/usr/bin/x",
                &["/usr/bin/x"],
                1000,
                &managed_cgroup(session),
            );
        }
        let relative = fixture_cgroup_scope(&dir, session, &[2143, 2200, 2201], Some(6));

        let sample = sample_scope(
            &CgroupRoot::new(&dir),
            &ProcRoot::new(&proc_root),
            &ClassTable::builtin(),
            Some(&relative),
            session,
        );
        assert_eq!(sample.processes.len(), 3);
        assert_eq!(sample.classes, vec!["agent", "git", "shell"]);
        assert_eq!(sample.peak, Some(6));
        // starttime came from the fixture's stat file, so the dedup key
        // is a real pair rather than (pid, 0).
        assert!(sample.processes.iter().all(|(_, start)| *start > 0));

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&proc_root);
    }

    #[test]
    fn an_unreadable_scope_falls_back_to_proc_and_reports_no_peak() {
        let proc_root = fixture_proc("sample-fallback");
        let session = "agt_fallback01";
        fake_process(
            &proc_root,
            3100,
            "git",
            "/usr/bin/git",
            &["/usr/bin/git"],
            1000,
            &managed_cgroup(session),
        );
        // A process in a *different* session's scope must not be counted.
        fake_process(
            &proc_root,
            3101,
            "git",
            "/usr/bin/git",
            &["/usr/bin/git"],
            1000,
            &managed_cgroup("agt_other000001"),
        );
        let sample = sample_scope(
            &CgroupRoot::new("/nonexistent-cgroup-root"),
            &ProcRoot::new(&proc_root),
            &ClassTable::builtin(),
            None,
            session,
        );
        assert_eq!(sample.processes.len(), 1);
        assert_eq!(sample.classes, vec!["git"]);
        assert_eq!(sample.peak, None, "peak is unknown, not invented");
        let _ = std::fs::remove_dir_all(&proc_root);
    }
}
