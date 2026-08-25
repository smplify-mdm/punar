//! Detection — the *suspected*, never certain, half of the registry
//! (spec section 23; milestone-7.md section 7, milestone-10.md sections
//! 3.5 and 4).
//!
//! One `/proc` walk per pass. Each process that is not already an accounted
//! managed session is checked against three signature sources:
//!
//! 1. **known-agent signatures** from the staged adapter definitions — a
//!    match *outside* a `punar-agent-*.scope` is `observed` ("known AI
//!    agent running outside managed runtime", spec 19.1);
//! 2. **suspected patterns** — a glob match is `unknown` (the spec's
//!    UNKNOWN / SUSPECTED class);
//! 3. **executable provenance** (M10's single new input) — an unmanaged
//!    path prefix **and** an agent-like name token, `require: "both"`,
//!    expressed as data in the same `suspected.json`.
//!
//! Everything this module produces is a heuristic. Findings carry
//! `suspected: true` into every surface, and no wording anywhere claims the
//! process *is* an AI agent — spec section 23 is explicit that Punar must
//! not claim perfect detection. What the detector actually knows is: a
//! process whose executable or arguments match a rule we wrote down.
//!
//! # Identity (milestone-10.md section 4)
//!
//! Every finding carries two ids. `detection_id` (the record's
//! `session_id`) names one running process and is stable for its whole
//! life — the property the set-diff depends on, and the reason a pass
//! that changes nothing can write nothing. `signature_id` names one
//! *thing seen* and is the alert key. Both are hashes, so they can appear
//! in an exported answer without leaking a path ([`crate::identity`]).
//!
//! # Sentinels, and the one that stopped being a sentinel
//!
//! `version` and `project` are `"unknown"` and `environment` is `"host"`
//! (milestone-7.md section 4.4). `project` in particular is **not**
//! inferred from `/proc/<pid>/cwd`: the root daemon could read it
//! trivially, and it would put a path from inside the user's home into a
//! record an administrator can later ask about — exactly what spec 21.2's
//! never-record list protects (milestone-10.md section 6.3).
//!
//! `started_at` was a sentinel in M7 — it held the time the daemon first
//! *observed* the process, because the detector did not read the kernel's
//! clock ticks. M10 reads them, so `started_at` is now the process's own
//! start (`btime` + `starttime`/`USER_HZ`), and the first-observed time
//! moved to its own [`crate::registry::Detection::observed_at`] field,
//! which is what `agents.json` renders. When the kernel does not answer,
//! `started_at` falls back to the observation time rather than inventing
//! one.
//!
//! # No timer here
//!
//! There is still no timer in this module. A pass runs when `agents.scan`
//! asks for one — including the `punar-agentd-scan.timer` unit, which
//! calls `punarctl agents scan --trigger timer` through the ordinary
//! socket, authz and audit path so there is exactly one code path to
//! verify — or when `agents.list` finds the last pass older than 30 s.
//! Spec 6.3 forbids background polling loops, and M10 honours that by
//! adding a low-frequency systemd timer outside the daemon, not a thread
//! inside it.

use std::collections::HashSet;

use punar_common::agent::{AgentClassification, AgentStatus, RegistryRecord};

use crate::adapters::SignatureSet;
use crate::identity::{detection_id, executable_zone, process_started_at, signature_id};
use crate::proc::{ProcEntry, ProcRoot};
use crate::registry::Detection;
use crate::util::{lookup_home, username_or_uid};

/// Sentinel for a field a detection cannot honestly fill.
pub const SENTINEL_UNKNOWN: &str = "unknown";
/// Sentinel environment: M7 detects host processes.
pub const SENTINEL_HOST: &str = "host";

/// The detector — signatures plus the `/proc` root they are matched
/// against. Cheap to hold: the signature set is parsed once at startup.
#[derive(Debug)]
pub struct Detector {
    proc: ProcRoot,
    signatures: SignatureSet,
    passwd_file: std::path::PathBuf,
}

impl Detector {
    pub fn new(
        proc: ProcRoot,
        signatures: SignatureSet,
        passwd_file: impl Into<std::path::PathBuf>,
    ) -> Detector {
        Detector {
            proc,
            signatures,
            passwd_file: passwd_file.into(),
        }
    }

    pub fn proc(&self) -> &ProcRoot {
        &self.proc
    }

    /// Whether any *known-agent* signature recognizes this process — the
    /// `observed` downgrade path of `agents.register` (milestone-7.md
    /// section 4.3: a launch that produced no scope, but a process the
    /// registry can still honestly name).
    pub fn matches_known_agent(&self, entry: &ProcEntry) -> bool {
        self.signatures.match_known(entry).is_some()
    }

    /// One detection pass. `accounted_pids` are the pids of active managed
    /// sessions: they are already in the registry with a *proven*
    /// classification, so re-reporting them as detections would double
    /// count the same process.
    ///
    /// `observed_at` is *this daemon's* clock for the pass. The two
    /// kernel facts the identity needs — the boot id and the boot time —
    /// are read **once per pass**, not once per pid, so the walk keeps
    /// the shape M7 measured (milestone-10.md section 15).
    pub fn scan(&self, accounted_pids: &HashSet<u32>, observed_at: &str) -> Vec<Detection> {
        let boot_id = self.proc.boot_id().unwrap_or_default();
        let boot_time = self.proc.boot_time_unix();
        let mut findings = Vec::new();
        for entry in self.proc.walk() {
            if accounted_pids.contains(&entry.pid) {
                continue;
            }
            // A process inside a managed scope belongs to a session, even
            // if this daemon has not seen its registration (a restart, or
            // a launcher that died before registering). Reporting it as
            // shadow AI would be wrong; it is attributable by cgroup.
            if entry.in_managed_scope() {
                continue;
            }
            if let Some(detection) = self.classify(&entry, observed_at, &boot_id, boot_time) {
                findings.push(detection);
            }
        }
        findings
    }

    /// Classify one process, or `None` when nothing matches — the answer
    /// for the overwhelming majority of processes on the machine.
    ///
    /// Order is **specific before general**: a named adapter signature,
    /// then the hand-written suspected globs, then M10's provenance rule.
    /// A glob was written for a particular thing and is the better label
    /// on an alert card; provenance is the rule that catches what no glob
    /// names. Keeping it last also keeps M7's shipped `signature_id`
    /// values stable for processes both rules would match.
    fn classify(
        &self,
        entry: &ProcEntry,
        observed_at: &str,
        boot_id: &str,
        boot_time: Option<u64>,
    ) -> Option<Detection> {
        let facts = |agent, classification, executable, signature_name| {
            self.detection(
                entry,
                observed_at,
                boot_id,
                boot_time,
                agent,
                classification,
                executable,
                signature_name,
            )
        };
        if let Some((adapter, path)) = self.signatures.match_known(entry) {
            return Some(facts(
                adapter.name.clone(),
                AgentClassification::Observed,
                path,
                adapter.name.clone(),
            ));
        }
        if let Some((pattern, path)) = self.signatures.match_suspected(entry) {
            let agent = agent_name_from_path(&path, &entry.comm);
            let id = pattern.id.clone();
            return Some(facts(agent, AgentClassification::Unknown, path, id));
        }
        // M10's one new input. The owning user's home is resolved here
        // rather than inside the rule so a `~/` prefix can never mean
        // "any home" — see `crate::adapters::expand_home`.
        let home = entry
            .uid
            .and_then(|uid| lookup_home(&self.passwd_file, uid));
        let (rule, path) = self.signatures.match_provenance(entry, home.as_deref())?;
        let agent = agent_name_from_path(&path, &entry.comm);
        let id = rule.id.clone();
        Some(facts(agent, AgentClassification::Unknown, path, id))
    }

    #[allow(clippy::too_many_arguments)]
    fn detection(
        &self,
        entry: &ProcEntry,
        observed_at: &str,
        boot_id: &str,
        boot_time: Option<u64>,
        agent: String,
        classification: AgentClassification,
        executable: String,
        signature_name: String,
    ) -> Detection {
        let uid = entry.uid;
        let user = uid
            .map(|uid| username_or_uid(&self.passwd_file, uid))
            .unwrap_or_else(|| SENTINEL_UNKNOWN.to_string());
        // Read only for a process that already matched: the walk pays
        // nothing for the overwhelming majority that match nothing.
        let starttime = self.proc.starttime_of(entry.pid);
        // A process whose owner uid the kernel would not report cannot be
        // given an owner-scoped identity; `0` here is not a claim that
        // root owns it — the identity is still unique because the exe,
        // pid and start tick differ, and `user` stays the honest
        // `"unknown"` sentinel above.
        let owner_uid_for_id = uid.unwrap_or(0);
        Detection {
            record: RegistryRecord {
                session_id: detection_id(
                    &executable,
                    owner_uid_for_id,
                    boot_id,
                    entry.pid,
                    starttime.unwrap_or(0),
                ),
                agent,
                version: SENTINEL_UNKNOWN.to_string(),
                process_id: entry.pid,
                user,
                project: SENTINEL_UNKNOWN.to_string(),
                environment: SENTINEL_HOST.to_string(),
                status: AgentStatus::Active,
                classification,
                // The process's own start when the kernel answered, and
                // the observation time when it did not — never a guess.
                started_at: process_started_at(boot_time, starttime)
                    .unwrap_or_else(|| observed_at.to_string()),
            },
            signature_id: signature_id(&executable, owner_uid_for_id),
            zone: executable_zone(&executable),
            observed_at: observed_at.to_string(),
            owner_uid: uid,
            executable,
            signature_name,
        }
    }
}

/// The `agent` name for an `unknown` detection: the executable's file name
/// when it fits the schema's name pattern, else the process's `comm`, else
/// the `"unknown"` sentinel. Never invented — it is only ever a name the
/// machine already used for the thing.
fn agent_name_from_path(path: &str, comm: &str) -> String {
    let file_name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    for candidate in [file_name.as_str(), &comm.to_ascii_lowercase()] {
        if punar_common::agent::agent_name_ok(candidate) {
            return candidate.to_string();
        }
    }
    SENTINEL_UNKNOWN.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::{
        fake_process, fixture_adapters, fixture_nss, fixture_proc, fixture_suspected,
        managed_cgroup, temp_dir,
    };

    struct Fixture {
        detector: Detector,
        proc_root: std::path::PathBuf,
        dir: std::path::PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.proc_root);
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn fixture(tag: &str) -> Fixture {
        let dir = temp_dir(&format!("detect-{tag}"));
        let (_, passwd) = fixture_nss(&dir);
        let signatures = SignatureSet::load(&fixture_adapters(&dir), &fixture_suspected(&dir));
        let proc_root = fixture_proc(tag);
        Fixture {
            detector: Detector::new(ProcRoot::new(&proc_root), signatures, passwd),
            proc_root,
            dir,
        }
    }

    #[test]
    fn a_downloads_script_is_suspected_never_asserted() {
        let f = fixture("suspect");
        fake_process(
            &f.proc_root,
            2410,
            "foo-agent",
            "/usr/bin/dash",
            &["/bin/sh", "/home/punar/Downloads/foo-agent"],
            1000,
            "/user.slice/user-1000.slice/session-3.scope",
        );
        let found = f.detector.scan(&HashSet::new(), "2026-08-27T09:59:55Z");
        assert_eq!(found.len(), 1);
        let detection = &found[0];
        assert_eq!(
            detection.record.classification,
            AgentClassification::Unknown
        );
        assert_eq!(detection.record.agent, "foo-agent");
        assert_eq!(detection.executable, "/home/punar/Downloads/foo-agent");
        assert_eq!(detection.signature_name, "downloads-foo-agent");
        assert!(
            punar_common::agent::signature_identity_ok(&detection.signature_id),
            "{}",
            detection.signature_id
        );
        assert_eq!(detection.zone, "downloads");
        assert_eq!(detection.record.user, "punar");
        // Sentinels, not invented facts.
        assert_eq!(detection.record.version, "unknown");
        assert_eq!(detection.record.project, "unknown");
        assert_eq!(detection.record.environment, "host");
        // The honesty label travels in the row itself.
        let row = detection.row();
        assert_eq!(row.suspected, Some(true));
        // And the record is schema-conformant even though it is never
        // persisted — one uniform row model everywhere.
        assert_eq!(
            punar_common::agent::validate_registry_record(&detection.record),
            Ok(())
        );
    }

    #[test]
    fn a_known_agent_outside_a_managed_scope_is_observed_inside_one_is_not() {
        let f = fixture("observed");
        fake_process(
            &f.proc_root,
            3001,
            "claude",
            "/usr/bin/claude",
            &["/usr/bin/claude"],
            1000,
            "/user.slice/user-1000.slice/session-3.scope",
        );
        fake_process(
            &f.proc_root,
            3002,
            "claude",
            "/usr/bin/claude",
            &["/usr/bin/claude"],
            1000,
            &managed_cgroup("agt_4f21c09ab3e1"),
        );
        let found = f.detector.scan(&HashSet::new(), "2026-08-27T10:00:00Z");
        assert_eq!(
            found.len(),
            1,
            "the scoped process is attributable, not shadow AI"
        );
        assert_eq!(found[0].record.process_id, 3001);
        assert_eq!(
            found[0].record.classification,
            AgentClassification::Observed
        );
        assert_eq!(found[0].record.agent, "claude-code");
        assert_eq!(found[0].signature_name, "claude-code");
        assert_eq!(found[0].zone, "system");
    }

    #[test]
    fn accounted_managed_pids_are_never_double_counted() {
        let f = fixture("accounted");
        fake_process(
            &f.proc_root,
            3001,
            "claude",
            "/usr/bin/claude",
            &["/usr/bin/claude"],
            1000,
            "/user.slice/user-1000.slice/session-3.scope",
        );
        let accounted: HashSet<u32> = [3001].into_iter().collect();
        assert!(
            f.detector
                .scan(&accounted, "2026-08-27T10:00:00Z")
                .is_empty()
        );
    }

    #[test]
    fn ordinary_processes_are_left_alone() {
        let f = fixture("quiet");
        fake_process(
            &f.proc_root,
            1,
            "systemd",
            "/usr/lib/systemd/systemd",
            &["/sbin/init"],
            0,
            "/init.scope",
        );
        fake_process(
            &f.proc_root,
            800,
            "sh",
            "/bin/sh",
            &["/bin/sh"],
            1000,
            "/user.slice",
        );
        fake_process(
            &f.proc_root,
            801,
            "cargo",
            "/usr/bin/cargo",
            &["/usr/bin/cargo", "/srv/atlas"],
            1000,
            "/user.slice",
        );
        assert!(
            f.detector
                .scan(&HashSet::new(), "2026-08-27T10:00:00Z")
                .is_empty(),
            "detection must not cry wolf over a normal desktop"
        );
    }

    #[test]
    fn a_detection_keeps_its_identity_while_the_process_lives() {
        let f = fixture("stable");
        fake_process(
            &f.proc_root,
            2410,
            "foo-agent",
            "/usr/bin/dash",
            &["/bin/sh", "/home/punar/Downloads/foo-agent"],
            1000,
            "/user.slice",
        );
        let first = f.detector.scan(&HashSet::new(), "2026-08-27T09:59:55Z");
        let second = f.detector.scan(&HashSet::new(), "2026-08-27T10:04:00Z");
        assert_eq!(first[0].record.session_id, second[0].record.session_id);
    }

    /// M10 identity, end to end through the shipping pass: the id is
    /// stable while the process lives, and a pid recycled to a different
    /// process is a *different* detection rather than a resurrected one.
    #[test]
    fn a_recycled_pid_is_a_new_detection_not_a_resurrected_one() {
        let f = fixture("recycle");
        fake_process(
            &f.proc_root,
            2410,
            "foo-agent",
            "/usr/bin/dash",
            &["/bin/sh", "/home/punar/Downloads/foo-agent"],
            1000,
            "/user.slice",
        );
        let first = f.detector.scan(&HashSet::new(), "2026-08-25T14:31:00Z");
        assert_eq!(first.len(), 1);
        let first_id = first[0].record.session_id.clone();

        // The process exits and the kernel hands 2410 to another run of
        // the same script — same exe, same uid, same pid, later start.
        crate::testsupport::kill_process(&f.proc_root, 2410);
        fake_process(
            &f.proc_root,
            2410,
            "foo-agent",
            "/usr/bin/dash",
            &["/bin/sh", "/home/punar/Downloads/foo-agent"],
            1000,
            "/user.slice",
        );
        // `fake_process` derives `starttime` from the pid, so force the
        // later tick the kernel would report for a later task.
        let stat = f.proc_root.join("2410/stat");
        let text = std::fs::read_to_string(&stat).unwrap();
        std::fs::write(&stat, text.replace(" 902410\n", " 1204915\n")).unwrap();

        let second = f.detector.scan(&HashSet::new(), "2026-08-25T14:39:00Z");
        assert_ne!(
            second[0].record.session_id, first_id,
            "pid reuse must not let a new process inherit a dead detection's record"
        );
        // But it is the same *thing seen*, so the alert key is identical
        // and the user is not told twice.
        assert_eq!(second[0].signature_id, first[0].signature_id);
    }

    /// `started_at` is the process's own start, derived from the kernel's
    /// boot time and tick stamp — not the moment the scan happened.
    #[test]
    fn started_at_is_the_process_start_and_observed_at_is_the_scan() {
        let f = fixture("started");
        fake_process(
            &f.proc_root,
            2410,
            "foo-agent",
            "/usr/bin/dash",
            &["/bin/sh", "/home/punar/Downloads/foo-agent"],
            1000,
            "/user.slice",
        );
        let found = f.detector.scan(&HashSet::new(), "2026-08-25T14:31:00Z");
        // btime 2026-08-25T00:00:00Z + 902410 ticks / 100 Hz = 9024.1 s.
        assert_eq!(found[0].record.started_at, "2026-08-25T02:30:24Z");
        assert_eq!(found[0].observed_at, "2026-08-25T14:31:00Z");

        // A kernel that answers neither must fall back to the observation
        // time rather than invent a start.
        std::fs::write(f.proc_root.join("stat"), "cpu 1 2 3\n").unwrap();
        let blind = f.detector.scan(&HashSet::new(), "2026-08-25T14:35:00Z");
        assert_eq!(blind[0].record.started_at, "2026-08-25T14:35:00Z");
    }

    /// M10's one new input, exercised through the shipping pass: the
    /// provenance rule fires where no hand-written glob names the thing,
    /// and it never fires on a path alone.
    #[test]
    fn provenance_catches_what_no_glob_names_and_never_a_path_alone() {
        let f = fixture("provenance");
        // `/tmp/local-llm-runner` matches no `*/Downloads/*` glob, but it
        // is an agent-named binary running from /tmp.
        fake_process(
            &f.proc_root,
            3100,
            "local-llm-runn",
            "/tmp/local-llm-runner",
            &["/tmp/local-llm-runner"],
            1000,
            "/user.slice",
        );
        // An innocent binary in the same directory: path alone is not a
        // signal, and it must stay invisible.
        fake_process(
            &f.proc_root,
            3101,
            "installer",
            "/tmp/installer",
            &["/tmp/installer"],
            1000,
            "/user.slice",
        );
        let found = f.detector.scan(&HashSet::new(), "2026-08-25T14:31:00Z");
        assert_eq!(found.len(), 1, "downloading a binary is not a suspicion");
        assert_eq!(found[0].record.process_id, 3100);
        assert_eq!(found[0].signature_name, "unmanaged-path-agentlike");
        assert_eq!(found[0].zone, "tmp");
        assert_eq!(found[0].record.classification, AgentClassification::Unknown);
    }

    /// A `~/`-rooted provenance prefix resolves against the **owning
    /// user's** home, so it never reaches into another account.
    #[test]
    fn a_home_rooted_prefix_matches_only_that_users_home() {
        let f = fixture("home-prefix");
        fake_process(
            &f.proc_root,
            3200,
            "helper-ai",
            "/home/punar/.local/bin/helper-ai",
            &["/home/punar/.local/bin/helper-ai"],
            1000,
            "/user.slice",
        );
        // Same shape under a home that belongs to nobody in the fixture
        // passwd: `~/.local/bin/` cannot expand for uid 4242, so the rule
        // matches nothing — never `/`.
        fake_process(
            &f.proc_root,
            3201,
            "helper-ai",
            "/home/ghost/.local/bin/helper-ai",
            &["/home/ghost/.local/bin/helper-ai"],
            4242,
            "/user.slice",
        );
        let found = f.detector.scan(&HashSet::new(), "2026-08-25T14:31:00Z");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].record.process_id, 3200);
        assert_eq!(found[0].record.user, "punar");
        assert_eq!(found[0].zone, "home");
    }

    #[test]
    fn unknown_agent_names_come_from_the_machine_not_from_imagination() {
        assert_eq!(
            agent_name_from_path("/home/punar/Downloads/foo-agent", "sh"),
            "foo-agent"
        );
        // A file name the schema pattern rejects falls back to comm.
        assert_eq!(agent_name_from_path("/tmp/-weird-", "dash"), "dash");
        // And when neither is usable, the sentinel — never a guess.
        assert_eq!(agent_name_from_path("/tmp/-weird-", "-"), "unknown");
    }
}
