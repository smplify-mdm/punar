//! Detection — the *suspected*, never certain, half of the registry
//! (spec section 23; milestone-7.md section 7).
//!
//! One `/proc` walk per pass. Each process that is not already an accounted
//! managed session is checked against two signature sources:
//!
//! 1. **known-agent signatures** from the staged adapter definitions — a
//!    match *outside* a `punar-agent-*.scope` is `observed` ("known AI
//!    agent running outside managed runtime", spec 19.1);
//! 2. **suspected patterns** — a match is `unknown` (the spec's UNKNOWN /
//!    SUSPECTED class).
//!
//! Everything this module produces is a heuristic. Findings carry
//! `suspected: true` into every surface, and no wording anywhere claims the
//! process *is* an AI agent — spec section 23 is explicit that Punar must
//! not claim perfect detection. What the detector actually knows is: a
//! process whose executable or arguments match a pattern we wrote down.
//!
//! Sentinels for the record fields a detection cannot honestly fill
//! (milestone-7.md section 4.4): `version` and `project` are `"unknown"`,
//! `environment` is `"host"`. `started_at` is the time this daemon **first
//! observed** the process, not the process's own start time — the detector
//! does not read `/proc/<pid>/stat` clock ticks and does not pretend to
//! know when the process began. [`crate::registry::Registry::replace_detections`]
//! keeps that first-observed value stable across later passes.
//!
//! There is no timer here. A pass runs when `agents.scan` asks for one, or
//! when `agents.list` finds the last pass older than 30 s — spec section
//! 6.3 forbids background polling loops, and continuous detection is
//! Milestone 10's named deliverable, not something M7 quietly ships.

use std::collections::HashSet;

use punar_common::agent::{AgentClassification, AgentStatus, RegistryRecord};

use crate::adapters::SignatureSet;
use crate::proc::{ProcEntry, ProcRoot};
use crate::registry::Detection;
use crate::util::{synthesized_session_id, username_or_uid};

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
    pub fn scan(&self, accounted_pids: &HashSet<u32>, observed_at: &str) -> Vec<Detection> {
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
            if let Some(detection) = self.classify(&entry, observed_at) {
                findings.push(detection);
            }
        }
        findings
    }

    /// Classify one process, or `None` when nothing matches — the answer
    /// for the overwhelming majority of processes on the machine.
    fn classify(&self, entry: &ProcEntry, observed_at: &str) -> Option<Detection> {
        if let Some((adapter, path)) = self.signatures.match_known(entry) {
            return Some(self.detection(
                entry,
                observed_at,
                adapter.name.clone(),
                AgentClassification::Observed,
                path,
                adapter.name.clone(),
            ));
        }
        let (pattern, path) = self.signatures.match_suspected(entry)?;
        let agent = agent_name_from_path(&path, &entry.comm);
        Some(self.detection(
            entry,
            observed_at,
            agent,
            AgentClassification::Unknown,
            path,
            pattern.id.clone(),
        ))
    }

    fn detection(
        &self,
        entry: &ProcEntry,
        observed_at: &str,
        agent: String,
        classification: AgentClassification,
        executable: String,
        signature_id: String,
    ) -> Detection {
        let user = entry
            .uid
            .map(|uid| username_or_uid(&self.passwd_file, uid))
            .unwrap_or_else(|| SENTINEL_UNKNOWN.to_string());
        Detection {
            record: RegistryRecord {
                session_id: synthesized_session_id(&executable, entry.pid),
                agent,
                version: SENTINEL_UNKNOWN.to_string(),
                process_id: entry.pid,
                user,
                project: SENTINEL_UNKNOWN.to_string(),
                environment: SENTINEL_HOST.to_string(),
                status: AgentStatus::Active,
                classification,
                started_at: observed_at.to_string(),
            },
            executable,
            signature_id,
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
        assert_eq!(detection.signature_id, "downloads-foo-agent");
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
        assert_eq!(found[0].signature_id, "claude-code");
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
