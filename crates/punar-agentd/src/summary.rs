//! `/run/punar/agents.json` — the AI panel's side contract (docs/api/ipc.md
//! section 11), the sibling of M5's `status.json`.
//!
//! The shell renders the PUNAR+A surface from this file with an
//! event-driven `FileView`: no socket client in the shell, no polling loop,
//! and no privileged data. Written at startup and on every change
//! (register, end, reap, detection diff), atomically (tmp + rename), `0644`.
//!
//! **Summary only.** No process ids, no command lines, no secrets, no
//! ledger data — the panel renders identity, classification, project,
//! environment, and the launcher's authority block, and that is the whole
//! list. The file is non-authoritative by design: `/run/punar` is owned by
//! the session user, so this is display data for that user's own session;
//! anything trusted stays on the agentd socket. Consumers fail closed —
//! a missing or unparsable file is the calm empty panel.
//!
//! # Policy citation
//!
//! The panel cites the authority the device is under: `personal-defaults`
//! unenrolled, the org policy id while enrolled (docs/api/ipc.md section
//! 10.3). Enrollment state comes from `status.json` (section 9), which
//! deliberately carries no policy ids; the id itself therefore comes from
//! punard's private `enrollment.json`, which agentd can read as root. If
//! the device is enrolled but no id can be read, the citation is the
//! honest generic [`CITATION_ORG_UNSPECIFIED`] — never a fabricated id, and
//! never a wrong "personal defaults" claim on a managed device.

use std::path::{Path, PathBuf};

use punar_common::agent::{
    AGENTS_SUMMARY_VERSION, AgentsSummary, SummaryDetection, SummarySession,
};
use punar_common::audit::POLICY_PERSONAL_DEFAULTS;

use crate::registry::Registry;

/// Citation shown when the device is enrolled but the org policy id is not
/// readable — an honest "org policy, id unavailable" rather than a guess.
pub const CITATION_ORG_UNSPECIFIED: &str = "org-policy";

/// Where the citation is read from: punard's section 9 status file (the
/// enrolled flag) and its private enrollment store (the policy id).
#[derive(Debug, Clone)]
pub struct CitationSources {
    pub status_file: PathBuf,
    pub enrollment_file: PathBuf,
}

impl CitationSources {
    /// Resolve the policy citation. Any read or parse failure degrades to
    /// `personal-defaults`, which is also what an unenrolled device shows —
    /// the calm, unmanaged-first default (DESIGN_LANGUAGE section 8).
    pub fn citation(&self) -> String {
        let enrolled = std::fs::read_to_string(&self.status_file)
            .ok()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
            .and_then(|value| value.get("enrolled").and_then(serde_json::Value::as_bool))
            .unwrap_or(false);
        if !enrolled {
            return POLICY_PERSONAL_DEFAULTS.to_string();
        }
        self.org_policy_id()
            .unwrap_or_else(|| CITATION_ORG_UNSPECIFIED.to_string())
    }

    /// The first policy id recorded by enrollment. punard names the files
    /// it drops into `policy.d` after their policy id, so the file stem is
    /// the id (`crates/punard/src/enroll.rs`, `Enrollment::policy_ids`).
    fn org_policy_id(&self) -> Option<String> {
        let text = std::fs::read_to_string(&self.enrollment_file).ok()?;
        let value: serde_json::Value = serde_json::from_str(&text).ok()?;
        let file = value
            .get("policy_files")?
            .as_array()?
            .iter()
            .find_map(serde_json::Value::as_str)?;
        let id = file.trim_end_matches(".json");
        (!id.is_empty()).then(|| id.to_string())
    }
}

/// Build the summary document from the current registry view.
pub fn build(
    registry: &Registry,
    policy_citation: &str,
    scanned_at: &str,
    now: &str,
) -> AgentsSummary {
    AgentsSummary {
        v: AGENTS_SUMMARY_VERSION,
        scanned_at: scanned_at.to_string(),
        policy_citation: policy_citation.to_string(),
        counts: registry.counts(),
        sessions: registry
            .sessions()
            .map(|session| SummarySession {
                session_id: session.record.session_id.clone(),
                agent: session.record.agent.clone(),
                project: session.record.project.clone(),
                environment: session.record.environment.clone(),
                classification: session.record.classification,
                status: session.record.status,
                started_at: session.record.started_at.clone(),
                authority: session.authority.clone(),
            })
            .collect(),
        detections: registry
            .detections()
            .map(|detection| SummaryDetection {
                session_id: detection.record.session_id.clone(),
                agent: detection.record.agent.clone(),
                classification: detection.record.classification,
                // Always true: the label is in the data, so no renderer can
                // drop it by forgetting (spec section 23).
                suspected: true,
                executable: detection.executable.clone(),
                // The moment **this daemon** first saw the process.
                // M7 conflated it with `started_at` because the detector
                // did not read the kernel's tick stamp; M10 reads it, so
                // `record.started_at` is now the process's own start and
                // the observation time has its own field
                // (milestone-10.md section 6.4). The meaning of this
                // field in `agents.json` is unchanged.
                observed_at: detection.observed_at.clone(),
            })
            .collect(),
        ts: now.to_string(),
    }
}

/// Write the summary atomically (`0644`).
pub fn write(path: &Path, summary: &AgentsSummary) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec(summary).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    crate::util::write_atomic(path, &bytes, 0o644)
}

#[cfg(test)]
mod tests {
    use punar_common::agent::{
        AgentClassification, AgentStatus, AuthorityRow, AuthoritySummary, RegistryRecord,
    };

    use super::*;
    use crate::registry::{Detection, Session};
    use crate::testsupport::temp_dir;

    fn populated_registry() -> Registry {
        let mut registry = Registry::default();
        registry.insert_session(Session {
            record: RegistryRecord {
                session_id: "agt_4f21c09ab3e1".into(),
                agent: "claude-code".into(),
                version: "mock".into(),
                process_id: 2143,
                user: "punar".into(),
                project: "atlas".into(),
                environment: "punar-env-atlas".into(),
                status: AgentStatus::Active,
                classification: AgentClassification::Managed,
                started_at: "2026-08-27T09:58:40Z".into(),
            },
            scope_unit: Some("punar-agent-agt_4f21c09ab3e1.scope".into()),
            scope_path: None,
            executable: Some("/usr/lib/punar/punar-mock-agent".into()),
            authority: Some(AuthoritySummary {
                policy_citation: "personal-defaults".into(),
                rows: vec![AuthorityRow {
                    zone: "filesystem.project".into(),
                    decision: "read_write".into(),
                    enforcement: "declared · M9".into(),
                }],
            }),
            owner_uid: Some(1000),
        });
        registry.replace_detections(vec![Detection {
            record: RegistryRecord {
                session_id: "agt_d11e0aa7c402".into(),
                agent: "foo-agent".into(),
                version: "unknown".into(),
                process_id: 2410,
                user: "punar".into(),
                project: "unknown".into(),
                environment: "host".into(),
                status: AgentStatus::Active,
                classification: AgentClassification::Unknown,
                started_at: "2026-08-27T09:59:55Z".into(),
            },
            executable: "/home/punar/Downloads/foo-agent".into(),
            signature_name: "downloads-foo-agent".into(),
            signature_id: "sig_a1b2c3d4e5f6".into(),
            zone: "downloads",
            observed_at: "2026-08-27T09:59:55Z".into(),
            owner_uid: Some(1000),
        }]);
        registry
    }

    #[test]
    fn the_summary_carries_no_pids_no_cmdlines_and_no_signature_internals() {
        let summary = build(
            &populated_registry(),
            "personal-defaults",
            "2026-08-27T10:00:02Z",
            "2026-08-27T10:00:02Z",
        );
        let text = serde_json::to_string(&summary).unwrap();
        for forbidden in [
            "process_id",
            "2143",
            "2410",
            "cmdline",
            "signature_id",
            "scope_unit",
        ] {
            assert!(
                !text.contains(forbidden),
                "{forbidden} leaked into agents.json: {text}"
            );
        }
        assert_eq!(summary.counts.managed, 1);
        assert_eq!(summary.counts.unknown, 1);
        assert!(summary.detections[0].suspected);
        assert_eq!(summary.detections[0].observed_at, "2026-08-27T09:59:55Z");
        // The authority block the panel renders survives (it is display
        // data the launcher already showed the user).
        assert_eq!(
            summary.sessions[0].authority.as_ref().unwrap().rows[0].enforcement,
            "declared · M9"
        );
    }

    #[test]
    fn writes_atomically_world_readable() {
        let dir = temp_dir("summary-write");
        let path = dir.join("run/agents.json");
        let summary = build(&populated_registry(), "personal-defaults", "t", "t");
        write(&path, &summary).unwrap();
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&path).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o644);
        let parsed: AgentsSummary =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed.v, AGENTS_SUMMARY_VERSION);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn citation_is_personal_defaults_unless_enrollment_says_otherwise() {
        let dir = temp_dir("citation");
        let sources = CitationSources {
            status_file: dir.join("status.json"),
            enrollment_file: dir.join("enrollment.json"),
        };
        // Missing files: the calm default, not an error.
        assert_eq!(sources.citation(), "personal-defaults");

        std::fs::write(
            &sources.status_file,
            r#"{"v":1,"enrolled":false,"org_name":null}"#,
        )
        .unwrap();
        assert_eq!(sources.citation(), "personal-defaults");

        std::fs::write(
            &sources.status_file,
            r#"{"v":1,"enrolled":true,"org_name":"Acme Engineering"}"#,
        )
        .unwrap();
        // Enrolled but no readable id: honest generic citation, never a
        // fabricated one and never a false "personal defaults".
        assert_eq!(sources.citation(), CITATION_ORG_UNSPECIFIED);

        std::fs::write(
            &sources.enrollment_file,
            r#"{"version":1,"policy_files":["eng-ai-v3.json"]}"#,
        )
        .unwrap();
        assert_eq!(sources.citation(), "eng-ai-v3");

        // Unparsable status file fails closed to the unmanaged default.
        std::fs::write(&sources.status_file, "not json").unwrap();
        assert_eq!(sources.citation(), "personal-defaults");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
