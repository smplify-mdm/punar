//! The authority summary a managed launch displays (SPEC section 20;
//! docs/api/ipc.md section 10.3; milestone-7.md section 5.1 step 3).
//!
//! The rows are the manifest's declared `permissions` block — the user's
//! own declaration — and each carries its current enforcement state.
//! Network rows are enforced for a managed host-agent scope by
//! `punar-netd`; container networking remains deny-only. No surface may
//! render a decision without that boundary (SPEC 1.22).
//!
//! Authority always cites a named source (design language section 8):
//! `personal-defaults` on an unenrolled device, the organization's policy
//! id once enrolled. The citation is read from `/run/punar/status.json`
//! (the section 9 side contract) — the same world-readable display file
//! the shell reads, so punar-env needs no punard socket client and fails
//! **closed to personal mode** exactly like the shell does.

use std::path::{Path, PathBuf};

use punar_common::agent::{AuthorityRow, AuthoritySummary};
use serde::Deserialize;

use crate::manifest::Manifest;

/// The world-readable status summary punard publishes (ipc.md section 9).
pub const STATUS_FILE: &str = "/run/punar/status.json";

/// Test/dev override for [`STATUS_FILE`]. Never set in the image.
pub const STATUS_FILE_ENV: &str = "PUNAR_STATUS_FILE";

/// Citation on an unenrolled device — the audit log's own spelling.
pub const PERSONAL_DEFAULTS: &str = punar_common::audit::POLICY_PERSONAL_DEFAULTS;

/// Citation while enrolled with an organization that has not published a
/// policy id to this session's display file. Honest sentinel: the source
/// is named (the organization) without inventing an id it did not send.
pub const ORGANIZATION_POLICY: &str = "organization-policy";

/// Enforcement labels, per permission category (ipc.md section 10.3's
/// example rows carry exactly these strings).
const ENFORCEMENT_FILESYSTEM: &str = "declared · M9";
const ENFORCEMENT_NETWORK: &str = "enforced (agent scope)";
const ENFORCEMENT_CREDENTIALS: &str = "declared · M9";

/// The enrollment facts this module reads. Lenient by contract (section 9:
/// consumers fail closed): every field optional, unknown fields ignored.
#[derive(Debug, Default, Deserialize)]
struct StatusSummary {
    #[serde(default)]
    enrolled: bool,
    #[serde(default)]
    org_name: Option<String>,
    /// Not in the section 9 tuple today. Read anyway so that if punard
    /// ever publishes the AI policy id to the display file, the citation
    /// upgrades from the sentinel with no code change here.
    #[serde(default)]
    ai_policy_id: Option<String>,
    #[serde(default)]
    policy_citation: Option<String>,
}

/// Where the enrollment display file lives, honoring the test override.
pub fn status_file() -> PathBuf {
    std::env::var_os(STATUS_FILE_ENV)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(STATUS_FILE))
}

/// The named policy source for this device, plus the organization name
/// when there is one (display only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Citation {
    /// The machine value carried on the wire and into `agents.json`.
    pub id: String,
    /// The organization display name, when enrolled.
    pub org_name: Option<String>,
}

impl Citation {
    /// Personal mode — the fail-closed answer.
    pub fn personal() -> Citation {
        Citation {
            id: PERSONAL_DEFAULTS.to_string(),
            org_name: None,
        }
    }

    /// The uppercase spelling for the launch block: `PERSONAL DEFAULTS`
    /// reads as prose, a policy id (`ENG-AI-V3`) keeps its exact
    /// characters — an id is an identifier, not a phrase.
    pub fn display(&self) -> String {
        match self.id.as_str() {
            PERSONAL_DEFAULTS => "PERSONAL DEFAULTS".to_string(),
            ORGANIZATION_POLICY => match &self.org_name {
                Some(org) => format!("ORGANIZATION POLICY · {}", org.to_uppercase()),
                None => "ORGANIZATION POLICY".to_string(),
            },
            other => other.to_uppercase(),
        }
    }
}

/// Read the citation from `path`. Missing, unreadable, unparsable, or
/// `enrolled: false` all mean personal defaults — the section 9 fail-closed
/// rule, which is also the honest answer (an unreadable display file is no
/// evidence of an organization).
pub fn citation_from(path: &Path) -> Citation {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Citation::personal();
    };
    let Ok(status) = serde_json::from_str::<StatusSummary>(&text) else {
        return Citation::personal();
    };
    if !status.enrolled {
        return Citation::personal();
    }
    let published = status
        .ai_policy_id
        .or(status.policy_citation)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    Citation {
        id: published.unwrap_or_else(|| ORGANIZATION_POLICY.to_string()),
        org_name: status
            .org_name
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
    }
}

/// The citation for this device.
pub fn citation() -> Citation {
    citation_from(&status_file())
}

/// Build the authority summary from the manifest's declared permissions,
/// in manifest order (the author's order is the reading order), each row
/// wearing its enforcement milestone.
pub fn summary(m: &Manifest, citation: &Citation) -> AuthoritySummary {
    let mut rows: Vec<AuthorityRow> = Vec::new();
    for (zone, grade) in m.permissions.filesystem.iter() {
        rows.push(AuthorityRow {
            zone: format!("filesystem.{zone}"),
            decision: grade.as_str().to_string(),
            enforcement: ENFORCEMENT_FILESYSTEM.to_string(),
        });
    }
    for (zone, decision) in m.permissions.network.iter() {
        rows.push(AuthorityRow {
            zone: format!("network.{zone}"),
            decision: decision.as_str().to_string(),
            enforcement: ENFORCEMENT_NETWORK.to_string(),
        });
    }
    for (class, grant) in m.permissions.credentials.iter() {
        rows.push(AuthorityRow {
            zone: format!("credentials.{class}"),
            decision: grant.as_str().to_string(),
            enforcement: ENFORCEMENT_CREDENTIALS.to_string(),
        });
    }
    AuthoritySummary {
        policy_citation: citation.id.clone(),
        rows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest;

    const ATLAS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/projects/atlas/project-environment.yaml"
    ));

    fn atlas() -> Manifest {
        manifest::parse_str(ATLAS).unwrap().manifest
    }

    fn tmp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("punar-env-authority-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("status.json")
    }

    #[test]
    fn rows_follow_the_manifest_order_and_carry_enforcement_labels() {
        let s = summary(&atlas(), &Citation::personal());
        assert_eq!(s.policy_citation, "personal-defaults");
        let zones: Vec<&str> = s.rows.iter().map(|r| r.zone.as_str()).collect();
        assert_eq!(
            zones,
            vec![
                "filesystem.project",
                "network.internet",
                "network.corp_dev",
                "network.corp_prod",
                "credentials.github",
                "credentials.aws_dev",
                "credentials.aws_prod",
            ]
        );
        let by_zone = |zone: &str| {
            s.rows
                .iter()
                .find(|r| r.zone == zone)
                .expect("row present")
                .clone()
        };
        assert_eq!(by_zone("filesystem.project").decision, "read_write");
        assert_eq!(by_zone("network.corp_prod").decision, "deny");
        assert_eq!(by_zone("credentials.aws_dev").decision, "request");
        // Every row, without exception, wears its current enforcement state.
        assert!(s.rows.iter().all(|r| !r.enforcement.is_empty()));
        assert_eq!(
            by_zone("network.internet").enforcement,
            "enforced (agent scope)"
        );
        assert_eq!(by_zone("credentials.github").enforcement, "declared · M9");
        assert_eq!(by_zone("filesystem.project").enforcement, "declared · M9");
    }

    #[test]
    fn a_missing_or_broken_status_file_cites_personal_defaults() {
        let path = tmp("missing");
        assert_eq!(citation_from(&path), Citation::personal());
        std::fs::write(&path, "{ not json").unwrap();
        assert_eq!(citation_from(&path), Citation::personal());
        std::fs::write(&path, "{}").unwrap();
        assert_eq!(citation_from(&path), Citation::personal());
    }

    #[test]
    fn an_unenrolled_device_cites_personal_defaults() {
        let path = tmp("personal");
        std::fs::write(
            &path,
            r#"{"v":1,"enrolled":false,"org_name":null,"compliance_overall":"compliant",
                "ts":"2026-08-25T07:00:12Z"}"#,
        )
        .unwrap();
        let citation = citation_from(&path);
        assert_eq!(citation.id, "personal-defaults");
        assert_eq!(citation.display(), "PERSONAL DEFAULTS");
    }

    /// Enrolled: the org is named. The section 9 tuple carries no policy
    /// id today, so the citation is the honest organization sentinel —
    /// never an invented id.
    #[test]
    fn an_enrolled_device_names_its_organization() {
        let path = tmp("managed");
        std::fs::write(
            &path,
            r#"{"v":1,"enrolled":true,"org_name":"Acme Engineering",
                "compliance_overall":"compliant","ts":"2026-08-25T07:00:12Z"}"#,
        )
        .unwrap();
        let citation = citation_from(&path);
        assert_eq!(citation.id, "organization-policy");
        assert_eq!(citation.display(), "ORGANIZATION POLICY · ACME ENGINEERING");
    }

    /// If a later punard publishes the AI policy id to the display file,
    /// the citation becomes that id verbatim (hero demo: `eng-ai-v3`).
    #[test]
    fn a_published_policy_id_is_cited_verbatim() {
        let path = tmp("policy-id");
        std::fs::write(
            &path,
            r#"{"v":1,"enrolled":true,"org_name":"Acme Engineering",
                "ai_policy_id":"eng-ai-v3","compliance_overall":"compliant",
                "ts":"2026-08-25T07:00:12Z"}"#,
        )
        .unwrap();
        let citation = citation_from(&path);
        assert_eq!(citation.id, "eng-ai-v3");
        assert_eq!(citation.display(), "ENG-AI-V3");
    }
}
