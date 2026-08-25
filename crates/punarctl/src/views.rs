//! Human renderers, one per verb — every view is composed from the
//! `fmt` idioms only (Plate D-014: no command formats itself).
//!
//! Unmanaged-first (design language section 8): personal mode draws **no**
//! org, compliance, or enrollment rows; policy citations say "personal
//! defaults" / "os default"; the absence of an organization renders calm
//! and uncolored. Enrollment (M5) adds rows, never redraws.

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::fmt::{self, Row, Slot, Style};
use crate::model::{self, state_str};

fn parse<T: DeserializeOwned>(result: &Value) -> Result<T, String> {
    serde_json::from_value(result.clone()).map_err(|e| format!("unexpected result shape — {e}"))
}

fn decision_slot(decision: &str) -> Slot {
    match decision {
        "allow" => Slot::Ok,
        "deny" => Slot::Bad,
        "approval_required" => Slot::Warn,
        _ => Slot::Neutral,
    }
}

fn state_slot(descriptor: &model::Descriptor) -> Slot {
    if descriptor.current_state == descriptor.desired_state {
        Slot::Ok
    } else {
        Slot::Warn
    }
}

fn personal_context(hostname: &str) -> String {
    format!("{hostname} · Personal")
}

/// `punarctl status`.
pub fn status(style: &Style, result: &Value) -> Result<String, String> {
    let s: model::Status = parse(result)?;
    let mut out = fmt::masthead(style, "Status", &personal_context(&s.hostname));

    let device_desc = if s.enrolled {
        format!("{} · {} · enrolled", s.hostname, s.device_id)
    } else {
        format!(
            "{} · {} · not enrolled · nothing leaves this machine",
            s.hostname, s.device_id
        )
    };
    let started = s
        .started_at
        .as_deref()
        .map(fmt::timestamp)
        .unwrap_or_else(|| "unknown".to_string());
    let reconcile_desc = match &s.last_reconcile {
        Some(ts) => format!("registry local · last reconcile {}", fmt::timestamp(ts)),
        None => "registry local · not yet reconciled".to_string(),
    };

    let mut rows = vec![
        Row::new("Device", &s.mode, Slot::Neutral, &device_desc),
        Row::new(
            "Daemon",
            "Ready",
            Slot::Ok,
            &format!(
                "punard {} · protocol v{} · started {started}",
                s.daemon_version, s.protocol_version
            ),
        ),
        Row::new(
            "Capabilities",
            &format!("{} Tracked", s.capabilities_total),
            Slot::Neutral,
            &reconcile_desc,
        ),
    ];
    if let Some(audit) = &s.audit {
        rows.push(Row::new(
            "Audit",
            &format!("{} Events", audit.events),
            Slot::Neutral,
            &format!("{} · local only", audit.path),
        ));
    }
    out.push_str(&fmt::rows(style, &rows));
    if !s.enrolled {
        out.push_str(&fmt::note(
            style,
            "No organization is enrolled · enrolling later never applies retroactively",
        ));
    }
    Ok(out)
}

/// `punarctl capabilities` (bare = list).
pub fn capabilities(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let list: model::CapabilityList = parse(result)?;
    let mut out = fmt::masthead(style, "Capabilities", &personal_context(hostname));
    let rows: Vec<Row> = list
        .capabilities
        .iter()
        .map(|d| {
            Row::new(
                &d.capability,
                &state_str(&d.current_state),
                state_slot(d),
                &format!(
                    "desired {} · risk {} · verify {} · {}",
                    state_str(&d.desired_state),
                    d.risk,
                    d.verification,
                    d.managed_by
                ),
            )
        })
        .collect();
    out.push_str(&fmt::rows(style, &rows));
    out.push_str(&fmt::note(
        style,
        "Observed live at request time · no organization is enrolled",
    ));
    Ok(out)
}

fn descriptor_rows(d: &model::Descriptor) -> Vec<Row> {
    let mut rows = vec![
        Row::new("Capability", &d.capability, Slot::Neutral, ""),
        Row::new(
            "State",
            &state_str(&d.current_state),
            state_slot(d),
            &format!(
                "desired {} · verify {}",
                state_str(&d.desired_state),
                d.verification
            ),
        ),
        Row::new(
            "Supported",
            if d.supported { "Yes" } else { "No" },
            if d.supported {
                Slot::Neutral
            } else {
                Slot::Bad
            },
            "",
        ),
        Row::new(
            "Mutable",
            if d.mutable { "Yes" } else { "No" },
            Slot::Neutral,
            if d.mutable {
                ""
            } else {
                "observe and report only"
            },
        ),
        Row::new(
            "Reboot",
            if d.requires_reboot {
                "Required"
            } else {
                "Not required"
            },
            Slot::Neutral,
            "",
        ),
        Row::new("Risk", &d.risk, Slot::Neutral, ""),
        Row::new(
            "Managed by",
            &d.managed_by,
            Slot::Neutral,
            "personal defaults · no organization is enrolled",
        ),
    ];
    if let Some(privilege) = &d.privilege_required {
        rows.push(Row::new(
            "Privilege",
            privilege,
            Slot::Neutral,
            "run mutations as root · just-in-time elevation arrives in Milestone 9",
        ));
    }
    if let Some(approval) = &d.approval_requirement {
        let desc = match approval.as_str() {
            "allow" => "no approval needed",
            "deny" => "mutation is refused",
            "approval_required" => "an approval gate applies",
            _ => "",
        };
        rows.push(Row::new(
            "Approval",
            approval,
            decision_slot(approval),
            desc,
        ));
    }
    if let Some(category) = &d.audit_category {
        rows.push(Row::new(
            "Audit",
            category,
            Slot::Neutral,
            "every change lands in the local audit log",
        ));
    }
    if let Some(states) = &d.allowed_desired_states {
        let listed: Vec<String> = states.iter().map(state_str).collect();
        rows.push(Row::new("Allowed", "", Slot::Neutral, &listed.join(" · ")));
    }
    rows
}

/// `punarctl capabilities get <id>`.
pub fn capability(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let got: model::CapabilityGet = parse(result)?;
    let mut out = fmt::masthead(style, "Capability", &personal_context(hostname));
    out.push_str(&fmt::rows(style, &descriptor_rows(&got.descriptor)));
    Ok(out)
}

/// `punarctl capabilities set <id> <state>` — post-verify descriptor plus
/// a verdict line (the plate's one loud register).
pub fn set(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let outcome: model::CapabilitySet = parse(result)?;
    let d = &outcome.descriptor;
    let mut out = fmt::masthead(style, "Set", &personal_context(hostname));
    out.push_str(&fmt::rows(style, &descriptor_rows(d)));
    if outcome.changed {
        out.push_str(&fmt::verdict(
            style,
            Slot::Ok,
            &format!(
                "✓ Applied · {} → {} · verified",
                d.capability,
                state_str(&d.current_state)
            ),
        ));
    } else {
        out.push_str(&fmt::verdict(
            style,
            Slot::Neutral,
            &format!(
                "No change · {} already {}",
                d.capability,
                state_str(&d.current_state)
            ),
        ));
    }
    out.push_str(&fmt::note(style, "Recorded to the local audit log"));
    Ok(out)
}

/// `punarctl audit tail [-n N]`.
pub fn audit(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let tail: model::AuditTail = parse(result)?;
    let mut out = fmt::masthead(style, "Audit", &personal_context(hostname));
    if tail.events.is_empty() {
        out.push_str(&fmt::note(style, "No audit events recorded yet"));
        return Ok(out);
    }

    let cells: Vec<[String; 5]> = tail
        .events
        .iter()
        .map(|e| {
            [
                fmt::timestamp(&e.timestamp),
                e.action.clone(),
                e.resource.clone(),
                e.user_id.clone(),
                e.event_id.clone(),
            ]
        })
        .collect();
    let mut widths = [0usize; 5];
    for row in &cells {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    for (event, row) in tail.events.iter().zip(&cells) {
        let mut line = String::new();
        for (i, (w, cell)) in widths.iter().zip(row).enumerate() {
            let padding = " ".repeat(w - cell.chars().count() + 2);
            // Time and event id sit in the muted register; the middle
            // columns carry the story.
            if i == 0 || i == 4 {
                line.push_str(&style.muted(cell));
            } else {
                line.push_str(cell);
            }
            line.push_str(&padding);
        }
        let decision = format!("{} · {}", event.decision, event.result).to_uppercase();
        line.push_str(&style.slot(decision_slot(&event.decision), &decision));
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out.push_str(&fmt::note(
        style,
        &format!(
            "{} events · newest last · local only · nothing leaves this machine",
            tail.events.len()
        ),
    ));
    Ok(out)
}

/// `punarctl reconcile` — M3 reports drift, never remediates.
pub fn reconcile(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let report: model::Reconcile = parse(result)?;
    let mut out = fmt::masthead(style, "Reconcile", &personal_context(hostname));
    let rows: Vec<Row> = report
        .capabilities
        .iter()
        .map(|entry| {
            let (value, slot) = if !entry.verified {
                ("Unverified", Slot::Bad)
            } else if entry.drift {
                ("Drift", Slot::Warn)
            } else {
                ("Ok", Slot::Ok)
            };
            Row::new(
                &entry.capability,
                value,
                slot,
                &format!(
                    "desired {} · observed {}",
                    state_str(&entry.desired_state),
                    state_str(&entry.current_state)
                ),
            )
        })
        .collect();
    out.push_str(&fmt::rows(style, &rows));

    let total = report.capabilities.len();
    if report.drift_count == 0 {
        out.push_str(&fmt::verdict(
            style,
            Slot::Ok,
            &format!("Clean · {total} capabilities verified"),
        ));
    } else {
        out.push_str(&fmt::verdict(
            style,
            Slot::Warn,
            &format!(
                "Drift detected · {} of {total} capabilities · reported only",
                report.drift_count
            ),
        ));
    }
    let mut closing = String::new();
    if let Some(ts) = &report.reconciled_at {
        closing.push_str(&format!("Reconciled {} · ", fmt::timestamp(ts)));
    }
    closing.push_str(
        "Milestone 3 reports drift without remediating · the desired-state merge arrives in Milestone 4",
    );
    out.push_str(&fmt::note(style, &closing));
    Ok(out)
}

const POLICY_NOTE: &str = "No policy is loaded until Milestone 4 · the preference/policy merge and explain engine arrive there";

/// `punarctl policy effective` — honest personal-mode answer; no engine
/// exists yet, and this view never pretends otherwise.
pub fn policy_effective(style: &Style, hostname: &str) -> String {
    let mut out = fmt::masthead(style, "Policy", &personal_context(hostname));
    out.push_str(&fmt::rows(
        style,
        &[
            Row::new(
                "Source",
                "You · this device",
                Slot::Neutral,
                "no organization is enrolled",
            ),
            Row::new(
                "Policy",
                "Personal defaults",
                Slot::Neutral,
                "built-in rule · mutations need root",
            ),
        ],
    ));
    out.push_str(&fmt::note(style, POLICY_NOTE));
    out
}

/// `punarctl policy explain <capability>` — the Plate D-014 explain
/// anatomy in personal mode, minus the rows only an engine could fill.
pub fn policy_explain(style: &Style, capability: &str) -> String {
    let mut out = fmt::masthead(style, "Policy Explain", capability);
    out.push_str(&fmt::rows(
        style,
        &[
            Row::new("Capability", capability, Slot::Neutral, ""),
            Row::new(
                "Source",
                "You · this device",
                Slot::Neutral,
                "no organization is enrolled",
            ),
            Row::new("Policy", "Personal defaults", Slot::Neutral, ""),
            Row::new("User override", "Permitted", Slot::Ok, "it is your device"),
            Row::new(
                "Compliance",
                "",
                Slot::Neutral,
                "not enrolled · local state only",
            ),
        ],
    ));
    out.push_str(&fmt::note(style, POLICY_NOTE));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decision_slots_map_the_spec_values() {
        assert_eq!(decision_slot("allow"), Slot::Ok);
        assert_eq!(decision_slot("deny"), Slot::Bad);
        assert_eq!(decision_slot("approval_required"), Slot::Warn);
        assert_eq!(decision_slot("something_else"), Slot::Neutral);
    }

    #[test]
    fn views_reject_shapeless_results_with_a_reason() {
        let style = Style::plain();
        let err = status(&style, &json!({"not": "a status"})).unwrap_err();
        assert!(err.contains("unexpected result shape"));
    }

    #[test]
    fn policy_views_are_honest_about_milestone_4_and_show_no_org() {
        let style = Style::plain();
        for text in [
            policy_effective(&style, "punar-m3"),
            policy_explain(&style, "security.firewall"),
        ] {
            assert!(text.contains("MILESTONE 4"));
            assert!(text.contains("PERSONAL DEFAULTS"));
            let lower = text.to_lowercase();
            assert!(!lower.contains("org "));
            assert!(!lower.contains("acme"));
            assert!(!lower.contains("compliant"));
        }
    }

    #[test]
    fn reconcile_view_reports_drift_without_promising_a_fix() {
        let style = Style::plain();
        let result = json!({
            "reconciled_at": "2026-08-25T07:41:03Z",
            "drift_count": 1,
            "capabilities": [
                {"capability": "security.firewall", "desired_state": "enabled",
                 "current_state": "disabled", "drift": true, "verified": true},
                {"capability": "time.timezone", "desired_state": "UTC",
                 "current_state": "UTC", "drift": false, "verified": true}
            ]
        });
        let text = reconcile(&style, &result, "punar-m3").unwrap();
        assert!(text.contains("DRIFT DETECTED · 1 OF 2 CAPABILITIES · REPORTED ONLY"));
        assert!(text.contains("desired enabled · observed disabled"));
        assert!(text.contains("MILESTONE 3 REPORTS DRIFT WITHOUT REMEDIATING"));
    }
}
