//! Human renderers, one per verb — every view is composed from the
//! `fmt` idioms only (Plate D-014: no command formats itself).
//!
//! Unmanaged-first (design language section 8): personal mode draws **no**
//! org or enrollment rows; policy citations say "Personal preference" /
//! "OS default" / `personal-defaults`; the absence of an organization
//! renders calm and uncolored. Enrollment (M5) adds rows, never redraws.
//! M4 amendment to the M3 note "no compliance rows in personal mode":
//! **personal** compliance — the device measured against its own
//! preferences and OS defaults (SPEC section 52, milestone-4.md section 7)
//! — now exists and renders; org rows still never render before
//! enrollment.

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

/// SPEC section 52 states on the terminal semantic slots (fmt.rs: lime
/// for compliant, peach for pending, red for broken/unknown).
fn compliance_slot(state: &str) -> Slot {
    match state {
        "compliant" => Slot::Ok,
        "remediating" | "exception" => Slot::Warn,
        "non_compliant" | "unknown" => Slot::Bad,
        // `unsupported` and anything a newer daemon invents stay calm.
        _ => Slot::Neutral,
    }
}

/// Row label for a capability in the SPEC section 52 compliance block
/// ("per-capability rows: Firewall, Hostname, Timezone" —
/// milestone-4.md section 7). Unknown ids render as themselves.
fn compliance_label(capability: &str) -> &str {
    match capability {
        "security.firewall" => "Firewall",
        "system.hostname" => "Hostname",
        "time.timezone" => "Timezone",
        other => other,
    }
}

/// The SPEC section 52 block (Overall + per-capability rows), shared by
/// `status`. Personal scope: the device vs. its own effective document.
fn compliance_rows(c: &model::Compliance) -> Vec<Row> {
    let remediation = match (c.drift_remediated_total, &c.last_remediation_at) {
        (0, _) => "no drift remediated since daemon start".to_string(),
        (n, Some(ts)) => format!("drift remediated {n} · last {}", fmt::timestamp(ts)),
        (n, None) => format!("drift remediated {n}"),
    };
    let mut rows = vec![Row::new(
        "Overall",
        &c.overall,
        compliance_slot(&c.overall),
        &format!("personal scope · {remediation}"),
    )];
    for capability in &c.capabilities {
        rows.push(Row::new(
            compliance_label(&capability.capability),
            &capability.state,
            compliance_slot(&capability.state),
            "",
        ));
    }
    rows
}

/// Masthead context: `<hostname> · Personal` or `<hostname> · Managed`
/// (M5 — enrollment adds the word, never redraws the layout).
fn device_context(hostname: &str, enrolled: bool) -> String {
    format!(
        "{hostname} · {}",
        if enrolled { "Managed" } else { "Personal" }
    )
}

/// `punarctl status`. `org_policy_ids` is the policy-id list fetched from
/// `enroll.status` when the device is enrolled (the status result itself
/// carries only the org identity) — empty when unenrolled or when the
/// follow-up read failed; the row then falls back to the org domain.
pub fn status(style: &Style, result: &Value, org_policy_ids: &[String]) -> Result<String, String> {
    let s: model::Status = parse(result)?;
    let mut out = fmt::masthead(style, "Status", &device_context(&s.hostname, s.enrolled));

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

    let mut rows = vec![Row::new("Device", &s.mode, Slot::Neutral, &device_desc)];
    if let Some(org) = &s.org {
        // The M5 org row (ipc.md section 7): `Organization  <display
        // name> · <policy id>`; never rendered on a personal device.
        let detail = if org_policy_ids.is_empty() {
            org.domain.clone()
        } else {
            org_policy_ids.join(" · ")
        };
        rows.push(Row::new(
            "Organization",
            "",
            Slot::Neutral,
            &format!("{} · {detail}", org.display_name),
        ));
    }
    rows.extend([
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
    ]);
    if let Some(audit) = &s.audit {
        rows.push(Row::new(
            "Audit",
            &format!("{} Events", audit.events),
            Slot::Neutral,
            &format!("{} · local only", audit.path),
        ));
    }
    out.push_str(&fmt::rows(style, &rows));
    if let Some(compliance) = &s.compliance {
        // M4: the SPEC section 52 block, its own aligned block below the
        // daemon rows (the spec example draws it as a separate stanza).
        out.push('\n');
        out.push_str(&fmt::rows(style, &compliance_rows(compliance)));
    }
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
///
/// M5 (contract section 5.4): `overridden: true` renders the neutral
/// "Recorded, not applied" verdict — the preference was recorded and
/// outranked, not forbidden (SPEC section 39; the root caller exits 0).
/// `pinning` is the `policy.explain` entry for the capability, fetched by
/// the caller so the verdict can cite the winning source by name; without
/// it the verdict still states the override honestly.
pub fn set(
    style: &Style,
    result: &Value,
    hostname: &str,
    pinning: Option<&model::PolicyExplain>,
) -> Result<String, String> {
    let outcome: model::CapabilitySet = parse(result)?;
    let d = &outcome.descriptor;
    let overridden = outcome.overridden == Some(true);
    let context = if overridden {
        format!("{hostname} · Managed")
    } else {
        personal_context(hostname)
    };
    let mut out = fmt::masthead(style, "Set", &context);
    out.push_str(&fmt::rows(style, &descriptor_rows(d)));
    if overridden {
        let effective = outcome
            .effective_state
            .as_ref()
            .map(state_str)
            .unwrap_or_else(|| state_str(&d.current_state));
        let citation = match pinning {
            Some(explain) => format!(
                "{} is managed by {} ({})",
                d.capability, explain.source.name, explain.source.policy_id
            ),
            None => format!("{} is managed by organization policy", d.capability),
        };
        out.push_str(&fmt::verdict(
            style,
            Slot::Neutral,
            &format!("Recorded, not applied · {citation} · effective: {effective}"),
        ));
    } else if outcome.changed {
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

/// `punarctl reconcile` — since M4 the daemon remediates drift per the
/// effective policy (contract section 5.6); `remediated_count` present is
/// the marker. An M3-shaped result (report-only daemon) still renders
/// with the M3 wording — the view never claims a remediation that did
/// not happen.
pub fn reconcile(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let report: model::Reconcile = parse(result)?;
    let mut out = fmt::masthead(style, "Reconcile", &personal_context(hostname));
    let rows: Vec<Row> = report
        .capabilities
        .iter()
        .map(|entry| {
            // `drift` is the pre-remediation observation (contract 5.6);
            // the remediation outcome refines the row verdict.
            let (value, slot) = if !entry.verified {
                ("Unverified", Slot::Bad)
            } else if entry.drift {
                match entry.remediation.as_deref() {
                    Some("applied") => ("Remediated", Slot::Ok),
                    Some("suppressed") => ("Suppressed", Slot::Bad),
                    Some("apply_failed" | "verify_failed") => ("Drift", Slot::Bad),
                    _ => ("Drift", Slot::Warn),
                }
            } else {
                ("Ok", Slot::Ok)
            };
            let mut desc = format!(
                "desired {} · observed {}",
                state_str(&entry.desired_state),
                state_str(&entry.current_state)
            );
            if entry.drift {
                // SPEC section 43: how the effective policy classified the
                // drift, then what the daemon did about it.
                if let Some(classification) = &entry.classification {
                    desc.push_str(&format!(" · classification {classification}"));
                }
                if let Some(remediation) = &entry.remediation {
                    desc.push_str(&format!(" · remediation {remediation}"));
                }
            }
            Row::new(&entry.capability, value, slot, &desc)
        })
        .collect();
    out.push_str(&fmt::rows(style, &rows));

    let total = report.capabilities.len();
    match (report.drift_count, report.remediated_count) {
        (0, _) => out.push_str(&fmt::verdict(
            style,
            Slot::Ok,
            &format!("Clean · {total} capabilities verified"),
        )),
        // M3 daemon: reported only, and the verdict says so.
        (drift, None) => out.push_str(&fmt::verdict(
            style,
            Slot::Warn,
            &format!("Drift detected · {drift} of {total} capabilities · reported only"),
        )),
        (drift, Some(remediated)) if remediated >= drift => out.push_str(&fmt::verdict(
            style,
            Slot::Ok,
            &format!("✓ Drift remediated · {drift} of {total} capabilities · verified"),
        )),
        (drift, Some(remediated)) => out.push_str(&fmt::verdict(
            style,
            Slot::Warn,
            &format!("Drift detected · {drift} of {total} capabilities · {remediated} remediated"),
        )),
    }
    let mut closing = String::new();
    if let Some(ts) = &report.reconciled_at {
        closing.push_str(&format!("Reconciled {} · ", fmt::timestamp(ts)));
    }
    closing.push_str(if report.remediated_count.is_some() {
        "Remediation follows your effective policy · every attempt lands in the local audit log"
    } else {
        "Milestone 3 reports drift without remediating · the desired-state merge arrives in Milestone 4"
    });
    out.push_str(&fmt::note(style, &closing));
    Ok(out)
}

/// Shared closing note for the policy views: where the effective document
/// comes from in personal mode (SPEC section 39 merge, no org sources).
const POLICY_NOTE: &str =
    "Merged from OS defaults + your preferences · no organization is enrolled";

/// `punarctl policy effective` — D-014 table over contract section 5.7:
/// one row per path, `security.firewall  enabled  Personal preference ·
/// personal-defaults` (milestone-4.md section 7). The value cell carries
/// the entry's compliance color, matching how `capabilities` colors
/// observed state by health.
pub fn policy_effective(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let doc: model::PolicyEffective = parse(result)?;
    let mut out = fmt::masthead(style, "Policy", &personal_context(hostname));
    let rows: Vec<Row> = doc
        .entries
        .iter()
        .map(|entry| {
            Row::new(
                &entry.path,
                &state_str(&entry.explain.effective_value),
                compliance_slot(&entry.explain.compliance_state),
                &format!(
                    "{} · {}",
                    entry.explain.source.name, entry.explain.source.policy_id
                ),
            )
        })
        .collect();
    out.push_str(&fmt::rows(style, &rows));
    let mut closing = String::new();
    if let Some(ts) = &doc.computed_at {
        closing.push_str(&format!("Computed {} · ", fmt::timestamp(ts)));
    }
    closing.push_str(POLICY_NOTE);
    out.push_str(&fmt::note(style, &closing));
    Ok(out)
}

/// `punarctl policy explain <path>` — the SPEC section 40 layout verbatim
/// in the Plate D-014 field-note grammar: EFFECTIVE VALUE / SOURCE /
/// POLICY / USER OVERRIDE / COMPLIANCE rows over contract section 5.8.
/// Source and policy names stay in the mixed-case description column
/// (the plate's anatomy) so `personal-defaults` renders verbatim.
pub fn policy_explain(style: &Style, result: &Value, path: &str) -> Result<String, String> {
    let explain: model::PolicyExplain = parse(result)?;
    let override_desc = if explain.user_override_permitted {
        "Permitted · it is your device"
    } else {
        // Renderable, but never reached before M5: only a source above
        // the User Preference rung (rank < 5) pins a value.
        "Not permitted · a higher-precedence source pins this value"
    };
    let mut out = fmt::masthead(style, "Policy Explain", path);
    out.push_str(&fmt::rows(
        style,
        &[
            Row::new(
                "Effective value",
                &state_str(&explain.effective_value),
                Slot::Neutral,
                "",
            ),
            Row::new("Source", "", Slot::Neutral, &explain.source.name),
            Row::new("Policy", "", Slot::Neutral, &explain.source.policy_id),
            Row::new("User override", "", Slot::Neutral, override_desc),
            Row::new(
                "Compliance",
                &explain.compliance_state,
                compliance_slot(&explain.compliance_state),
                "",
            ),
        ],
    ));
    out.push_str(&fmt::note(style, POLICY_NOTE));
    Ok(out)
}

// ---------------------------------------------------------------------------
// M5 enrollment views (contract sections 5.9–5.11; milestone-5.md § 8.3)
// ---------------------------------------------------------------------------

/// Rows shared by `enroll start` and `enroll status`: org identity, policy
/// ids, and the loudly-labeled SIMULATED attestation (the honesty label —
/// the mock control plane measures nothing, and the output says so).
fn enrollment_rows(
    org: &model::Org,
    policy_ids: &[String],
    attestation: &str,
    enrolled_at: Option<&str>,
) -> Vec<Row> {
    let mut rows = vec![
        Row::new(
            "Organization",
            "",
            Slot::Neutral,
            &format!("{} · {}", org.display_name, org.domain),
        ),
        Row::new("Policy", "", Slot::Neutral, &policy_ids.join(" · ")),
        Row::new(
            "Attestation",
            attestation,
            Slot::Warn,
            "no real measurement — the mock control plane accepts every device",
        ),
    ];
    if let Some(ts) = enrolled_at {
        rows.push(Row::new("Enrolled", "", Slot::Neutral, &fmt::timestamp(ts)));
    }
    rows
}

/// `punarctl enroll start <domain>`.
pub fn enroll_start(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let outcome: model::EnrollStart = parse(result)?;
    let mut out = fmt::masthead(style, "Enroll", &device_context(hostname, true));
    let mut rows = enrollment_rows(
        &outcome.org,
        &outcome.policy_ids,
        &outcome.attestation,
        outcome.enrolled_at.as_deref(),
    );
    if let Some(sync) = &outcome.first_sync {
        rows.push(Row::new(
            "First sync",
            "",
            Slot::Neutral,
            &format!(
                "compliance {} · inventory {}",
                sync.compliance, sync.inventory
            ),
        ));
    }
    out.push_str(&fmt::rows(style, &rows));
    out.push_str(&fmt::verdict(
        style,
        Slot::Ok,
        &format!(
            "✓ Enrolled · {} · {}",
            outcome.org.display_name,
            outcome.policy_ids.join(" · ")
        ),
    ));
    out.push_str(&fmt::note(
        style,
        "Org policy applies from now on · compliance sync sends category states only",
    ));
    Ok(out)
}

/// `punarctl enroll status`.
pub fn enroll_status(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let status: model::EnrollStatus = parse(result)?;
    let mut out = fmt::masthead(style, "Enroll", &device_context(hostname, status.enrolled));
    if !status.enrolled {
        out.push_str(&fmt::rows(
            style,
            &[Row::new(
                "Enrollment",
                "None",
                Slot::Neutral,
                "personal device",
            )],
        ));
        out.push_str(&fmt::note(
            style,
            "No organization is enrolled · nothing leaves this machine",
        ));
        return Ok(out);
    }
    let org = status
        .org
        .as_ref()
        .ok_or_else(|| "enrolled result without an org object".to_string())?;
    let policy_ids = status.policy_ids.clone().unwrap_or_default();
    let attestation = status.attestation.as_deref().unwrap_or("unknown");
    let mut rows = enrollment_rows(org, &policy_ids, attestation, status.enrolled_at.as_deref());
    if let Some(sync) = &status.last_sync {
        let (value, slot) = match sync.result.as_deref() {
            Some("success") => ("Success", Slot::Ok),
            Some("unreachable") => ("Unreachable", Slot::Warn),
            _ => ("Never", Slot::Neutral),
        };
        let mut desc = sync
            .at
            .as_deref()
            .map(fmt::timestamp)
            .unwrap_or_else(|| "no attempt yet".to_string());
        if sync.pending {
            desc.push_str(" · report queued — retried on the next reconcile pass");
        }
        rows.push(Row::new("Last sync", value, slot, &desc));
    }
    out.push_str(&fmt::rows(style, &rows));
    out.push_str(&fmt::note(
        style,
        "Category-level sync only · states, never values or activity",
    ));
    Ok(out)
}

/// `punarctl enroll stop`.
pub fn enroll_stop(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let outcome: model::EnrollStop = parse(result)?;
    let mut out = fmt::masthead(style, "Enroll", &device_context(hostname, false));
    out.push_str(&fmt::rows(
        style,
        &[Row::new(
            "Removed",
            "",
            Slot::Neutral,
            &outcome.removed_policy_ids.join(" · "),
        )],
    ));
    out.push_str(&fmt::verdict(
        style,
        Slot::Ok,
        "Personal state restored · org layers removed",
    ));
    out.push_str(&fmt::note(
        style,
        "Unenrollment is local · reports the org already received are not retracted",
    ));
    Ok(out)
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
        let err = status(&style, &json!({"not": "a status"}), &[]).unwrap_err();
        assert!(err.contains("unexpected result shape"));
    }

    #[test]
    fn compliance_slots_map_the_spec_52_states() {
        assert_eq!(compliance_slot("compliant"), Slot::Ok);
        assert_eq!(compliance_slot("remediating"), Slot::Warn);
        assert_eq!(compliance_slot("exception"), Slot::Warn);
        assert_eq!(compliance_slot("non_compliant"), Slot::Bad);
        assert_eq!(compliance_slot("unknown"), Slot::Bad);
        assert_eq!(compliance_slot("unsupported"), Slot::Neutral);
        assert_eq!(compliance_slot("invented_later"), Slot::Neutral);
    }

    #[test]
    fn status_renders_the_personal_compliance_stanza() {
        let style = Style::plain();
        let result = json!({
            "protocol_version": 1,
            "daemon_version": "0.2.0",
            "device_id": "dev_9f3k2v8q1x",
            "mode": "personal",
            "enrolled": false,
            "hostname": "punar-m4",
            "capabilities_total": 3,
            "compliance": {
                "overall": "non_compliant",
                "capabilities": [
                    {"capability": "security.firewall", "state": "non_compliant"},
                    {"capability": "system.hostname", "state": "compliant"},
                    {"capability": "time.timezone", "state": "compliant"}
                ],
                "drift_remediated_total": 0,
                "last_remediation_at": null
            }
        });
        let text = status(&style, &result, &[]).unwrap();
        assert!(text.contains("OVERALL"), "{text}");
        assert!(text.contains("NON_COMPLIANT"), "{text}");
        assert!(
            text.contains("personal scope · no drift remediated since daemon start"),
            "{text}"
        );
        // SPEC section 52 rows carry the friendly capability labels.
        assert!(text.contains("FIREWALL"), "{text}");
        assert!(text.contains("HOSTNAME"), "{text}");
        assert!(text.contains("TIMEZONE"), "{text}");
        // Personal compliance is not an org row (design section 8).
        let lower = text.to_lowercase();
        assert!(!lower.contains("org "));
        assert!(!lower.contains("acme"));
        assert!(text.contains("NO ORGANIZATION IS ENROLLED"), "{text}");
    }

    #[test]
    fn status_without_a_compliance_block_still_renders_m3_shaped() {
        let style = Style::plain();
        let result = json!({
            "protocol_version": 1,
            "daemon_version": "0.1.0",
            "device_id": "dev_9f3k2v8q1x",
            "mode": "personal",
            "enrolled": false,
            "hostname": "punar-m3",
            "capabilities_total": 3
        });
        let text = status(&style, &result, &[]).unwrap();
        assert!(!text.contains("OVERALL"), "{text}");
        assert!(text.contains("NO ORGANIZATION IS ENROLLED"), "{text}");
    }

    #[test]
    fn policy_effective_renders_the_d014_table() {
        let style = Style::plain();
        let result = json!({
            "computed_at": "2026-08-25T09:14:02Z",
            "entries": [
                {"path": "security.firewall", "effective_value": "enabled",
                 "source": {"kind": "local_user_preference", "rank": 5,
                            "policy_id": "personal-defaults",
                            "name": "Personal preference"},
                 "user_override_permitted": true,
                 "compliance_state": "compliant"},
                {"path": "time.timezone", "effective_value": "UTC",
                 "source": {"kind": "os_secure_default", "rank": 6,
                            "policy_id": "personal-defaults",
                            "name": "OS default"},
                 "user_override_permitted": true,
                 "compliance_state": "compliant"}
            ]
        });
        let text = policy_effective(&style, &result, "punar-m4").unwrap();
        assert!(text.contains("P U N A R   ·   P O L I C Y"), "{text}");
        // One row per path: value cell + `<source name> · <policy id>`.
        assert!(text.contains("SECURITY.FIREWALL"), "{text}");
        assert!(
            text.contains("Personal preference · personal-defaults"),
            "{text}"
        );
        assert!(text.contains("OS default · personal-defaults"), "{text}");
        assert!(text.contains("COMPUTED 2026-08-25 09:14:02"), "{text}");
        assert!(text.contains("NO ORGANIZATION IS ENROLLED"), "{text}");
    }

    #[test]
    fn policy_explain_renders_the_spec_40_rows() {
        let style = Style::plain();
        let result = json!({
            "effective_value": "enabled",
            "source": {"kind": "local_user_preference", "rank": 5,
                       "policy_id": "personal-defaults",
                       "name": "Personal preference"},
            "user_override_permitted": true,
            "compliance_state": "compliant"
        });
        let text = policy_explain(&style, &result, "security.firewall").unwrap();
        // The SPEC section 40 information set, one row each, path in the
        // masthead context.
        assert!(text.contains("SECURITY.FIREWALL"), "{text}");
        assert!(text.contains("EFFECTIVE VALUE  ENABLED"), "{text}");
        assert!(text.contains("SOURCE"), "{text}");
        assert!(text.contains("Personal preference"), "{text}");
        assert!(text.contains("POLICY"), "{text}");
        assert!(text.contains("personal-defaults"), "{text}");
        assert!(text.contains("USER OVERRIDE"), "{text}");
        assert!(text.contains("Permitted · it is your device"), "{text}");
        assert!(text.contains("COMPLIANCE       COMPLIANT"), "{text}");
    }

    #[test]
    fn policy_explain_renders_a_pinned_value_honestly() {
        // Renderable but unreachable before M5: a rank-<5 source wins and
        // pins the value (engine/tests only until enrollment).
        let style = Style::plain();
        let result = json!({
            "effective_value": "required",
            "source": {"kind": "organization_baseline", "rank": 2,
                       "policy_id": "eng-baseline-v12",
                       "name": "Acme Engineering Baseline"},
            "user_override_permitted": false,
            "compliance_state": "compliant"
        });
        let text = policy_explain(&style, &result, "security.diskEncryption").unwrap();
        assert!(
            text.contains("Not permitted · a higher-precedence source pins this value"),
            "{text}"
        );
        assert!(text.contains("eng-baseline-v12"), "{text}");
    }

    #[test]
    fn reconcile_view_renders_m4_remediation_outcomes() {
        let style = Style::plain();
        let result = json!({
            "reconciled_at": "2026-08-25T09:14:02Z",
            "drift_count": 2,
            "remediated_count": 1,
            "compliance": {"overall": "non_compliant", "capabilities": [],
                           "drift_remediated_total": 1},
            "capabilities": [
                {"capability": "security.firewall", "desired_state": "enabled",
                 "current_state": "disabled", "drift": true, "verified": true,
                 "classification": "auto_remediate", "remediation": "applied"},
                {"capability": "system.hostname", "desired_state": "punar-m4",
                 "current_state": "mallory", "drift": true, "verified": true,
                 "classification": "auto_remediate", "remediation": "suppressed"},
                {"capability": "time.timezone", "desired_state": "UTC",
                 "current_state": "UTC", "drift": false, "verified": true,
                 "classification": "auto_remediate", "remediation": "none"}
            ]
        });
        let text = reconcile(&style, &result, "punar-m4").unwrap();
        assert!(text.contains("REMEDIATED"), "{text}");
        assert!(text.contains("SUPPRESSED"), "{text}");
        assert!(text.contains("remediation applied"), "{text}");
        assert!(
            text.contains("DRIFT DETECTED · 2 OF 3 CAPABILITIES · 1 REMEDIATED"),
            "{text}"
        );
        assert!(
            text.contains("EVERY ATTEMPT LANDS IN THE LOCAL AUDIT LOG"),
            "{text}"
        );
        // The M3 "reported only" wording must be gone from an M4 result.
        assert!(!text.contains("REPORTED ONLY"), "{text}");
        assert!(!text.contains("MILESTONE 3"), "{text}");
    }

    fn acme_org() -> serde_json::Value {
        json!({"id": "acme", "name": "Acme",
               "display_name": "Acme Engineering", "domain": "acme.com"})
    }

    #[test]
    fn status_renders_the_org_row_only_while_enrolled() {
        let style = Style::plain();
        let mut result = json!({
            "protocol_version": 1,
            "daemon_version": "0.2.0",
            "device_id": "dev_9f3k2v8q1x",
            "mode": "managed",
            "enrolled": true,
            "hostname": "punar-m5",
            "capabilities_total": 3,
            "org": acme_org()
        });
        let ids = vec!["eng-baseline-v12".to_string()];
        let text = status(&style, &result, &ids).unwrap();
        assert!(text.contains("ORGANIZATION"), "{text}");
        assert!(
            text.contains("Acme Engineering · eng-baseline-v12"),
            "{text}"
        );
        assert!(text.contains("MANAGED"), "{text}");
        assert!(!text.contains("NO ORGANIZATION IS ENROLLED"), "{text}");

        // Without the enroll.status follow-up, the row degrades to the
        // domain instead of inventing a policy id.
        let text = status(&style, &result, &[]).unwrap();
        assert!(text.contains("Acme Engineering · acme.com"), "{text}");

        // Personal device: byte-for-byte no org row (design section 8).
        result["enrolled"] = json!(false);
        result["mode"] = json!("personal");
        result.as_object_mut().unwrap().remove("org");
        let text = status(&style, &result, &[]).unwrap();
        assert!(!text.contains("ORGANIZATION  "), "{text}");
        assert!(text.contains("NO ORGANIZATION IS ENROLLED"), "{text}");
    }

    #[test]
    fn overridden_set_renders_the_recorded_not_applied_verdict() {
        let style = Style::plain();
        let result = json!({
            "descriptor": {
                "capability": "security.firewall",
                "supported": true,
                "current_state": "enabled",
                "desired_state": "enabled",
                "mutable": true,
                "requires_reboot": false,
                "risk": "high",
                "managed_by": "local",
                "verification": "nftables"
            },
            "changed": false,
            "overridden": true,
            "effective_state": "enabled"
        });
        let pinning: model::PolicyExplain = serde_json::from_value(json!({
            "effective_value": "enabled",
            "source": {"kind": "organization_baseline", "rank": 2,
                       "policy_id": "eng-baseline-v12",
                       "name": "Acme Engineering Baseline"},
            "user_override_permitted": false,
            "compliance_state": "compliant"
        }))
        .unwrap();
        let text = set(&style, &result, "punar-m5", Some(&pinning)).unwrap();
        assert!(
            text.contains(
                "RECORDED, NOT APPLIED · SECURITY.FIREWALL IS MANAGED BY \
                 ACME ENGINEERING BASELINE (ENG-BASELINE-V12) · EFFECTIVE: ENABLED"
            ),
            "{text}"
        );
        // Not the plain no-change verdict, and never the success one.
        assert!(!text.contains("NO CHANGE ·"), "{text}");
        assert!(!text.contains("✓ APPLIED"), "{text}");

        // Without the explain follow-up the override is still stated.
        let text = set(&style, &result, "punar-m5", None).unwrap();
        assert!(text.contains("IS MANAGED BY ORGANIZATION POLICY"), "{text}");
    }

    #[test]
    fn personal_set_render_is_unchanged_by_the_m5_fields() {
        let style = Style::plain();
        let result = json!({
            "descriptor": {
                "capability": "system.hostname",
                "supported": true,
                "current_state": "punar-m5",
                "desired_state": "punar-m5",
                "mutable": true,
                "requires_reboot": false,
                "risk": "low",
                "managed_by": "local",
                "verification": "kernel+file"
            },
            "changed": true
        });
        let text = set(&style, &result, "punar-m5", None).unwrap();
        assert!(text.contains("✓ APPLIED"), "{text}");
        assert!(!text.contains("RECORDED, NOT APPLIED"), "{text}");
    }

    #[test]
    fn enroll_start_renders_the_loud_simulated_label() {
        let style = Style::plain();
        let result = json!({
            "enrolled": true,
            "org": acme_org(),
            "policy_ids": ["eng-baseline-v12"],
            "attestation": "simulated",
            "enrolled_at": "2026-08-26T09:00:00Z",
            "first_sync": {"compliance": "success", "inventory": "success"}
        });
        let text = enroll_start(&style, &result, "punar-m5").unwrap();
        assert!(text.contains("ATTESTATION"), "{text}");
        assert!(text.contains("SIMULATED"), "{text}");
        assert!(text.contains("no real measurement"), "{text}");
        assert!(text.contains("Acme Engineering · acme.com"), "{text}");
        assert!(text.contains("eng-baseline-v12"), "{text}");
        assert!(
            text.contains("compliance success · inventory success"),
            "{text}"
        );
        assert!(text.contains("✓ ENROLLED · ACME ENGINEERING"), "{text}");
    }

    #[test]
    fn enroll_status_renders_both_states_without_a_token() {
        let style = Style::plain();
        let text = enroll_status(&style, &json!({"enrolled": false}), "punar-m5").unwrap();
        assert!(text.contains("PERSONAL"), "{text}");
        assert!(text.contains("NO ORGANIZATION IS ENROLLED"), "{text}");

        let result = json!({
            "enrolled": true,
            "org": acme_org(),
            "policy_ids": ["eng-baseline-v12"],
            "enrolled_at": "2026-08-26T09:00:00Z",
            "attestation": "simulated",
            "last_sync": {"at": "2026-08-26T09:02:00Z", "result": "unreachable",
                           "pending": true}
        });
        let text = enroll_status(&style, &result, "punar-m5").unwrap();
        assert!(text.contains("SIMULATED"), "{text}");
        assert!(text.contains("UNREACHABLE"), "{text}");
        assert!(text.contains("report queued"), "{text}");
        assert!(!text.to_lowercase().contains("tok_"), "{text}");
    }

    #[test]
    fn enroll_stop_renders_the_contract_verdict() {
        let style = Style::plain();
        let result = json!({"enrolled": false, "removed_policy_ids": ["eng-baseline-v12"]});
        let text = enroll_stop(&style, &result, "punar-m5").unwrap();
        // The ipc.md section 7 phrase, verbatim (uppercased by the verdict
        // idiom).
        assert!(
            text.contains("PERSONAL STATE RESTORED · ORG LAYERS REMOVED"),
            "{text}"
        );
        assert!(text.contains("eng-baseline-v12"), "{text}");
        assert!(text.contains("NOT RETRACTED"), "{text}");
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
