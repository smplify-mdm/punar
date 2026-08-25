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

// ---------------------------------------------------------------------------
// M7 agent registry views (contract section 10.2; Plate D-005 in terminal
// grammar — the mockup's own Sect V names this parity)
// ---------------------------------------------------------------------------

/// The label a classification renders as. `unknown` never renders alone:
/// detection is heuristic and the word `suspected` travels with it
/// everywhere (SPEC section 23 — "Do not claim perfect detection").
fn classification_label(row: &model::AgentRow) -> String {
    match row.classification.as_str() {
        "unknown" => "unknown · suspected".to_string(),
        other => other.to_string(),
    }
}

/// Managed is calm green, unknown is the red voice, observed stays plain —
/// the D-005 palette, in the terminal's three slots.
fn classification_slot(classification: &str) -> Slot {
    match classification {
        "managed" => Slot::Ok,
        "unknown" => Slot::Bad,
        // `observed` and anything a newer daemon invents stay calm.
        _ => Slot::Neutral,
    }
}

/// Authority decision words (SPEC section 20 plus the manifest's
/// filesystem grades): a grant reads green, a refusal red, a request
/// amber.
fn authority_slot(decision: &str) -> Slot {
    match decision {
        "allow" | "read_write" | "read" => Slot::Ok,
        "deny" => Slot::Bad,
        "request" | "approval_required" => Slot::Warn,
        _ => Slot::Neutral,
    }
}

/// The honest footer under every detection surface.
const DETECTION_NOTE: &str = "Detection is heuristic — suspected, not certain · \
                              scan on view · continuous detection arrives in Milestone 10";

// ---------------------------------------------------------------------------
// M8 AI Access Ledger (contract sections 12–13; Plate D-005's Sect III in
// terminal grammar). The register answers SPEC section 21's question —
// "what did it access?" — and is kept structurally apart from the
// authority register above it, which answers "what may it access?".
// ---------------------------------------------------------------------------

/// A detection has no ledger and will not have one in M8: an unregistered
/// process has no persisted session (milestone-7.md section 4.4), so there
/// is nothing to aggregate against. Milestone 10 owns that work, and the
/// surface says so rather than rendering an empty section that could read
/// as "accessed nothing".
const DETECTION_LEDGER_NOTE: &str = "Unknown activity has no access ledger in Milestone 8 — \
                                     a detection has no registered session to aggregate \
                                     against · Milestone 10";

/// The SPEC section 21.2 never-record list, in the user's words. Used when
/// the daemon sends no `privacy.never_recorded` of its own; the daemon's
/// list always wins so the two surfaces cannot drift apart.
const NEVER_RECORDED: &str = "file paths inside your workspace · prompts · source code · \
                              secret values · individual file reads";

/// Where the ledger lives, and the two facts that matter about the place.
const LEDGER_STORAGE: &str = "/var/lib/punar/agents/ledger · root-only · never uploaded";

/// The boundary sentence every purge prints (milestone-8.md section 10.4):
/// the audit log is the tamper-evident record of decisions the *system*
/// made and is outside a user's delete authority. The ledger, derived from
/// it plus the scope cgroup, is not.
const AUDIT_BOUNDARY: &str = "The audit trail is a separate record and was not deleted · \
                              punarctl audit tail";

/// The same boundary, stated before anything is deleted — the ledger
/// surfaces say what purge will and will not touch, in the present tense.
const AUDIT_SEPARATE: &str = "a separate record · not deleted by purge · punarctl audit tail";

/// There is no upload path in Milestone 8 — not a path nobody used, a path
/// that does not exist (milestone-8.md section 10.5).
const REMOTE_QUERY: &str = "none — no upload path exists (Milestone 10 adds the authorized, \
                            audited administrator query)";

/// The count qualifier, stated wherever a process count is printed
/// (milestone-8.md section 3.3): the number is real and so is its limit.
const PROCESS_SAMPLING_NOTE: &str = "Processes · sampled at scan points · short-lived children \
                                     may be missed · peak is concurrent, never a spawn total";

/// The documented default retention window (milestone-8.md section 6.1).
/// Only ever printed when the daemon reported no live value — and then it
/// is labelled as the default, not as an observation.
const LEDGER_RETENTION_DEFAULT_DAYS: u32 = 14;

/// Human spelling of a Level-4 event category (contract section 12.2's
/// seven-value enum). An unrecognised value is printed verbatim rather
/// than guessed at.
fn event_words(event_type: &str) -> String {
    match event_type {
        "denied_access" => "Denied access".to_string(),
        "privilege_request" => "Privilege request".to_string(),
        "credential_request" => "Credential request".to_string(),
        "policy_bypass_attempt" => "Policy bypass attempt".to_string(),
        "production_access" => "Production access".to_string(),
        "sensitive_resource_access" => "Sensitive resource access".to_string(),
        "unknown_ai_execution" => "Unknown AI execution".to_string(),
        "" => "Security event".to_string(),
        other => other.replace('_', " "),
    }
}

/// Human spelling of the mediation point that proved an entry (contract
/// section 12.2's four-value evidence enum). Naming it on the row is the
/// point of the whole design: nothing here comes from tracing.
fn evidence_words(evidence: &str) -> String {
    match evidence {
        "cgroup_scope" => "cgroup scope".to_string(),
        "audit_event" => "audit event".to_string(),
        "workspace_bind" => "workspace bind".to_string(),
        "adapter_metadata" => "adapter metadata".to_string(),
        other => other.replace('_', " "),
    }
}

/// `class` or `class × N`. Process classes always carry the count (the
/// D-005 signature `git × 12 · cargo × 4 · bash × 9`); the other
/// categories stay bare at one, where a `× 1` would be noise.
fn resource_cell(category: &str, class: &str, count: Option<u64>) -> String {
    match count {
        Some(n) if n > 1 || category == "process_classes" => format!("{class} × {n}"),
        _ => class.to_string(),
    }
}

/// English plural for a counted noun, without a dependency.
fn plural(n: u64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("{n} {one}")
    } else {
        format!("{n} {many}")
    }
}

/// The Level-3 resource register: one row per category, in the Plate
/// D-005 reading order, with the counts in the value column and the
/// mediation point that proved them in the description.
///
/// A category with no owned producer renders its own
/// `NOT YET OBSERVED · MILESTONE n` row carrying the daemon's reason
/// verbatim — never an empty line that could be read as "did not happen"
/// (SPEC section 1.22, contract section 12.2).
fn ledger_resource_rows(style: &Style, access: &model::LedgerAccess) -> String {
    let resources = &access.summary.resources;
    let mut observed: Vec<Row> = Vec::new();
    let mut pending: Vec<Row> = Vec::new();

    for (key, label, values) in resources.categories() {
        if !values.is_empty() {
            let cells: Vec<String> = values
                .iter()
                .map(|class| {
                    let count = access.detail.as_ref().and_then(|d| d.count_of(key, class));
                    resource_cell(key, class, count)
                })
                .collect();
            let mut desc: Vec<String> = Vec::new();
            if let Some(entry) = access
                .detail
                .as_ref()
                .and_then(|d| d.entries.iter().find(|e| e.category == key))
            {
                if !entry.evidence.is_empty() {
                    desc.push(evidence_words(&entry.evidence));
                }
            }
            if key == "process_classes" {
                if let Some(peak) = access.detail.as_ref().and_then(|d| d.process_peak) {
                    desc.push(format!("peak {peak} concurrent"));
                }
            }
            observed.push(Row::new(
                label,
                &cells.join(" · "),
                Slot::Neutral,
                &desc.join(" · "),
            ));
            continue;
        }
        // Empty. Either an honest not-yet-observed category, or a real
        // "nothing was observed" — and the two never render alike.
        match access
            .not_yet_observed
            .iter()
            .find(|n| n.category == key && n.level != 4)
        {
            Some(pendingrow) => {
                let value = if pendingrow.milestone.is_empty() {
                    "Not yet observed".to_string()
                } else {
                    format!("Not yet observed · {}", pendingrow.milestone)
                };
                pending.push(Row::new(label, &value, Slot::Neutral, &pendingrow.reason));
            }
            None => observed.push(Row::new(label, "None recorded", Slot::Neutral, "")),
        }
    }

    let mut out = String::new();
    if !observed.is_empty() {
        out.push_str(&fmt::rows(style, &observed));
    }
    if let Some((first, last)) = observed_window(access) {
        out.push_str(&fmt::note(
            style,
            &format!(
                "Observed · first {} · last {}",
                fmt::timestamp(&first),
                fmt::timestamp(&last)
            ),
        ));
    }
    if !resources.process_classes.is_empty() {
        out.push_str(&fmt::note(style, PROCESS_SAMPLING_NOTE));
    }
    if !pending.is_empty() {
        out.push_str(&fmt::rows(style, &pending));
    }
    out
}

/// The Level-4 register: security events as **references** into the audit
/// log (contract section 12.2). The payload is deliberately not duplicated
/// here — the row names the category, the time and the `evt_` id, and
/// points at the one place that holds the record.
fn ledger_event_rows(style: &Style, access: &model::LedgerAccess) -> String {
    let mut out = fmt::section(
        style,
        "Security events · level 4",
        "references · punarctl audit tail",
    );
    let events = &access.summary.security_events;
    if events.is_empty() {
        out.push_str(&fmt::note(style, "None recorded"));
    } else {
        let rows: Vec<Row> = events
            .iter()
            .map(|event| {
                Row::new(
                    &event_words(&event.event_type),
                    &fmt::timestamp(&event.timestamp),
                    // The one loud register on the surface: a security
                    // event is the thing the reader must not scroll past.
                    Slot::Bad,
                    &event.event_id,
                )
            })
            .collect();
        out.push_str(&fmt::rows(style, &rows));
    }

    // The Level-4 categories nothing produces yet, named with their
    // milestone — the same honesty rule as the Level-3 rows above.
    let waiting: Vec<String> = access
        .not_yet_observed
        .iter()
        .filter(|n| n.level == 4)
        .map(|n| {
            if n.milestone.is_empty() {
                event_words(&n.category)
            } else {
                format!("{} ({})", event_words(&n.category), n.milestone)
            }
        })
        .collect();
    if !waiting.is_empty() {
        out.push_str(&fmt::note(
            style,
            &format!("Not yet observed · {}", waiting.join(" · ")),
        ));
    }
    out
}

/// Retention + the section 24.2 privacy guarantee, as the closing block of
/// every ledger surface. The daemon's own words win wherever it sent them,
/// so the CLI and the panel cannot say different things about the same
/// record.
fn ledger_privacy_rows(style: &Style, access: &model::LedgerAccess) -> String {
    let session_id = &access.summary.session_id;
    let mut rows: Vec<Row> = Vec::new();

    match &access.retention {
        Some(retention) => {
            let days = if retention.days == 0 {
                LEDGER_RETENTION_DEFAULT_DAYS
            } else {
                retention.days
            };
            match &retention.expires_at {
                Some(expires) if !expires.is_empty() => rows.push(Row::new(
                    "Retention",
                    &format!("kept until {}", fmt::timestamp(expires)),
                    Slot::Neutral,
                    &format!("{days} days after the session ended, then deleted automatically"),
                )),
                _ => rows.push(Row::new(
                    "Retention",
                    "active session",
                    Slot::Neutral,
                    &format!("kept {days} days after the session ends, then deleted automatically"),
                )),
            }
        }
        None => rows.push(Row::new(
            "Retention",
            "not reported",
            Slot::Neutral,
            "punar-agentd sent no retention block for this session",
        )),
    }
    // `local_only` is the daemon's own claim, and it is the claim that
    // matters most on this surface — so the row states what the daemon
    // said, not what M8 happens to be true today. Absent, it defaults to
    // the M8 fact: agentd has no network surface at all.
    let local_only = access.privacy.as_ref().is_none_or(|p| p.local_only);
    rows.push(Row::new(
        "Stored",
        "",
        Slot::Neutral,
        if local_only {
            LEDGER_STORAGE
        } else {
            "/var/lib/punar/agents/ledger · root-only"
        },
    ));
    let never = access
        .privacy
        .as_ref()
        .filter(|p| !p.never_recorded.is_empty())
        .map(|p| p.never_recorded.join(" · "))
        .unwrap_or_else(|| NEVER_RECORDED.to_string());
    rows.push(Row::new("Never recorded", "", Slot::Neutral, &never));
    let purge = access
        .privacy
        .as_ref()
        .map(|p| p.purge_command.clone())
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| format!("punarctl privacy purge --session {session_id}"));
    rows.push(Row::new("Delete", "", Slot::Neutral, &purge));
    if access
        .privacy
        .as_ref()
        .is_none_or(|p| p.audit_trail_separate)
    {
        rows.push(Row::new("Audit trail", "", Slot::Neutral, AUDIT_SEPARATE));
    }
    rows.push(Row::new("Remote query", "", Slot::Neutral, REMOTE_QUERY));

    let mut out = fmt::section(style, "Privacy · your copy of this data", "local only");
    out.push_str(&fmt::rows(style, &rows));
    out
}

/// The earliest `first_seen` and the latest `last_seen` across the whole
/// aggregate: the window the record actually covers. Printed once rather
/// than per row — a per-entry pair would bury the resource names the
/// reader came for, and the window is what "when did this happen?" means.
fn observed_window(access: &model::LedgerAccess) -> Option<(String, String)> {
    let detail = access.detail.as_ref()?;
    let first = detail
        .entries
        .iter()
        .map(|e| e.first_seen.as_str())
        .filter(|v| !v.is_empty())
        .min()?;
    let last = detail
        .entries
        .iter()
        .map(|e| e.last_seen.as_str())
        .filter(|v| !v.is_empty())
        .max()?;
    Some((first.to_string(), last.to_string()))
}

/// The whole ledger register for one session, shared verbatim by
/// `agents access`, `agents inspect` and `privacy ledger <id>` so the
/// three can never disagree.
fn ledger_register(style: &Style, access: &model::LedgerAccess) -> String {
    let mut out = fmt::section(
        style,
        "Ledger · what it accessed",
        "local only · level 3 · sampled at scan points",
    );

    // A purged session is not an empty one, and the surface never lets the
    // two look alike (contract section 12.2).
    if let Some(purged_at) = access.purged_at.as_ref().filter(|p| !p.is_empty()) {
        out.push_str(&fmt::verdict(
            style,
            Slot::Neutral,
            &format!("Purged by you · {}", fmt::timestamp(purged_at)),
        ));
        out.push_str(&fmt::note(style, AUDIT_BOUNDARY));
        out.push_str(&ledger_privacy_rows(style, access));
        return out;
    }

    out.push_str(&ledger_resource_rows(style, access));
    if access.detail.as_ref().is_some_and(|d| d.truncated) {
        out.push_str(&fmt::note(
            style,
            "… and more (truncated) · this session exceeded the per-session bounds              (milestone-8.md section 5.3)",
        ));
    }
    out.push_str(&ledger_event_rows(style, access));
    out.push_str(&ledger_privacy_rows(style, access));
    out
}

/// `punarctl agents access <id>` — the SPEC section 11.2 verb, real since
/// Milestone 8. Terminal parity with Plate D-005's ledger register: the
/// same rows in the same order as the panel, so the two surfaces are one
/// document rendered twice.
pub fn agent_access(style: &Style, result: &Value) -> Result<String, String> {
    let access: model::LedgerAccess = parse(result)?;
    let mut out = fmt::masthead(style, "AI Access Ledger", &access.summary.session_id);

    // The attribution line, from what the ledger itself carries.
    let mut parts = vec![access.summary.session_id.clone()];
    if !access.summary.agent.is_empty() {
        parts.push(access.summary.agent.clone());
    }
    if let Some(status) = access
        .detail
        .as_ref()
        .map(|d| d.status.clone())
        .filter(|s| !s.is_empty())
    {
        parts.push(status);
    }
    if !access.summary.generated_at.is_empty() {
        parts.push(format!(
            "read {}",
            fmt::timestamp(&access.summary.generated_at)
        ));
    }
    out.push_str(&fmt::note(style, &parts.join(" · ")));
    out.push_str(&ledger_register(style, &access));
    Ok(out)
}

/// `punarctl privacy ledger <id>` — the same record, opened from the
/// privacy side rather than the agent side.
pub fn privacy_ledger_session(
    style: &Style,
    result: &Value,
    hostname: &str,
) -> Result<String, String> {
    let access: model::LedgerAccess = parse(result)?;
    let mut out = fmt::masthead(style, "Privacy", &personal_context(hostname));
    out.push_str(&fmt::section(
        style,
        "Local AI ledger · what this device recorded",
        &access.summary.session_id,
    ));
    out.push_str(&ledger_register(style, &access));
    Ok(out)
}

/// `punarctl privacy ledger` — the device-wide answer to the section 24.2
/// question, which is not the agent-side question: **what has this device
/// recorded about me?**
///
/// Composed from two contract methods (the `status` → `enroll.status`
/// precedent): `agents.list` for the sessions and their counts-only ledger
/// fingerprints, then one `agents.access` per session for the retention
/// date and the totals. A session whose ledger this user may not read
/// still gets a row — with its counts and the reason — because hiding it
/// would understate what the device holds.
pub fn privacy_ledger(
    style: &Style,
    list: &Value,
    accesses: &[(String, Value)],
    hostname: &str,
) -> Result<String, String> {
    let registry: model::AgentsList = parse(list)?;
    let mut out = fmt::masthead(style, "Privacy", &personal_context(hostname));
    out.push_str(&fmt::section(
        style,
        "Local AI ledger · what this device recorded",
        "local only · never uploaded",
    ));

    let mut classes: u64 = 0;
    let mut events: u64 = 0;
    let mut recorded: u64 = 0;
    let mut retention_days: Option<u32> = None;
    let mut never: Option<String> = None;
    let mut rows: Vec<Row> = Vec::new();

    for session in &registry.sessions {
        let access: Option<model::LedgerAccess> = accesses
            .iter()
            .find(|(id, _)| *id == session.session_id)
            .and_then(|(_, value)| serde_json::from_value(value.clone()).ok());

        let mut facts: Vec<String> = Vec::new();
        if !session.agent.is_empty() {
            facts.push(session.agent.clone());
        }
        if !session.project.is_empty() {
            facts.push(session.project.clone());
        }

        let purged = access
            .as_ref()
            .and_then(|a| a.purged_at.clone())
            .filter(|p| !p.is_empty());
        match (&access, &session.ledger) {
            (Some(a), _) => {
                let n = a.summary.resources.total() as u64;
                let e = a.summary.security_events.len() as u64;
                classes += n;
                events += e;
                if purged.is_none() {
                    recorded += 1;
                }
                facts.push(plural(n, "resource class", "resource classes"));
                facts.push(plural(e, "security event", "security events"));
                if let Some(retention) = &a.retention {
                    if retention.days > 0 {
                        retention_days = Some(retention.days);
                    }
                    if let Some(expires) = retention.expires_at.as_ref().filter(|v| !v.is_empty()) {
                        facts.push(format!("kept until {}", fmt::timestamp(expires)));
                    } else if retention.active {
                        facts.push("active — retention starts when it ends".to_string());
                    }
                }
                if let Some(privacy) = &a.privacy {
                    if !privacy.never_recorded.is_empty() && never.is_none() {
                        never = Some(privacy.never_recorded.join(" · "));
                    }
                }
            }
            (None, Some(fingerprint)) => {
                classes += fingerprint.resources;
                events += fingerprint.security_events;
                recorded += 1;
                facts.push(plural(
                    fingerprint.resources,
                    "resource class",
                    "resource classes",
                ));
                facts.push(plural(
                    fingerprint.process_classes,
                    "process class",
                    "process classes",
                ));
                facts.push(plural(
                    fingerprint.security_events,
                    "security event",
                    "security events",
                ));
                if !fingerprint.updated_at.is_empty() {
                    facts.push(format!(
                        "updated {}",
                        fmt::timestamp(&fingerprint.updated_at)
                    ));
                }
                facts.push("not readable by you — owner or root only".to_string());
            }
            (None, None) => facts.push("no ledger recorded".to_string()),
        }

        let state = match &purged {
            Some(at) => format!("purged {}", fmt::timestamp(at)),
            None => session.status.clone(),
        };
        rows.push(Row::new(
            &session.session_id,
            &state,
            Slot::Neutral,
            &facts.join(" · "),
        ));
    }

    if rows.is_empty() {
        out.push_str(&fmt::note(
            style,
            "Nothing is recorded · no AI agent session on this device has an access ledger",
        ));
    } else {
        out.push_str(&fmt::rows(
            style,
            &[Row::new(
                "What is recorded",
                &plural(recorded, "session", "sessions"),
                Slot::Neutral,
                &format!(
                    "{} · {}",
                    plural(classes, "resource class", "resource classes"),
                    plural(events, "security event", "security events")
                ),
            )],
        ));
        out.push_str(&fmt::rows(style, &rows));
    }

    // Detections are named, not hidden: they have no ledger in M8 and the
    // reason is structural, not an omission.
    if !registry.detections.is_empty() {
        out.push_str(&fmt::note(
            style,
            &format!(
                "{} · no access ledger in Milestone 8 — a detection has no registered \
                 session to aggregate against · Milestone 10",
                plural(
                    registry.detections.len() as u64,
                    "suspected AI process",
                    "suspected AI processes"
                ),
            ),
        ));
    }

    let days = retention_days.unwrap_or(LEDGER_RETENTION_DEFAULT_DAYS);
    let retention_desc = if retention_days.is_some() {
        format!("{days} days after a session ends, then deleted automatically")
    } else {
        format!("{days} days after a session ends (the documented default; no live value read)")
    };
    out.push_str(&fmt::section(
        style,
        "The rules · what this device will not do",
        "SPEC section 21.2 · 24",
    ));
    out.push_str(&fmt::rows(
        style,
        &[
            Row::new(
                "Never recorded",
                "",
                Slot::Neutral,
                &never.unwrap_or_else(|| NEVER_RECORDED.to_string()),
            ),
            Row::new("Stored", "", Slot::Neutral, LEDGER_STORAGE),
            Row::new("Retention", "", Slot::Neutral, &retention_desc),
            Row::new(
                "Delete",
                "",
                Slot::Neutral,
                "punarctl privacy purge --session <id>  ·  punarctl privacy purge --all",
            ),
            Row::new("Audit trail", "", Slot::Neutral, AUDIT_SEPARATE),
            Row::new("Remote query", "", Slot::Neutral, REMOTE_QUERY),
        ],
    ));
    out.push_str(&fmt::note(
        style,
        concat!(
            "You never see less than an administrator would · ",
            "punarctl agents access <id> --json prints the exact document ",
            "a future authorized query would return"
        ),
    ));
    Ok(out)
}

/// `punarctl privacy purge` — what was deleted, and the one sentence that
/// keeps the ledger and the audit trail from being confused for each other.
pub fn privacy_purge(
    style: &Style,
    result: &Value,
    hostname: &str,
    scope: &str,
) -> Result<String, String> {
    let purge: model::LedgerPurge = parse(result)?;
    let mut out = fmt::masthead(style, "Privacy", &personal_context(hostname));
    out.push_str(&fmt::rows(
        style,
        &[
            Row::new("Scope", "", Slot::Neutral, scope),
            Row::new(
                "Purged at",
                "",
                Slot::Neutral,
                &fmt::timestamp(&purge.purged_at),
            ),
            Row::new("Stored", "", Slot::Neutral, LEDGER_STORAGE),
        ],
    ));
    out.push_str(&fmt::verdict(
        style,
        Slot::Neutral,
        &format!(
            "✓ Purged · {} · {} · {}",
            plural(purge.purged, "session", "sessions"),
            plural(purge.resource_classes, "resource class", "resource classes"),
            plural(purge.security_events, "event reference", "event references"),
        ),
    ));
    out.push_str(&fmt::note(style, AUDIT_BOUNDARY));
    Ok(out)
}

/// `punarctl privacy connections` — reserved, and honest about it. The
/// verb is in SPEC section 11.2 and a user who finds the `privacy` noun
/// will type it, so it answers in the section 73 voice instead of going
/// silently missing.
pub fn privacy_connections_notice() -> String {
    concat!(
        "Local network observability is not available yet.\n",
        "Why: nothing on this device observes network destinations — punar-netd arrives in ",
        "Milestone 12 (network privacy prototype), and Punar does not guess at data it does ",
        "not mediate.\n",
        "Next step: punarctl privacy ledger",
    )
    .to_string()
}

/// `punarctl agents list` — one row per session and per detection:
/// `SESSION · AGENT · PROJECT · CLASS · STATUS · STARTED`. Unmanaged-first:
/// no org chrome, ever.
pub fn agents_list(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let list: model::AgentsList = parse(result)?;
    let mut out = fmt::masthead(style, "AI Agents", &personal_context(hostname));

    let rows: Vec<&model::AgentRow> = list.sessions.iter().chain(list.detections.iter()).collect();
    if rows.is_empty() {
        out.push_str(&fmt::note(
            style,
            "No agent sessions · no suspected AI activity observed",
        ));
        out.push_str(&fmt::note(style, DETECTION_NOTE));
        return Ok(out);
    }

    let cells: Vec<[String; 6]> = rows
        .iter()
        .map(|row| {
            [
                row.session_id.to_uppercase(),
                row.agent.clone(),
                row.project.clone(),
                classification_label(row).to_uppercase(),
                row.status.to_uppercase(),
                fmt::timestamp(&row.started_at),
            ]
        })
        .collect();
    let mut widths = [0usize; 6];
    for cell_row in &cells {
        for (w, cell) in widths.iter_mut().zip(cell_row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    for (row, cell_row) in rows.iter().zip(&cells) {
        let mut line = String::new();
        for (i, (w, cell)) in widths.iter().zip(cell_row).enumerate() {
            let padding = " ".repeat(w - cell.chars().count() + 2);
            // Only the classification cell is colored — the one word that
            // carries a verdict (D-014: color is spent on status words).
            match i {
                3 => line.push_str(&style.slot(classification_slot(&row.classification), cell)),
                0 | 5 => line.push_str(&style.muted(cell)),
                _ => line.push_str(cell),
            }
            line.push_str(&padding);
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }

    let suspected = list.detections.len();
    out.push_str(&fmt::note(
        style,
        &format!(
            "{} session{} · {suspected} suspected · scanned {}",
            list.sessions.len(),
            if list.sessions.len() == 1 { "" } else { "s" },
            fmt::timestamp(&list.scanned_at),
        ),
    ));
    out.push_str(&fmt::note(style, DETECTION_NOTE));
    Ok(out)
}

/// `punarctl agents inspect <id>` — Plate D-005's detail pane in terminal
/// grammar: the attribution masthead (SPEC section 22), then the authority
/// register with its named policy source and per-row enforcement labels,
/// then — since Milestone 8 — the real ledger register, fetched by the
/// caller with a best-effort `agents.access` follow-up (the `status` →
/// `enroll.status` precedent). `ledger` is `None` when no follow-up was
/// attempted (a detection has no ledger to fetch) and `Err(reason)` when
/// the follow-up failed — the section then says why rather than drawing an
/// empty ledger that would read as "accessed nothing". A detection renders
/// the unknown card
/// instead: what was observed, said as *suspected*, with no authority
/// block (there is none — it was never launched through the runtime) and
/// no actions (those are M9/M10; no dead buttons on a terminal either).
pub fn agent_inspect(
    style: &Style,
    result: &Value,
    ledger: Option<Result<&Value, String>>,
) -> Result<String, String> {
    let got: model::AgentGet = parse(result)?;
    let s = &got.session;
    let context = format!(
        "{} · {} · {}",
        s.session_id,
        classification_label(s),
        s.status
    );
    let mut out = fmt::masthead(style, "Agent", &context);

    // The attribution chain, one line, middle dots (SPEC sections 22/47).
    let environment = if s.environment.is_empty() {
        "host".to_string()
    } else {
        s.environment.clone()
    };
    out.push_str(&fmt::note(
        style,
        &format!(
            "{} · {} · {} · started {}",
            s.session_id,
            s.user,
            environment,
            fmt::timestamp(&s.started_at)
        ),
    ));

    // A detection has no authority block to lead with, so its identity
    // register opens the detail instead — and opens it as *observed*.
    if s.suspected {
        out.push_str(&fmt::section(
            style,
            "Identity · observed",
            "best effort · SPEC section 23",
        ));
    }

    let mut rows = vec![
        Row::new("Agent", "", Slot::Neutral, &s.agent),
        Row::new(
            "Version",
            "",
            Slot::Neutral,
            if s.version.is_empty() {
                "unknown"
            } else {
                &s.version
            },
        ),
        Row::new(
            "Classification",
            &classification_label(s),
            classification_slot(&s.classification),
            match s.classification.as_str() {
                "managed" => "launched through the managed Punar runtime",
                "observed" => "known AI agent running outside the managed runtime",
                "unknown" => "uncertain identity — heuristic detection, not proof",
                _ => "",
            },
        ),
        Row::new("Project", "", Slot::Neutral, &s.project),
    ];
    if let Some(scope) = &s.scope_unit {
        rows.push(Row::new(
            "Scope",
            "",
            Slot::Neutral,
            &format!("{scope} · attribution via cgroup"),
        ));
    }
    if let Some(executable) = &s.executable {
        rows.push(Row::new("Executable", "", Slot::Neutral, executable));
    }
    if let Some(signature) = &s.signature_id {
        rows.push(Row::new(
            "Signature",
            "",
            Slot::Neutral,
            &format!("{signature} · heuristic match"),
        ));
    }
    out.push_str(&fmt::rows(style, &rows));

    match &s.authority {
        Some(authority) => {
            out.push_str(&fmt::section(
                style,
                "Authority · what it may access",
                &format!("policy · {}", policy_words(&authority.policy_citation)),
            ));
            let authority_rows: Vec<Row> = authority
                .rows
                .iter()
                .map(|row| {
                    Row::new(
                        &row.zone,
                        &row.decision,
                        authority_slot(&row.decision),
                        &row.enforcement,
                    )
                })
                .collect();
            if authority_rows.is_empty() {
                out.push_str(&fmt::note(style, "No permissions were declared"));
            } else {
                out.push_str(&fmt::rows(style, &authority_rows));
            }
            out.push_str(&fmt::note(
                style,
                "Declared authority · nothing here is enforced in Milestone 7 \
                 (credentials M9 · network M12)",
            ));
        }
        None if s.suspected => out.push_str(&fmt::note(style, DETECTION_NOTE)),
        None => {
            out.push_str(&fmt::section(
                style,
                "Authority · what it may access",
                "not recorded for this session",
            ));
            out.push_str(&fmt::note(
                style,
                "This session carries no authority summary — it was not launched through \
                 punar-env",
            ));
        }
    }

    // LEDGER — "what it accessed" (SPEC section 21). The May/Did split is
    // structural: two ruled registers, each with its question in the
    // header, so the promise and the record can never be read as one.
    match ledger {
        Some(Ok(value)) => {
            let access: model::LedgerAccess = parse(value)?;
            out.push_str(&ledger_register(style, &access));
        }
        Some(Err(why)) => {
            out.push_str(&fmt::section(
                style,
                "Ledger · what it accessed",
                "not available",
            ));
            out.push_str(&fmt::note(style, &why));
        }
        None => {
            out.push_str(&fmt::section(
                style,
                "Ledger · what it accessed",
                "not recorded for unknown activity",
            ));
            out.push_str(&fmt::note(style, DETECTION_LEDGER_NOTE));
        }
    }
    Ok(out)
}

/// Human spelling of a policy citation: `personal-defaults` reads as the
/// phrase it is; a policy id keeps its exact characters.
fn policy_words(citation: &str) -> String {
    match citation {
        "personal-defaults" => "personal defaults".to_string(),
        other => other.to_string(),
    }
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

    /// A purged ledger is not an empty one, and the two never render
    /// alike (contract section 12.2).
    #[test]
    fn a_purged_session_renders_as_purged_not_as_nothing_recorded() {
        let style = Style::plain();
        let result = json!({
            "summary": {
                "session_id": "agt_4f21c09ab3e1",
                "agent": "claude-code",
                "generated_at": "2026-08-27T10:06:00Z",
                "resources": {
                    "repositories": [], "directory_zones": [],
                    "network_destinations": [], "mcp_servers": [],
                    "credential_classes": [], "process_classes": []
                },
                "security_events": []
            },
            "purged_at": "2026-08-27T10:05:00Z",
            "retention": {"days": 14, "expires_at": "2026-09-10T14:31:00Z"},
            "privacy": {"local_only": true, "audit_trail_separate": true,
                        "purge_command": "punarctl privacy purge --session agt_4f21c09ab3e1",
                        "never_recorded": ["prompts"]}
        });
        let text = agent_access(&style, &result).unwrap();
        assert!(
            text.contains("PURGED BY YOU · 2026-08-27 10:05:00"),
            "{text}"
        );
        assert!(
            text.contains("THE AUDIT TRAIL IS A SEPARATE RECORD AND WAS NOT DELETED"),
            "{text}"
        );
        // Nothing may read as "this agent accessed nothing".
        assert!(!text.contains("NONE RECORDED"), "{text}");
        assert!(!text.contains("NOT YET OBSERVED"), "{text}");
    }

    /// An empty category is either *not yet observed* (and names its
    /// milestone) or genuinely *none recorded* — never a blank line, and
    /// never the wrong one of the two (SPEC section 1.22).
    #[test]
    fn an_empty_category_is_labelled_either_pending_or_none() {
        let style = Style::plain();
        let result = json!({
            "summary": {
                "session_id": "agt_1", "agent": "mock",
                "generated_at": "2026-08-27T10:00:00Z",
                "resources": {
                    "repositories": [], "directory_zones": ["workspace"],
                    "network_destinations": [], "mcp_servers": [],
                    "credential_classes": [], "process_classes": []
                },
                "security_events": []
            },
            "not_yet_observed": [
                {"level": 3, "category": "network_destinations", "milestone": "M12",
                 "reason": "punar-netd does not exist yet"}
            ],
            "retention": {"days": 14, "active": true}
        });
        let text = agent_access(&style, &result).unwrap();
        // Named producer-less category: pending, with its milestone.
        let network = text
            .lines()
            .find(|l| l.starts_with("NETWORK DESTINATIONS"))
            .unwrap_or_default();
        assert!(network.contains("NOT YET OBSERVED · M12"), "{text}");
        // Unnamed empty category: an honest "none recorded", never a
        // borrowed milestone from another row.
        let repositories = text
            .lines()
            .find(|l| l.starts_with("REPOSITORIES"))
            .unwrap_or_default();
        assert!(repositories.contains("NONE RECORDED"), "{text}");
        assert!(!repositories.contains("M12"), "{text}");
        // No process rows: no sampling qualifier claiming a count exists.
        assert!(!text.contains("SHORT-LIVED CHILDREN"), "{text}");
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
