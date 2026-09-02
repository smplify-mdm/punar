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

use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;

use punar_common::update::{
    DesiredReleaseState, RollbackState, UpdateApplyResult, UpdateCheckResult, UpdateHealthState,
    UpdateRollbackResult, UpdateSlot, UpdateStatusResult,
};

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

/// `punarctl update status`: system and browser provenance from the typed
/// local evidence surface. Unknowns remain visible instead of becoming sample
/// versions or a false "up to date" claim.
pub fn update_status(style: &Style, result: &Value) -> Result<String, String> {
    let status: UpdateStatusResult = parse(result)?;
    let mut out = fmt::masthead(style, "Update", &status.image_id);
    out.push_str(&fmt::section(style, "System", "local evidence"));

    let slot = |slot: UpdateSlot| match slot {
        UpdateSlot::A => "slot A",
        UpdateSlot::B => "slot B",
        UpdateSlot::Unknown => "slot unknown",
    };
    let health_slot = |state| match state {
        UpdateHealthState::Pass => Slot::Ok,
        UpdateHealthState::Partial => Slot::Warn,
        UpdateHealthState::Fail | UpdateHealthState::Unknown => Slot::Bad,
    };
    let health_word = |state| match state {
        UpdateHealthState::Pass => "pass",
        UpdateHealthState::Partial => "partial",
        UpdateHealthState::Fail => "fail",
        UpdateHealthState::Unknown => "unknown",
    };

    let current = status.current.version.as_deref().unwrap_or("unknown");
    let current_detail = [
        Some(slot(status.current.slot).to_string()),
        status.current.blessed.map(|blessed| {
            if blessed {
                "blessed".to_string()
            } else {
                "not yet blessed".to_string()
            }
        }),
        status.current.reason.clone(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" · ");

    let desired = status.desired.version.as_deref().unwrap_or("unknown");
    let desired_detail = match status.desired.state {
        DesiredReleaseState::Staged => format!(
            "staged{}",
            status
                .desired
                .slot
                .map(|value| format!(" · {}", slot(value)))
                .unwrap_or_default()
        ),
        DesiredReleaseState::Available => "verified and available".to_string(),
        DesiredReleaseState::Unknown => status
            .desired
            .reason
            .clone()
            .unwrap_or_else(|| "no verified update decision".to_string()),
    };
    let channel_detail = status.channel.reason.clone().unwrap_or_else(|| {
        let age = status
            .channel
            .metadata_age_seconds
            .map(|seconds| format!("metadata {seconds}s old"))
            .unwrap_or_else(|| "verified metadata".to_string());
        format!("{age} · {}", status.channel.source)
    });
    let rollback_detail = status
        .rollback
        .target_slot
        .map(|target| slot(target).to_string())
        .or_else(|| status.rollback.rollback_unavailable_reason.clone())
        .unwrap_or_default();
    let rollback_word = match status.rollback.state {
        RollbackState::None => "none",
        RollbackState::Available => "available",
        RollbackState::PendingReboot => "pending reboot",
        RollbackState::AutoRolledBack => "auto rolled back",
        RollbackState::Unavailable => "unavailable",
    };

    out.push_str(&fmt::rows(
        style,
        &[
            Row::new(
                "Current",
                current,
                if status.current.version.is_some() && status.current.slot != UpdateSlot::Unknown {
                    Slot::Ok
                } else {
                    Slot::Bad
                },
                &current_detail,
            ),
            Row::new(
                "Desired",
                desired,
                match status.desired.state {
                    DesiredReleaseState::Staged | DesiredReleaseState::Available => Slot::Warn,
                    DesiredReleaseState::Unknown => Slot::Bad,
                },
                &desired_detail,
            ),
            Row::new(
                "Channel",
                &status.channel.name.to_string(),
                if status.channel.reachable {
                    Slot::Ok
                } else {
                    Slot::Warn
                },
                &channel_detail,
            ),
            Row::new(
                "Health",
                health_word(status.health.state),
                health_slot(status.health.state),
                status
                    .health
                    .reason
                    .as_deref()
                    .unwrap_or("four-signal boot gate"),
            ),
            Row::new(
                "Rollback",
                rollback_word,
                match status.rollback.state {
                    RollbackState::Available | RollbackState::AutoRolledBack => Slot::Ok,
                    RollbackState::PendingReboot => Slot::Warn,
                    RollbackState::None | RollbackState::Unavailable => Slot::Neutral,
                },
                &rollback_detail,
            ),
        ],
    ));

    out.push_str(&fmt::section(style, "Browser", "running image provenance"));
    let engine_detail = status
        .browser
        .reason
        .clone()
        .unwrap_or_else(|| "installed local package".to_string());
    let channel = status
        .browser
        .snapshot_pin
        .as_deref()
        .map(|pin| format!("{} ({pin})", status.browser.channel))
        .unwrap_or_else(|| status.browser.channel.clone());
    out.push_str(&fmt::rows(
        style,
        &[
            Row::new(
                "Engine",
                &status.browser.engine,
                if status.browser.version.is_some() {
                    Slot::Ok
                } else {
                    Slot::Bad
                },
                status.browser.version.as_deref().unwrap_or(&engine_detail),
            ),
            Row::new(
                "Channel",
                &channel,
                Slot::Neutral,
                &status.browser.pin_source,
            ),
            Row::new(
                "Security channel",
                status
                    .browser
                    .security_channel
                    .as_deref()
                    .unwrap_or("not configured"),
                Slot::Warn,
                "browser updates currently ride the complete signed OS image",
            ),
        ],
    ));
    Ok(out)
}

/// `punarctl update check`: render the authenticated selection decision, not
/// merely transport success. A signed but halted/out-of-cohort head remains a
/// calm no-op with the reason visible.
pub fn update_check(style: &Style, result: &Value) -> Result<String, String> {
    let check: UpdateCheckResult = parse(result)?;
    let mut out = fmt::masthead(style, "Update check", &check.channel.to_string());
    out.push_str(&fmt::section(style, "Decision", "signed channel metadata"));
    let available = check
        .available
        .map(|version| version.to_string())
        .unwrap_or_else(|| "none".to_string());
    let source = if check.cached {
        format!("verified cache · {}s old", check.metadata_age_seconds)
    } else {
        "configured source · verified now".to_string()
    };
    out.push_str(&fmt::rows(
        style,
        &[
            Row::new(
                "Current",
                &check.current.to_string(),
                Slot::Ok,
                "running image",
            ),
            Row::new(
                "Available",
                &available,
                if check.available.is_some() {
                    Slot::Warn
                } else {
                    Slot::Neutral
                },
                check.reason.as_deref().unwrap_or("signed channel head"),
            ),
            Row::new(
                "Eligible",
                if check.admissible { "yes" } else { "no" },
                if check.admissible {
                    Slot::Ok
                } else {
                    Slot::Neutral
                },
                if check.halted {
                    "channel halted"
                } else if !check.in_cohort {
                    "outside staged rollout"
                } else {
                    "target and rollout checks passed"
                },
            ),
            Row::new("Evidence", &source, Slot::Neutral, "Ed25519 verified"),
        ],
    ));
    Ok(out)
}

/// `punarctl update apply`: report the durable, verified staging outcome. The
/// daemon never reboots; that remains an explicit caller choice.
pub fn update_apply(style: &Style, result: &Value) -> Result<String, String> {
    let applied: UpdateApplyResult = parse(result)?;
    let slot = match applied.staged_slot {
        UpdateSlot::A => "slot A",
        UpdateSlot::B => "slot B",
        UpdateSlot::Unknown => "slot unknown",
    };
    let mut out = fmt::masthead(style, "Update staged", &applied.staged_version.to_string());
    out.push_str(&fmt::section(style, "Transaction", "inactive system image"));
    out.push_str(&fmt::rows(
        style,
        &[
            Row::new(
                "Release",
                &applied.staged_version.to_string(),
                Slot::Ok,
                slot,
            ),
            Row::new(
                "Verification",
                if applied.verified { "passed" } else { "failed" },
                if applied.verified {
                    Slot::Ok
                } else {
                    Slot::Bad
                },
                "signed source · physical post-write digest",
            ),
            Row::new(
                "Written",
                &format!("{} bytes", applied.bytes_written),
                Slot::Neutral,
                "root payload and boot artifact",
            ),
            Row::new(
                "Restart",
                if applied.requires_reboot {
                    "required"
                } else {
                    "not required"
                },
                if applied.requires_reboot {
                    Slot::Warn
                } else {
                    Slot::Neutral
                },
                "use --reboot or restart when ready",
            ),
        ],
    ));
    Ok(out)
}

/// `punarctl update rollback`: report only the selector transition. The
/// target already existed locally and no remote artifact was downloaded.
pub fn update_rollback(style: &Style, result: &Value) -> Result<String, String> {
    let rollback: UpdateRollbackResult = parse(result)?;
    let mut out = fmt::masthead(style, "Update rollback", &rollback.new_default);
    out.push_str(&fmt::section(style, "Selector", "local last-known-good"));
    out.push_str(&fmt::rows(
        style,
        &[
            Row::new(
                "Previous",
                &rollback.previous_default,
                Slot::Neutral,
                "selector before this request",
            ),
            Row::new(
                "Next boot",
                &rollback.new_default,
                Slot::Ok,
                "already present locally",
            ),
            Row::new(
                "Restart",
                if rollback.requires_reboot {
                    "required"
                } else {
                    "not required"
                },
                if rollback.requires_reboot {
                    Slot::Warn
                } else {
                    Slot::Neutral
                },
                "use --reboot or restart when ready",
            ),
        ],
    ));
    Ok(out)
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
        "system.update_channel" => "Update channel",
        other => other,
    }
}

/// The DESIGN_LANGUAGE section 8.1 word table. ONE table, shared with the
/// shell's `Services/Status.qml stateLabel()`, so the CLI and the GUI cannot
/// drift into two vocabularies.
///
/// Compliance asserts conformance TO AN AUTHORITY. A device with no
/// organization has none, so on a personal machine the word is either
/// meaningless or it implies one that does not exist. The underlying primitive
/// is unchanged and is a good one — the machine noticed something moved and
/// put it back — so only the naming differs: on a personal device the
/// capability MATCHES the effective document, or it has DRIFTED and is being
/// RESTORED.
///
/// THE WIRE DOES NOT MOVE. `ComplianceState`, `schemas/common/defs.json` and
/// `/run/punar/status.json` keep their spelling; the mapping is 1:1 and this
/// renderer already knows `enrolled`, so a second wire vocabulary would carry
/// no information while shipping two spellings of one value forever under
/// `v: 1` — and would invalidate roughly fifteen in-VM assertions to say
/// nothing new.
fn state_word(state: &str, enrolled: bool) -> String {
    if enrolled {
        return state.to_string();
    }
    match state {
        "compliant" => "matches".to_string(),
        "non_compliant" => "drifted".to_string(),
        "remediating" => "restoring".to_string(),
        other => other.to_string(),
    }
}

/// The key that precedes the word, for the same reason.
fn state_key(enrolled: bool) -> &'static str {
    if enrolled { "Compliance" } else { "Drift" }
}

/// The SPEC section 52 block (Overall + per-capability rows), shared by
/// `status`. On a personal device this is the device against its OWN effective
/// document, and it is worded that way.
fn compliance_rows(c: &model::Compliance, enrolled: bool) -> Vec<Row> {
    // "drift remediated" is the honest phrase in both modes: it is what the
    // reconcile loop actually did, and it names no authority.
    let remediation = match (c.drift_remediated_total, &c.last_remediation_at) {
        (0, _) => "no drift put back since daemon start".to_string(),
        (n, Some(ts)) => format!("drift put back {n} · last {}", fmt::timestamp(ts)),
        (n, None) => format!("drift put back {n}"),
    };
    // "personal scope" was here unconditionally. It only means something if
    // another scope exists that you are outside of — which is the feeling this
    // whole pass removes.
    let detail = if enrolled {
        format!("organization scope · {remediation}")
    } else {
        remediation
    };
    let mut rows = vec![Row::new(
        "Overall",
        &state_word(&c.overall, enrolled),
        compliance_slot(&c.overall),
        &detail,
    )];
    for capability in &c.capabilities {
        rows.push(Row::new(
            compliance_label(&capability.capability),
            &state_word(&capability.state, enrolled),
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
/// `punarctl compliance` — the SPEC section 11.2 verb, rendered over the block
/// `status` already returns.
///
/// It used to be a stub that printed "not implemented until Milestone 5 (mock
/// Smplify enrollment)" to stderr and exited non-zero. On a personal device
/// that is a nag pointing at a product the person does not have, for a reading
/// the daemon was already computing and already showing under `status`. The
/// verb is a spec example (SPEC section 11.2) and a test asserts every section
/// 11.2 example parses, so it is made real rather than deleted.
pub fn compliance(style: &Style, result: &Value) -> Result<String, String> {
    let s: model::Status = parse(result)?;
    // device_context() is the existing helper that renders `<host> · Managed`
    // or `<host> · Personal` — enrollment adds the word, never redraws.
    let mut out = fmt::masthead(
        style,
        state_key(s.enrolled),
        &device_context(&s.hostname, s.enrolled),
    );

    match &s.compliance {
        Some(c) => {
            out.push_str(&fmt::rows(style, &compliance_rows(c, s.enrolled)));
            out.push_str(&fmt::note(
                style,
                if s.enrolled {
                    "Each capability is measured against the effective policy · punarctl policy explain <capability>"
                } else {
                    // No authority is named, because there is none. What the
                    // machine does for its owner is stated plainly instead.
                    "Punar watches these settings and puts them back if something changes them · punarctl policy explain <capability>"
                },
            ));
        }
        None => {
            out.push_str(&fmt::rows(
                style,
                &[Row::new(
                    state_key(s.enrolled),
                    "none",
                    Slot::Neutral,
                    "the daemon reported no reconcile state",
                )],
            ));
        }
    }
    Ok(out)
}

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
    if let Some(device) = &s.device {
        let battery = match device.facts.battery_present {
            Some(true) => "battery",
            Some(false) => "no battery",
            None => "battery unknown",
        };
        let display = match device.facts.display_connected {
            Some(true) => "display",
            Some(false) => "headless",
            None => "display unknown",
        };
        rows.push(Row::new(
            "Device class",
            &device.class,
            Slot::Neutral,
            &format!(
                "{} MiB RAM · {} logical cores · {battery} · {display} · {}",
                device.facts.memory_mib, device.facts.logical_cores, device.source
            ),
        ));
    }
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
        out.push_str(&fmt::rows(style, &compliance_rows(compliance, s.enrolled)));
    }
    if !s.enrolled {
        out.push_str(&fmt::note(
            style,
            "Personal device · enrollment later never applies retroactively",
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
    out.push_str(&fmt::note(style, "Observed live at request time"));
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
            "personal defaults",
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
    // `overridden` means SOMETHING of higher precedence than your preference
    // decided this — and on a personal device that something is NOT an
    // organization: ranks 1-4 include non-org sources such as a temporary
    // approved exception. Reading `overridden` as "managed" printed
    // `<host> · Managed` and "is managed by organization policy" on a machine
    // that has never enrolled. The pinning explain names the real decider when
    // there is one; where it does not, we no longer invent one.
    let managed = overridden && pinning.is_some();
    let context = if managed {
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
            // No pinning source to cite: say what is true — something ranked
            // above your preference decided it — and name where to look,
            // rather than asserting an organization.
            None => format!(
                "{} was decided above your preference · punarctl policy explain {}",
                d.capability, d.capability
            ),
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
const POLICY_NOTE: &str = "Merged from OS defaults + your preferences";

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
            "Personal mode is local-only · nothing leaves this machine",
        ));
        // THE ONE POINTER, and it lives here on purpose. Requirement (3) is
        // that enrolling into a Smplify instance is genuinely possible and
        // findable; the constraint is that nobody may feel they SHOULD. This
        // is the surface a person reaches only by asking about enrollment, so
        // it is the one place where naming the command answers a question
        // instead of interrupting. It appears on no other view, and there is
        // deliberately no banner, no badge and no prompt anywhere else.
        //
        // SIMULATED, and labelled (spec 1.22): the endpoint this talks to is
        // punar-mock-smplify. The real control plane does not exist yet —
        // docs/development/user-blocked.md item 4.
        out.push_str(&fmt::note(
            style,
            "To enroll: sudo punarctl enroll start <domain> · SIMULATED — the endpoint is a local mock, not a Smplify instance",
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

/// The honest footer under every detection surface (milestone-10.md
/// section 14). Two facts, both of which a user is entitled to without
/// asking: the cadence is real and periodic since M10, and sampling
/// detection has a hole by construction. Closing that hole needs
/// exec-time notification — the broad tracing spec 1.14 rules out — so it
/// is stated, never engineered around.
const DETECTION_NOTE: &str = "Detection is heuristic — suspected, not certain · \
                              continuous · every 4 min · a process that starts and exits \
                              inside one interval is not seen";

// ---------------------------------------------------------------------------
// M8 AI Access Ledger (contract sections 12–13; Plate D-005's Sect III in
// terminal grammar). The register answers SPEC section 21's question —
// "what did it access?" — and is kept structurally apart from the
// authority register above it, which answers "what may it access?".
// ---------------------------------------------------------------------------

/// M8 said a detection had no ledger and named M10 as the owner of that
/// work. **M10 shipped it**, so this note no longer explains an absence —
/// it explains a *shape*: an unknown agent's ledger is strictly smaller
/// than a managed one, because Punar mediates nothing for a process it
/// did not launch. The invariant the surface must keep asserting is that
/// every empty category is *not yet observed*, never *did not happen*.
const DETECTION_LEDGER_NOTE: &str = "This ledger is bounded by what an unmanaged process \
                                     can be observed through: a process class, a zone \
                                     class and the security-event references · no cwd, \
                                     no command line, no child processes, ever";

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

/// The M10 boundary beside it: the record of who asked about this device
/// is a record of what the ORGANIZATION did, so a purge of the user's own
/// data does not remove it — and a user deleting the evidence of a query
/// would be deleting their own recourse (milestone-10.md section 10.1).
const QUERY_LOG_BOUNDARY: &str = "The remote-query log is a record of what the organization \
                                  asked and was not deleted · punarctl privacy queries";

/// M8 wrote this line as a placeholder for M10 and said so. M10 fulfils it,
/// so the placeholder is replaced by the **invariant** it was protecting:
/// nothing is uploaded continuously, an administrator's question is scoped
/// and audited, and the user can read the whole record with one command
/// (SPEC sections 24, 24.2; milestone-10.md section 10.3).
///
/// Used where the surface has no live count to show (the per-session
/// register). The device-wide register calls [`remote_query_line`] instead,
/// which prints the real numbers.
const REMOTE_QUERY: &str = "scoped, audited, never continuous · see who asked with \
                            punarctl privacy queries";

/// The device-wide `Remote query` row, from the live query log when one
/// could be read. Fails **closed to the honest static sentence** rather
/// than to a fabricated zero: "no queries" and "could not ask" are
/// different, and only one of them is a claim.
fn remote_query_line(log: Option<&model::QueriesList>) -> String {
    match log {
        None => REMOTE_QUERY.to_string(),
        Some(log) if !log.enrolled => "none — personal mode · no \
             remote-query path exists on this device"
            .to_string(),
        Some(log) => {
            let total = log.queries.len() as u64;
            let refused = log
                .queries
                .iter()
                .filter(|q| q.result_category == "refused")
                .count() as u64;
            format!(
                "{} · {} refused · punarctl privacy queries",
                plural(total, "query", "queries"),
                refused
            )
        }
    }
}

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
    queries: Option<&Value>,
) -> Result<String, String> {
    // Best-effort: a daemon that does not answer `queries.list` leaves the
    // row on its honest static sentence rather than on a fabricated zero.
    let query_log: Option<model::QueriesList> =
        queries.and_then(|v| serde_json::from_value(v.clone()).ok());
    let query_log = query_log.as_ref();
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

    // Detections are named, not hidden. M8 said they had no ledger and
    // named M10 as the owner; M10 shipped it, so the honest line is now
    // about the ledger's SHAPE and its shorter window, not its absence
    // (milestone-10.md sections 6.3, 6.5).
    if !registry.detections.is_empty() {
        out.push_str(&fmt::note(
            style,
            &format!(
                "{} · each has a bounded detection ledger — a process class, a zone \
                 class and the security-event references, kept 7 days after it clears · \
                 punarctl agents access <detection id>",
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
            Row::new(
                "Remote query",
                "",
                Slot::Neutral,
                &remote_query_line(query_log),
            ),
        ],
    ));
    out.push_str(&fmt::note(
        style,
        concat!(
            "You never see less than an administrator would · ",
            "punarctl agents access <id> --json prints the exact document ",
            "an authorized query returns"
        ),
    ));
    Ok(out)
}

// ---------------------------------------------------------------------------
// M10 — `punarctl privacy queries`, the SPEC section 24.2 command
// (docs/development/milestone-10.md section 10.3)
// ---------------------------------------------------------------------------

/// The calm personal-device sentence. Not an error, not an upsell, not an
/// empty table that could read as "nobody has asked *yet*" — a statement
/// that the path does not exist here (milestone-10.md section 11).
const NO_QUERY_PATH: &str = "Personal mode · no remote-query path exists on \
                             this device · nothing has ever been asked.";

/// The honesty label on every rendering of a requesting administrator.
/// There is no IdP in M10, and a surface that printed an identity as though
/// it were verified would be the exact dishonesty SPEC section 1.22
/// forbids.
const IDENTITY_UNVERIFIED: &str = "not verified by this device";

/// `punarctl privacy queries` — who asked about this device, what they
/// asked for, and what was decided.
///
/// Readable by any peer the agentd socket admits, deliberately: withholding
/// the log of who asked about the user *from the user* would invert SPEC
/// section 24.2, which is the promise this whole milestone exists to keep.
pub fn privacy_queries(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let log: model::QueriesList = parse(result)?;
    let mut out = fmt::masthead(style, "Privacy", &personal_context(hostname));

    if !log.enrolled && log.queries.is_empty() {
        out.push_str(&fmt::section(
            style,
            "Remote AI queries · who asked about this device",
            "personal device",
        ));
        out.push_str(&fmt::rows(
            style,
            &[Row::new(
                "Remote query",
                "none",
                Slot::Neutral,
                NO_QUERY_PATH,
            )],
        ));
        out.push_str(&fmt::note(
            style,
            "Nothing listens on this device · a query would have to be fetched by \
             the device itself, and an unenrolled device fetches nothing",
        ));
        return Ok(out);
    }

    let total = log.queries.len() as u64;
    let refused = log
        .queries
        .iter()
        .filter(|q| q.result_category == "refused")
        .count() as u64;
    let answered = total - refused;
    // A device that has been UNENROLLED still holds the queries it answered
    // while it was enrolled, and it must keep showing them — deleting the
    // record on unenrollment would be the device quietly editing its own
    // history. But a surface that renders that history with no statement of
    // the CURRENT state reads as though an organization is still asking, which
    // on a personal device is false. The scope is therefore named in the
    // section context, and the note below explains that the list is a record
    // rather than a live relationship.
    let scope = if log.enrolled {
        String::new()
    } else {
        "personal device · ".to_string()
    };
    out.push_str(&fmt::section(
        style,
        "Who asked about this device",
        &format!(
            "{scope}{} · {answered} answered · {refused} refused",
            plural(total, "query", "queries")
        ),
    ));

    if log.queries.is_empty() {
        out.push_str(&fmt::rows(
            style,
            &[Row::new(
                "Queries",
                "none",
                Slot::Neutral,
                "no administrator has asked this device anything",
            )],
        ));
    } else {
        let mut rows: Vec<Row> = Vec::new();
        // Newest last, like `audit tail`: a log reads downward.
        for query in &log.queries {
            let when = fmt::timestamp(if query.answered_at.is_empty() {
                &query.received_at
            } else {
                &query.answered_at
            });
            // The slot follows the **decision**, and the words follow the
            // result: a refusal is red because the device said deny, not
            // because a string happened to say "refused".
            let slot = match query.authorization_decision.as_str() {
                "allow" => Slot::Ok,
                "deny" => Slot::Bad,
                _ => Slot::Warn,
            };
            let verdict = match query.result_category.as_str() {
                "answered" => match query.granted_scope.as_deref() {
                    Some(granted) if granted != query.requested_scope => {
                        format!("answered at {granted}")
                    }
                    _ => "answered".to_string(),
                },
                "refused" => match query.refusal_reason.as_deref() {
                    Some("out_of_scope") | None => "refused · out of scope".to_string(),
                    Some(other) => format!("refused · {}", other.replace('_', " ")),
                },
                other => other.to_string(),
            };
            let mut facts: Vec<String> = vec![verdict];
            if query.result_category == "answered" {
                let counts = &query.record_counts;
                // The *shape* of what left, never a second copy of it.
                for (n, one, many) in [
                    (counts.sessions, "session", "sessions"),
                    (counts.detections, "detection", "detections"),
                    (counts.security_events, "event", "events"),
                ] {
                    if n > 0 {
                        facts.push(plural(n, one, many));
                    }
                }
            }
            // Every row carries a handle you can look up: the audit event
            // when there is one, the query id otherwise.
            match query.audit_event_id.as_ref().filter(|e| !e.is_empty()) {
                Some(event) => facts.push(event.clone()),
                None if !query.query_id.is_empty() => facts.push(query.query_id.clone()),
                None => {}
            }
            rows.push(Row::new(
                &format!("{when}  {}", query.requesting_admin),
                &query.requested_scope,
                slot,
                &facts.join(" · "),
            ));
        }
        out.push_str(&fmt::rows(style, &rows));
    }

    // Said once, after the rows, and only when the two facts actually
    // disagree: there is history, and nobody is enrolled now.
    if !log.enrolled && !log.queries.is_empty() {
        out.push_str(&fmt::note(
            style,
            "Personal device now · the queries above are a record of \
             what was asked while this device was enrolled, kept because \
             deleting it would be the device editing its own history",
        ));
    }

    out.push('\n');
    out.push_str(&fmt::section(
        style,
        "The rules · what an administrator can and cannot get",
        "SPEC section 24.1 · 51.1",
    ));

    let mut rules: Vec<Row> = Vec::new();
    // The daemon's own honesty flag, not a CLI-side assumption: if a
    // future milestone ever authenticates an administrator, this line
    // changes because the daemon changed, not because the CLI was edited.
    let verification = if log.admin_identity_verified {
        "verified by this device"
    } else {
        IDENTITY_UNVERIFIED
    };
    let asserted = match &log.organization {
        Some(org) if !org.is_empty() => format!("asserted by {org} · {verification}"),
        _ => format!("asserted by the organization · {verification}"),
    };
    rules.push(Row::new("Identities", "", Slot::Neutral, &asserted));
    // The daemon's own list always wins, so the CLI and the daemon cannot
    // disagree about what is refused.
    let never = if log.never_answered.is_empty() {
        punar_common::query::NEVER_ANSWERED.join(" · ")
    } else {
        log.never_answered.join(" · ")
    };
    rules.push(Row::new("Never answered", "", Slot::Neutral, &never));
    let granted = if log.granted_scopes.is_empty() {
        "none — nothing was granted at enrollment".to_string()
    } else {
        let citation = log
            .policy_citation
            .as_ref()
            .filter(|c| !c.is_empty())
            .map(|c| format!("   ({c})"))
            .unwrap_or_default();
        format!("{}{citation}", log.granted_scopes.join(" · "))
    };
    rules.push(Row::new("Granted scopes", "", Slot::Neutral, &granted));
    if let Some(storage) = &log.storage {
        let path = if storage.path.is_empty() {
            punar_common::query::QUERIES_LOG_PATH
        } else {
            storage.path.as_str()
        };
        rules.push(Row::new(
            "Where",
            "",
            Slot::Neutral,
            &format!("{path} · kept {} days", storage.retention_days),
        ));
        if !storage.purged_by_privacy_purge {
            rules.push(Row::new(
                "Purge",
                "",
                Slot::Neutral,
                "this log is NOT deleted by punarctl privacy purge — it records what \
                 the organization did, and deleting it would delete your own recourse",
            ));
        }
    }
    rules.push(Row::new(
        "See also",
        "",
        Slot::Neutral,
        "punarctl privacy ledger  ·  punarctl audit tail",
    ));
    out.push_str(&fmt::rows(style, &rules));
    out.push_str(&fmt::note(
        style,
        "Nothing can be answered that you cannot print · an answer is a subset of \
         what punarctl agents access --json already shows you",
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
    // The second boundary, since M10. Both are printed because a user who
    // deletes their ledger is entitled to know exactly what remains, and
    // the two remainders have different reasons: the audit trail is the
    // decision record, and the query log is a record of what the
    // ORGANIZATION did — deleting it would delete the user's own recourse
    // (milestone-10.md section 10.1).
    out.push_str(&fmt::note(style, QUERY_LOG_BOUNDARY));
    Ok(out)
}

#[derive(Deserialize)]
struct NetworkEnforcement {
    state: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    installed_sessions: usize,
}

#[derive(Deserialize)]
struct RelayView {
    mode: String,
    simulated: bool,
    #[serde(default)]
    hops: Vec<RelayHopView>,
    #[serde(default)]
    property_claimed: Option<String>,
    #[serde(default)]
    property_not_held: Option<String>,
    #[serde(default)]
    real_relay_milestone: Option<String>,
}

#[derive(Deserialize)]
struct RelayHopView {
    role: String,
    #[serde(default)]
    knows: Vec<String>,
}

#[derive(Deserialize)]
struct DnsProtectionView {
    state: String,
    milestone: String,
}

#[derive(Deserialize)]
struct ObservationView {
    transport: String,
    udp_quic: String,
    content_inspection: bool,
    dns_logging: bool,
}

#[derive(Deserialize)]
struct NetworkStatusView {
    enforcement: NetworkEnforcement,
    relay: RelayView,
    dns_protection: DnsProtectionView,
    observation: ObservationView,
}

fn plain_enum(value: &str) -> String {
    value.replace('_', " ")
}

fn bool_word(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

pub fn network_status(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let status: NetworkStatusView = parse(result)?;
    let enforcement_slot = if status.enforcement.state == "available" {
        Slot::Ok
    } else {
        Slot::Bad
    };
    let relay_slot = if status.relay.simulated {
        Slot::Warn
    } else {
        Slot::Neutral
    };
    let mut out = fmt::masthead(style, "Network", &personal_context(hostname));
    out.push_str(&fmt::rows(
        style,
        &[
            Row::new(
                "Enforcement",
                &status.enforcement.state,
                enforcement_slot,
                status.enforcement.reason.as_deref().unwrap_or(
                    "kernel nftables · per managed cgroup · outside processes unchanged",
                ),
            ),
            Row::new(
                "Sessions",
                &status.enforcement.installed_sessions.to_string(),
                Slot::Neutral,
                "active managed session policies installed",
            ),
            Row::new(
                "Observation",
                &status.observation.transport,
                Slot::Neutral,
                "on demand · current kernel sockets only",
            ),
            Row::new(
                "UDP / QUIC",
                &plain_enum(&status.observation.udp_quic),
                Slot::Neutral,
                "not inferred from TCP",
            ),
            Row::new(
                "Content",
                bool_word(status.observation.content_inspection),
                Slot::Neutral,
                "no packet or payload inspection",
            ),
            Row::new(
                "DNS logging",
                bool_word(status.observation.dns_logging),
                Slot::Neutral,
                "no DNS history recorded",
            ),
            Row::new(
                "Relay",
                &plain_enum(&status.relay.mode),
                relay_slot,
                if status.relay.simulated {
                    "simulated model · packet path remains direct"
                } else {
                    "direct packet path"
                },
            ),
            Row::new(
                "DNS protection",
                &plain_enum(&status.dns_protection.state),
                Slot::Neutral,
                &format!(
                    "planned for {}",
                    plain_enum(&status.dns_protection.milestone)
                ),
            ),
        ],
    ));
    out.push_str(&fmt::note(
        style,
        "Punar records neither ports nor local addresses · punarctl privacy connections",
    ));
    Ok(out)
}

#[derive(Deserialize)]
struct ZoneView {
    name: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    kind: String,
    #[serde(default)]
    relay_mode: Option<String>,
}

pub fn network_zones(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let zones: Vec<ZoneView> = parse(result)?;
    let mut out = fmt::masthead(style, "Network zones", &personal_context(hostname));
    let rows = zones
        .iter()
        .map(|zone| {
            let detail = [
                Some(plain_enum(&zone.kind)),
                zone.relay_mode
                    .as_deref()
                    .map(|mode| format!("route {}", plain_enum(mode))),
                zone.description.clone(),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" · ");
            Row::new(
                &zone.name,
                zone.display_name.as_deref().unwrap_or(&zone.name),
                Slot::Neutral,
                &detail,
            )
        })
        .collect::<Vec<_>>();
    out.push_str(&fmt::rows(style, &rows));
    out.push_str(&fmt::note(
        style,
        "Membership is CIDR-only · names appear only when trusted zone data supplies them",
    ));
    Ok(out)
}

#[derive(Deserialize)]
struct PolicyView {
    project_id: String,
    rules: Vec<PolicyRuleView>,
    container_network: ContainerNetworkView,
}

#[derive(Deserialize)]
struct PolicyRuleView {
    zone: String,
    decision: String,
    bound_by: String,
    #[serde(default)]
    manifest_decision: Option<String>,
    #[serde(default)]
    policy_decision: Option<String>,
}

#[derive(Deserialize)]
struct ContainerNetworkView {
    mode: String,
    reason: String,
}

pub fn network_policy(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let policy: PolicyView = parse(result)?;
    let mut out = fmt::masthead(
        style,
        "Network policy",
        &format!("{} · {}", hostname, policy.project_id),
    );
    let rows = policy
        .rules
        .iter()
        .map(|rule| {
            let sources = match (&rule.manifest_decision, &rule.policy_decision) {
                (Some(manifest), Some(policy)) => format!(
                    "manifest {} · project policy {} · bound by {}",
                    plain_enum(manifest),
                    plain_enum(policy),
                    plain_enum(&rule.bound_by)
                ),
                (Some(manifest), None) => format!(
                    "manifest {} · bound by {}",
                    plain_enum(manifest),
                    plain_enum(&rule.bound_by)
                ),
                (None, Some(policy)) => format!(
                    "project policy {} · bound by {}",
                    plain_enum(policy),
                    plain_enum(&rule.bound_by)
                ),
                (None, None) => format!("bound by {}", plain_enum(&rule.bound_by)),
            };
            Row::new(
                &rule.zone,
                &plain_enum(&rule.decision),
                decision_slot(&rule.decision),
                &sources,
            )
        })
        .collect::<Vec<_>>();
    out.push_str(&fmt::rows(style, &rows));
    out.push_str(&fmt::rows(
        style,
        &[Row::new(
            "Container",
            &plain_enum(&policy.container_network.mode),
            Slot::Neutral,
            &policy.container_network.reason,
        )],
    ));
    out.push_str(&fmt::note(
        style,
        "Strictest source wins · an absent rule denies · sudo punarctl network apply",
    ));
    Ok(out)
}

#[derive(Deserialize)]
struct ExplainView {
    what: String,
    why: String,
    who: String,
    which_policy: Vec<String>,
    can_you_change_it: String,
    next_step: String,
    decision: String,
    zone: String,
    project: String,
    enforcement: NetworkEnforcement,
}

pub fn network_explain(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let explain: ExplainView = parse(result)?;
    let mut out = fmt::masthead(
        style,
        "Network explain",
        &format!("{} · {}", hostname, explain.project),
    );
    out.push_str(&fmt::rows(
        style,
        &[
            Row::new(
                "Decision",
                &plain_enum(&explain.decision),
                decision_slot(&explain.decision),
                &format!("zone {}", explain.zone),
            ),
            Row::new("What", "", Slot::Neutral, &explain.what),
            Row::new("Why", "", Slot::Neutral, &explain.why),
            Row::new("Who", "", Slot::Neutral, &explain.who),
            Row::new(
                "Policies",
                "",
                Slot::Neutral,
                &explain.which_policy.join(" · "),
            ),
            Row::new("Change", "", Slot::Neutral, &explain.can_you_change_it),
            Row::new(
                "Enforcement",
                &explain.enforcement.state,
                if explain.enforcement.state == "available" {
                    Slot::Ok
                } else {
                    Slot::Bad
                },
                explain
                    .enforcement
                    .reason
                    .as_deref()
                    .unwrap_or("kernel policy available"),
            ),
        ],
    ));
    out.push_str(&fmt::note(
        style,
        &format!("Next step · {}", explain.next_step),
    ));
    Ok(out)
}

#[derive(Deserialize)]
struct ApplyView {
    installed_sessions: usize,
    #[serde(default)]
    skipped_sessions: Vec<SkippedSessionView>,
    #[serde(default)]
    warnings: Vec<ApplyWarningView>,
}

#[derive(Deserialize)]
struct SkippedSessionView {
    session_id: String,
    reason: String,
}

#[derive(Deserialize)]
struct ApplyWarningView {
    session_id: String,
    project: String,
    fallback: String,
    reason: String,
}

pub fn network_apply(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let applied: ApplyView = parse(result)?;
    let mut out = fmt::masthead(style, "Network apply", &personal_context(hostname));
    out.push_str(&fmt::rows(
        style,
        &[Row::new(
            "Installed",
            &applied.installed_sessions.to_string(),
            Slot::Ok,
            "managed session policies in one nftables transaction",
        )],
    ));
    for warning in &applied.warnings {
        out.push_str(&fmt::rows(
            style,
            &[Row::new(
                &warning.project,
                &plain_enum(&warning.fallback),
                Slot::Warn,
                &format!("{} · {}", warning.session_id, warning.reason),
            )],
        ));
    }
    for skipped in &applied.skipped_sessions {
        out.push_str(&fmt::rows(
            style,
            &[Row::new(
                &skipped.session_id,
                "skipped",
                Slot::Warn,
                &skipped.reason,
            )],
        ));
    }
    out.push_str(&fmt::verdict(
        style,
        if applied.warnings.is_empty() && applied.skipped_sessions.is_empty() {
            Slot::Ok
        } else {
            Slot::Warn
        },
        "✓ Kernel network policy reconciled",
    ));
    Ok(out)
}

pub fn relay_status(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let relay: RelayView = parse(result)?;
    let mut out = fmt::masthead(style, "Relay", &personal_context(hostname));
    out.push_str(&fmt::rows(
        style,
        &[Row::new(
            "Mode",
            &plain_enum(&relay.mode),
            if relay.simulated {
                Slot::Warn
            } else {
                Slot::Neutral
            },
            if relay.simulated {
                "simulated model · packet path remains direct"
            } else {
                "direct packet path"
            },
        )],
    ));
    for hop in &relay.hops {
        out.push_str(&fmt::rows(
            style,
            &[Row::new(
                &hop.role,
                "knows",
                Slot::Neutral,
                &hop.knows
                    .iter()
                    .map(|v| plain_enum(v))
                    .collect::<Vec<_>>()
                    .join(" · "),
            )],
        ));
    }
    if let Some(claim) = &relay.property_claimed {
        out.push_str(&fmt::note(style, claim));
    }
    if let Some(not_held) = &relay.property_not_held {
        out.push_str(&fmt::verdict(
            style,
            Slot::Warn,
            &format!("Simulated · {not_held}"),
        ));
    }
    if let Some(milestone) = &relay.real_relay_milestone {
        out.push_str(&fmt::note(
            style,
            &format!(
                "Independent relay trust boundaries · {}",
                plain_enum(milestone)
            ),
        ));
    }
    Ok(out)
}

#[derive(Deserialize)]
struct ConnectionsView {
    scanned_at: String,
    enforcement: String,
    #[serde(default)]
    enforcement_reason: Option<String>,
    relay: RelayView,
    dns_protection: DnsProtectionView,
    transport: String,
    #[serde(default)]
    limitations: Vec<String>,
    #[serde(default)]
    processes: Vec<NetworkProcessView>,
}

#[derive(Deserialize)]
struct NetworkProcessView {
    name: String,
    pid_class: String,
    #[serde(default)]
    session: Option<NetworkSessionView>,
    governed: bool,
    #[serde(default)]
    connections: Vec<NetworkConnectionView>,
    #[serde(default)]
    denied: Vec<NetworkDeniedView>,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Deserialize)]
struct NetworkSessionView {
    id: String,
    project: String,
}

#[derive(Deserialize)]
struct NetworkConnectionView {
    destination: String,
    #[serde(default)]
    name: Option<String>,
    zone: String,
    category: String,
    route: String,
    state: String,
}

#[derive(Deserialize)]
struct NetworkDeniedView {
    zone: String,
    kind: String,
    attempts: u64,
    #[serde(default)]
    last_destination: Option<String>,
    explain: String,
}

/// `punarctl privacy connections` — a bounded, on-demand TCP view. The wire
/// types deliberately contain no local address, port, uid, pid, cgroup, DNS
/// history, or packet content, so this renderer cannot accidentally expose it.
pub fn privacy_connections(
    style: &Style,
    result: &Value,
    hostname: &str,
) -> Result<String, String> {
    let connections: ConnectionsView = parse(result)?;
    let mut out = fmt::masthead(style, "Connections", &personal_context(hostname));
    out.push_str(&fmt::rows(
        style,
        &[
            Row::new(
                "Scanned",
                "",
                Slot::Neutral,
                &fmt::timestamp(&connections.scanned_at),
            ),
            Row::new(
                "Enforcement",
                &connections.enforcement,
                if connections.enforcement == "available" {
                    Slot::Ok
                } else {
                    Slot::Bad
                },
                connections
                    .enforcement_reason
                    .as_deref()
                    .unwrap_or("per managed cgroup"),
            ),
            Row::new(
                "Transport",
                &connections.transport,
                Slot::Neutral,
                "current sockets · on demand",
            ),
            Row::new(
                "Relay",
                &plain_enum(&connections.relay.mode),
                if connections.relay.simulated {
                    Slot::Warn
                } else {
                    Slot::Neutral
                },
                if connections.relay.simulated {
                    "simulated · actual packet path direct"
                } else {
                    "direct"
                },
            ),
            Row::new(
                "DNS protection",
                &plain_enum(&connections.dns_protection.state),
                Slot::Neutral,
                &format!(
                    "planned for {}",
                    plain_enum(&connections.dns_protection.milestone)
                ),
            ),
        ],
    ));
    if connections.processes.is_empty() {
        out.push_str(&fmt::note(style, "No current TCP connections observed"));
    }
    for process in &connections.processes {
        let context = process.session.as_ref().map_or_else(
            || format!("{} · unmanaged", plain_enum(&process.pid_class)),
            |session| format!("{} · {}", session.project, session.id),
        );
        out.push_str(&fmt::section(
            style,
            &process.name,
            &format!(
                "{} · {}",
                if process.governed {
                    "governed"
                } else {
                    "not governed"
                },
                context
            ),
        ));
        if process.connections.is_empty() && process.denied.is_empty() {
            out.push_str(&fmt::note(
                style,
                process
                    .note
                    .as_deref()
                    .unwrap_or("No current TCP connections"),
            ));
        }
        let rows = process
            .connections
            .iter()
            .map(|connection| {
                Row::new(
                    connection
                        .name
                        .as_deref()
                        .unwrap_or(&connection.destination),
                    &plain_enum(&connection.state),
                    Slot::Neutral,
                    &format!(
                        "{} · {} · {} · {}",
                        connection.destination,
                        plain_enum(&connection.zone),
                        plain_enum(&connection.category),
                        plain_enum(&connection.route)
                    ),
                )
            })
            .collect::<Vec<_>>();
        out.push_str(&fmt::rows(style, &rows));
        let denied = process
            .denied
            .iter()
            .map(|denial| {
                Row::new(
                    &denial.zone,
                    &format!("DENIED · {}", denial.attempts),
                    Slot::Bad,
                    &format!(
                        "{}{} · {}",
                        plain_enum(&denial.kind),
                        denial
                            .last_destination
                            .as_deref()
                            .map(|destination| format!(" · last {destination}"))
                            .unwrap_or_default(),
                        denial.explain
                    ),
                )
            })
            .collect::<Vec<_>>();
        out.push_str(&fmt::rows(style, &denied));
    }
    for limitation in &connections.limitations {
        out.push_str(&fmt::note(style, limitation));
    }
    out.push_str(&fmt::note(
        style,
        "No ports · no local addresses · no payloads · no DNS history · no export method",
    ));
    Ok(out)
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
    // Two clocks, deliberately (milestone-10.md section 3.4): `scanned_at`
    // is the view as of the last CHANGE — a pass that changes nothing
    // writes nothing — and `last_scan_at` is when a pass last actually
    // ran, which only the socket can answer because no file records it.
    let liveness = match (&list.last_scan_at, &list.last_scan_trigger) {
        (Some(at), Some(trigger)) if !at.is_empty() => {
            format!(" · last pass {} ({trigger})", fmt::timestamp(at))
        }
        (Some(at), None) if !at.is_empty() => format!(" · last pass {}", fmt::timestamp(at)),
        _ => String::new(),
    };
    out.push_str(&fmt::note(
        style,
        &format!(
            "{} session{} · {suspected} suspected · last change {}{liveness}",
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
                "Network authority is enforced for managed agent scopes · \
                 credential labels state their own enforcement status",
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

// ---------------------------------------------------------------------
// Milestone 10 — the shadow-AI alert register (contract section 17.1;
// Plate D-009 in terminal grammar).
//
// The card the shell draws and this register are the same record read two
// ways, and the voice rules are the same on both: the word *suspected*
// appears, the subject of every sentence is the process rather than the
// person, and `nothing was blocked` is printed because M10 is not armed
// (milestone-10.md law 4). A red line that cannot act is honest; a red
// line that implies it acted is not.
// ---------------------------------------------------------------------

/// The two sentences every alert surface must carry, in the CLI's voice.
const ALERT_FOOTER: &str = "Suspected, not certain · nothing was blocked · \
                            punarctl agents list";

/// `punarctl agents alerts [--all]` — the register behind the card.
pub fn agents_alerts(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let list: model::AlertsList = parse(result)?;
    let mut out = fmt::masthead(style, "AI Alerts", &personal_context(hostname));

    let live = list.alerts.iter().filter(|a| a.state == "live").count();
    out.push_str(&fmt::section(
        style,
        "Unknown AI · suspected",
        &format!(
            "{} · {live} live",
            plural(list.alerts.len() as u64, "alert", "alerts")
        ),
    ));

    if list.alerts.is_empty() {
        out.push_str(&fmt::note(
            style,
            "No alerts · nothing unmanaged has been suspected on this device",
        ));
        out.push_str(&fmt::note(style, DETECTION_NOTE));
        return Ok(out);
    }

    let rows: Vec<Row> = list
        .alerts
        .iter()
        .map(|alert| {
            let state = match alert.state.as_str() {
                // The state word carries the verdict; the slot follows it.
                "live" => Slot::Bad,
                "cleared" => Slot::Warn,
                _ => Slot::Neutral,
            };
            // The executable path is Level-1 LOCAL data: the user sees
            // it here and on the card, and the export carries a zone
            // class instead (milestone-10.md section 8.3 point 3).
            let mut tail = vec![
                format!("{} · running as {}", alert.executable, alert.owner),
                format!("signature {} · {}", alert.signature, alert.signature_id),
                format!(
                    "first seen {} · last seen {}",
                    fmt::timestamp(&alert.first_seen),
                    fmt::timestamp(&alert.last_seen)
                ),
                format!(
                    "{} live · latest {}",
                    alert.live,
                    alert.detection_id.to_uppercase()
                ),
                format!("raised {}", fmt::timestamp(&alert.raised_at)),
            ];
            if let Some(at) = alert.cleared_at.as_deref() {
                tail.push(format!("cleared {}", fmt::timestamp(at)));
            }
            if alert.state == "dismissed" {
                if let Some(at) = alert.dismissed_at.as_deref() {
                    // "I clicked it away and now I cannot find it" has an
                    // answer, and the answer is this line.
                    tail.push(format!("filed {} · not deleted", fmt::timestamp(at)));
                }
            } else if let Some(until) = alert.quiet_until.as_deref() {
                tail.push(format!("quiet until {}", fmt::timestamp(until)));
            }
            Row::new(
                &alert.alert_id,
                &format!("{} · {}", alert.agent, alert.state),
                state,
                &tail.join(" · "),
            )
        })
        .collect();
    out.push_str(&fmt::rows(style, &rows));

    let citation = list
        .alerts
        .first()
        .map(|a| policy_words(&a.policy_citation))
        .unwrap_or_else(|| "personal defaults".to_string());
    out.push_str(&fmt::rows(
        style,
        &[
            Row::new(
                "Policy",
                &citation,
                Slot::Neutral,
                "the citation the card carries",
            ),
            Row::new(
                "Anti-nag",
                &format!("{} h", list.quiet_window_secs / 3600),
                Slot::Neutral,
                "one alert per signature · a sighting inside the window updates the \
                 record silently",
            ),
        ],
    ));
    out.push_str(&fmt::note(style, ALERT_FOOTER));
    out.push_str(&fmt::note(style, DETECTION_NOTE));
    Ok(out)
}

/// `punarctl agents alerts dismiss <alr_id>` — filing, never deleting.
pub fn agent_alert_dismissed(style: &Style, result: &Value) -> Result<String, String> {
    let filed: model::AlertDismissed = parse(result)?;
    let mut out = fmt::verdict(
        style,
        Slot::Ok,
        "dismissed · filed to the record · not deleted",
    );
    out.push_str(&fmt::rows(
        style,
        &[
            Row::new(
                "Alert",
                &filed.alert_id,
                Slot::Neutral,
                &format!("filed {}", fmt::timestamp(&filed.dismissed_at)),
            ),
            Row::new(
                "Suppression",
                if filed.suppression_changed {
                    "changed"
                } else {
                    "unchanged"
                },
                Slot::Neutral,
                "dismissing files a card · it was never going to be raised twice",
            ),
        ],
    ));
    out.push_str(&fmt::note(
        style,
        "Still listed by `punarctl agents alerts --all`, and still in the detection record",
    ));
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

// ---------------------------------------------------------------------
// Milestone 9 — approvals, just-in-time privilege, the secret broker
// (contract sections 14, 16; Plates D-003, D-012, D-014 register 05).
// ---------------------------------------------------------------------

/// SPEC section 28 statuses on the terminal semantic slots. `pending` is
/// the peach/amber "waiting on a human" register; `expired` is red
/// because expiry **is** a denial, not a neutral lapse (Plate D-003:
/// "Expired · denied by timeout").
fn approval_slot(status: &str) -> Slot {
    match status {
        "approved" => Slot::Ok,
        "pending" => Slot::Warn,
        "denied" | "expired" => Slot::Bad,
        _ => Slot::Neutral,
    }
}

/// Risk pill colors (Plate D-003 draws `Medium` in warn-amber). An
/// unrecognized word stays calm rather than guessing a severity.
fn risk_slot(risk: &str) -> Slot {
    match risk {
        "high" | "critical" => Slot::Bad,
        "medium" => Slot::Warn,
        _ => Slot::Neutral,
    }
}

/// Seconds from now until `expires_at`, negative once it has lapsed.
/// `None` when the timestamp is missing or unparsable — the view then
/// prints the raw stamp and no countdown, because a formatter that
/// invents a clock is worse than one that omits it.
fn seconds_until(expires_at: &str) -> Option<i64> {
    let deadline = punar_common::time::unix_seconds_from_rfc3339(expires_at)? as i64;
    let now = (punar_common::time::unix_now_millis() / 1000) as i64;
    Some(deadline - now)
}

/// `M:SS` in the tabular register Plate D-003 draws in the masthead. Past
/// zero it reads `0:00` — the card then says `EXPIRED` in words, never a
/// negative clock.
pub fn countdown(seconds: i64) -> String {
    let s = seconds.max(0);
    format!("{}:{:02}", s / 60, s % 60)
}

/// Prose spelling of a remaining window: `4m 59s`, `45s`, `expired`.
fn remaining_words(seconds: i64) -> String {
    if seconds <= 0 {
        return "expired".to_string();
    }
    if seconds < 60 {
        return format!("{seconds}s");
    }
    format!("{}m {}s", seconds / 60, seconds % 60)
}

/// The `capability(resource)` spelling of Plate D-003's contract block —
/// `security.firewall(disabled)`, `credential.request(aws-dev)`,
/// `time.timezone(15m)`. `resource` semantics are defined once for all
/// three kinds (contract section 14.3), which is exactly why one
/// formatter can serve them all.
fn typed_call(capability: &str, resource: &str) -> String {
    if resource.is_empty() {
        capability.to_string()
    } else {
        format!("{capability}({resource})")
    }
}

/// The contract line an approval carries, falling back to the typed call
/// when the daemon sent none. Never invented: the fallback is derived
/// from fields the record already holds.
fn contract_line(env: &model::ApprovalEnvelope) -> String {
    if env.contract.is_empty() {
        typed_call(&env.approval.capability, &env.approval.resource)
    } else {
        env.contract.clone()
    }
}

/// The Plate D-003 identity chain, on one line: principal kind, agent
/// name, session id, routed user. Only the parts the record actually
/// carries are printed — an absent project is absent, not a placeholder.
/// `agent_name` is normally ABSENT here: `schemas/audit/approval.json`'s
/// requester carries `{type, id}` only, and punard deliberately keeps the
/// friendly name out of the root-owned surfaces (it lives in the
/// world-writable `agents.json`, so putting it on an authorization
/// surface would be a spoofing primitive). The chain therefore keys on
/// the kernel-attested `agt_` id, and prints a display name only if one
/// was actually supplied.
fn identity_chain(doc: &model::ApprovalDoc) -> String {
    let mut parts = Vec::new();
    parts.push(match doc.requester.kind.as_str() {
        "ai_agent" => "AI agent".to_string(),
        "user" => "User".to_string(),
        "" => "Requester".to_string(),
        other => other.replace('_', " "),
    });
    if !doc.requester.agent_name.is_empty() {
        parts.push(doc.requester.agent_name.clone());
    }
    if !doc.requester.id.is_empty() {
        parts.push(doc.requester.id.clone());
    }
    if !doc.user.is_empty() {
        parts.push(doc.user.clone());
    }
    parts.join(" · ")
}

/// The policy citation, in the section 8 unmanaged-first voice: personal
/// mode reads `personal defaults`, an enrolled device reads the org's own
/// name. Whatever the daemon cites is printed — the CLI never upgrades a
/// personal citation into an organizational one.
fn policy_citation(env: &model::ApprovalEnvelope) -> String {
    match &env.policy {
        Some(p) if !p.name.is_empty() && !p.policy_id.is_empty() => {
            let id = policy_words(&p.policy_id);
            // `Personal defaults · personal defaults` says one thing
            // twice. When the machine id humanizes to the display name,
            // the citation prints once.
            if id.eq_ignore_ascii_case(&p.name) {
                p.name.clone()
            } else {
                format!("{} · {id}", p.name)
            }
        }
        Some(p) if !p.name.is_empty() => p.name.clone(),
        Some(p) if !p.policy_id.is_empty() => policy_words(&p.policy_id),
        _ => "personal defaults".to_string(),
    }
}

/// The quoted requester voice (milestone-9.md section 8.3). The reason is
/// requester-authored text and it **is** shown — SPEC section 73 requires
/// *why* and *who requested it*, and a gate whose justification is hidden
/// is a rubber stamp. It is quoted and attributed so that requester prose
/// can never be mistaken for system prose, and the daemon has already
/// refused control characters and newlines at creation time.
fn quoted_reason(doc: &model::ApprovalDoc) -> Option<String> {
    if doc.reason.is_empty() {
        return None;
    }
    let who = if !doc.requester.agent_name.is_empty() {
        doc.requester.agent_name.clone()
    } else if doc.requester.kind == "ai_agent" {
        // The attested id, not a friendly name — see `identity_chain`.
        if doc.requester.id.is_empty() {
            "The AI agent".to_string()
        } else {
            doc.requester.id.clone()
        }
    } else if !doc.user.is_empty() {
        doc.user.clone()
    } else {
        "The requester".to_string()
    };
    Some(format!("{who} says: \"{}\"", doc.reason))
}

/// The one-sentence request line — Plate D-003's `.req`, derived from the
/// record rather than stored, so it can never disagree with the contract
/// block beneath it.
fn request_sentence(env: &model::ApprovalEnvelope) -> String {
    let doc = &env.approval;
    let who = if !doc.requester.agent_name.is_empty() {
        doc.requester.agent_name.clone()
    } else if doc.requester.kind == "ai_agent" {
        // The requester row above carries the attested id, so the
        // sentence says what KIND of principal is asking rather than
        // repeating it: the card names the requester once, precisely.
        "This AI agent".to_string()
    } else if !doc.user.is_empty() {
        doc.user.clone()
    } else {
        "A requester".to_string()
    };
    match env.kind.as_str() {
        "credential_request" => format!("{who} wants a short-lived {} credential.", doc.resource),
        "privilege_request" => format!(
            "{who} is requesting {} for {}.",
            doc.capability, doc.resource
        ),
        _ => format!("{who} wants to set {} to {}.", doc.capability, doc.resource),
    }
}

/// The verdict line of a resolved approval, in Plate D-003's exact
/// wording — including the audit pointer, which is what makes the card
/// and the trail one story.
fn approval_verdict(style: &Style, env: &model::ApprovalEnvelope) -> String {
    let doc = &env.approval;
    let call = contract_line(env);
    let audit = env
        .execution
        .as_ref()
        .and_then(|e| e.audit_event_id.clone())
        .map(|id| format!(" · audit {id}"))
        .unwrap_or_default();
    match doc.status.as_str() {
        "approved" => {
            let outcome = match env.execution.as_ref() {
                // A credential approval is flipped by punard and spent
                // later by the broker (contract section 14.6): there is
                // no execution to claim, and the card must not invent one.
                None if env.kind == "credential_request" => {
                    if env.consumed_at.is_some() {
                        "credential issued".to_string()
                    } else {
                        "awaiting issuance".to_string()
                    }
                }
                None => "approved".to_string(),
                Some(e) if e.result == "success" => {
                    // `changed: false` is a real, honest outcome: the
                    // capability was already in the requested state, so
                    // the card says so rather than claiming a mutation.
                    if e.changed == Some(false) {
                        format!("{call} · already in that state")
                    } else {
                        format!("{call} executed")
                    }
                }
                Some(e) => {
                    let why = e.error.clone().unwrap_or_else(|| e.result.clone());
                    return fmt::verdict(
                        style,
                        Slot::Bad,
                        &format!("Approved, but not applied · {why}{audit}"),
                    );
                }
            };
            let grant = env
                .execution
                .as_ref()
                .and_then(|e| e.grant_id.clone())
                .map(|id| format!(" · grant {id}"))
                .unwrap_or_default();
            fmt::verdict(
                style,
                Slot::Ok,
                &format!("✓ Approved · {outcome}{grant}{audit}"),
            )
        }
        "denied" => fmt::verdict(
            style,
            Slot::Bad,
            &format!("Denied · nothing executed{audit}"),
        ),
        "expired" => fmt::verdict(
            style,
            Slot::Bad,
            &format!("Expired · denied by timeout · nothing executed{audit}"),
        ),
        _ => String::new(),
    }
}

/// The contract card body shared by `approvals get` and `approvals wait`
/// — Plate D-003 Sect II in terminal grammar, and Plate D-014 register 05
/// verbatim: who is asking, for what, under which policy, for how long,
/// and what exactly happens on yes.
///
/// `eligible` decides whether the `[A]` / `[D]` affordance is drawn.
/// Resolution is human-only (contract section 14.5), so an agent running
/// this command sees the card and the countdown and **no buttons**. The
/// affordance is display only: the daemon is the authorization point and
/// re-checks every rule regardless of what was printed here.
fn approval_card(style: &Style, env: &model::ApprovalEnvelope, eligible: bool) -> String {
    let doc = &env.approval;
    let mut out = String::new();

    let remaining = seconds_until(&doc.expires_at);
    let expiry_cell = match remaining {
        Some(s) if doc.status == "pending" && s > 0 => {
            format!(
                "expires {} · {} left",
                fmt::timestamp(&doc.expires_at),
                countdown(s)
            )
        }
        Some(_) if doc.status == "pending" => {
            format!("expired {}", fmt::timestamp(&doc.expires_at))
        }
        _ => fmt::timestamp(&doc.expires_at),
    };

    let mut rows = vec![
        Row::new(
            "Approval",
            &doc.approval_id,
            approval_slot(&doc.status),
            &format!(
                "{}{}",
                if doc.status.is_empty() {
                    "pending"
                } else {
                    &doc.status
                },
                if env.kind.is_empty() {
                    String::new()
                } else {
                    format!(" · {}", env.kind.replace('_', " "))
                }
            ),
        ),
        Row::new(
            "Requester",
            &doc.requester.kind.replace('_', " "),
            Slot::Neutral,
            &if env.created_at.is_empty() {
                identity_chain(doc)
            } else {
                format!(
                    "{} · requested {}",
                    identity_chain(doc),
                    fmt::timestamp(&env.created_at)
                )
            },
        ),
        // The value column uppercases by grammar, so the exact typed
        // call — the thing that will actually run — sits in the
        // description column where its spelling survives verbatim.
        Row::new(
            "Capability",
            &doc.capability,
            Slot::Neutral,
            &contract_line(env),
        ),
        Row::new("Policy", "", Slot::Neutral, &policy_citation(env)),
        Row::new("Expiry", "", Slot::Neutral, &expiry_cell),
    ];
    if !doc.risk.is_empty() {
        rows.insert(1, Row::new("Risk", &doc.risk, risk_slot(&doc.risk), ""));
    }
    out.push_str(&fmt::rows(style, &rows));

    // Plate D-003's `.req` — one plain sentence in the SYSTEM voice,
    // derived from the record so it can never disagree with the contract
    // block beneath it.
    out.push('\n');
    out.push_str(&format!("  {}\n", request_sentence(env)));

    // The requester's own words, quoted and attributed — never in the
    // system voice, never formatted as a system statement. Requester
    // prose and system prose never share a line on this surface.
    if let Some(reason) = quoted_reason(doc) {
        out.push_str(&format!("  {reason}\n"));
    }

    // The contract block: what runs on yes, under which policy, and the
    // audit promise that holds either way.
    out.push('\n');
    out.push_str(&fmt::section(
        style,
        "Contract · what happens on yes",
        "spec 28",
    ));
    out.push_str(&fmt::note(
        style,
        &format!("One-time execution · {}", contract_line(env)),
    ));
    out.push_str(&fmt::note(
        style,
        &format!("Policy · {}", policy_citation(env)),
    ));
    out.push_str(&fmt::note(style, "Recorded to local audit either way"));

    if doc.status == "pending" {
        out.push('\n');
        if eligible {
            out.push_str(&fmt::note(
                style,
                &format!(
                    "[A] punarctl approvals resolve {} --decision approved",
                    doc.approval_id
                ),
            ));
            out.push_str(&fmt::note(
                style,
                &format!(
                    "[D] punarctl approvals resolve {} --decision denied",
                    doc.approval_id
                ),
            ));
        } else {
            // Not a refusal to render — a statement of who may act. The
            // agent that raised this request is told, in the section 73
            // voice, that it is not the one who answers.
            out.push_str(&fmt::note(
                style,
                "Only a human at this device may resolve this — an AI agent may resolve nothing",
            ));
            out.push_str(&fmt::note(
                style,
                &format!("Routed to {} · answer it in the approval overlay", doc.user),
            ));
        }
    } else {
        out.push_str(&approval_verdict(style, env));
    }
    out
}

/// `punarctl approvals list` — pending first, then recently resolved.
pub fn approvals_list(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let list: model::ApprovalsList = parse(result)?;
    let mut out = fmt::masthead(style, "Approvals", &personal_context(hostname));

    let pending = list
        .approvals
        .iter()
        .filter(|e| e.approval.status == "pending")
        .count();
    out.push_str(&fmt::section(
        style,
        "Approvals · what is waiting on you",
        &format!("{pending} pending"),
    ));

    if list.approvals.is_empty() {
        out.push_str(&fmt::note(
            style,
            "No approvals pending — nothing is gated right now",
        ));
        return Ok(out);
    }

    let rows: Vec<Row> = list
        .approvals
        .iter()
        .map(|env| {
            let doc = &env.approval;
            let tail = match seconds_until(&doc.expires_at) {
                Some(s) if doc.status == "pending" => {
                    format!("{} · {} left", contract_line(env), remaining_words(s))
                }
                _ => contract_line(env),
            };
            Row::new(
                &doc.approval_id,
                &doc.status,
                approval_slot(&doc.status),
                &format!("{tail} · {}", identity_chain(doc)),
            )
        })
        .collect();
    out.push_str(&fmt::rows(style, &rows));
    let checked = if list.checked_at.is_empty() {
        String::new()
    } else {
        format!(" · read {}", fmt::timestamp(&list.checked_at))
    };
    out.push_str(&fmt::note(
        style,
        &format!(
            "{} recorded · a pending approval executes nothing until a human answers{checked}",
            list.approvals.len()
        ),
    ));
    Ok(out)
}

/// `punarctl approvals get <apr_id>` — the full contract card.
pub fn approval_get(
    style: &Style,
    result: &Value,
    hostname: &str,
    eligible: bool,
) -> Result<String, String> {
    let env: model::ApprovalEnvelope = parse(result)?;
    let mut out = fmt::masthead(style, "Approval", &personal_context(hostname));
    out.push_str(&approval_card(style, &env, eligible));
    Ok(out)
}

/// `punarctl approvals wait <apr_id>` — Plate D-014 register 05. Same
/// card, redrawn on each wake, with the countdown live.
pub fn approval_wait(
    style: &Style,
    result: &Value,
    hostname: &str,
    eligible: bool,
) -> Result<String, String> {
    approval_get(style, result, hostname, eligible)
}

/// `punarctl approvals resolve <apr_id> --decision …` — the verdict, and
/// the audit pointer that ties it to the trail.
pub fn approval_resolved(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let env: model::ApprovalEnvelope = parse(result)?;
    let mut out = fmt::masthead(style, "Approval", &personal_context(hostname));
    let doc = &env.approval;
    let mut rows = vec![
        Row::new(
            "Approval",
            &doc.approval_id,
            approval_slot(&doc.status),
            &contract_line(&env),
        ),
        Row::new("Requester", "", Slot::Neutral, &identity_chain(doc)),
    ];
    if let Some(by) = &env.resolved_by {
        let mut who = Vec::new();
        if !by.user.is_empty() {
            who.push(by.user.clone());
        }
        if let Some(uid) = by.uid {
            who.push(format!("uid {uid}"));
        }
        if let Some(pid) = by.pid {
            who.push(format!("pid {pid}"));
        }
        rows.push(Row::new("Resolved by", "", Slot::Neutral, &who.join(" · ")));
    }
    if let Some(at) = &env.resolved_at {
        rows.push(Row::new(
            "Resolved at",
            "",
            Slot::Neutral,
            &fmt::timestamp(at),
        ));
    }
    out.push_str(&fmt::rows(style, &rows));
    out.push_str(&approval_verdict(style, &env));
    out.push_str(&fmt::note(
        style,
        "The agent did it · the human allowed it · the trail says both",
    ));
    Ok(out)
}

/// The **exit 4** surface: a gated call created an approval and executed
/// nothing (contract section 14.1). This is not a failure report — it is
/// the section 73 four beats for a request that is alive and waiting:
/// what is pending, who must decide, how long it lasts, what to do next.
///
/// `message` is the daemon's own prose and is printed verbatim; the rows
/// beneath it are the machine facts from `error.details`.
pub fn approval_required(
    style: &Style,
    message: &str,
    details: Option<&Value>,
    hostname: &str,
) -> String {
    let mut out = fmt::masthead(style, "Approval required", &personal_context(hostname));
    if !message.is_empty() {
        out.push_str(message);
        if !message.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
    }

    let get = |key: &str| -> String {
        details
            .and_then(|d| d.get(key))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let approval_id = get("approval_id");
    let expires_at = get("expires_at");
    let capability = get("capability");
    let resource = get("resource");
    let decision = get("decision");
    let policy_ids: Vec<String> = details
        .and_then(|d| d.get("policy_ids"))
        .and_then(Value::as_array)
        .map(|ids| {
            ids.iter()
                .filter_map(Value::as_str)
                .map(policy_words)
                .collect()
        })
        .unwrap_or_default();

    let mut rows = Vec::new();
    if !approval_id.is_empty() {
        rows.push(Row::new(
            "Approval",
            &approval_id,
            Slot::Warn,
            "pending · nothing has been executed",
        ));
    }
    if !capability.is_empty() {
        rows.push(Row::new(
            "Capability",
            &typed_call(&capability, &resource),
            Slot::Neutral,
            "",
        ));
    }
    if !decision.is_empty() {
        rows.push(Row::new(
            "Decision",
            &decision,
            decision_slot(&decision),
            "the effective AI authority for this capability",
        ));
    }
    if !policy_ids.is_empty() {
        rows.push(Row::new(
            "Policy",
            "",
            Slot::Neutral,
            &policy_ids.join(" · "),
        ));
    }
    if !expires_at.is_empty() {
        let cell = match seconds_until(&expires_at) {
            Some(s) if s > 0 => format!(
                "{} · {} left to answer",
                fmt::timestamp(&expires_at),
                remaining_words(s)
            ),
            _ => format!("{} · elapsed", fmt::timestamp(&expires_at)),
        };
        rows.push(Row::new("Expires", "", Slot::Neutral, &cell));
    }
    if !rows.is_empty() {
        out.push_str(&fmt::rows(style, &rows));
    }

    // The loudest sentence on this surface, in the loud register: the
    // call did not happen. Exit 4 is not "it failed" and not "it worked".
    out.push_str(&fmt::verdict(
        style,
        Slot::Warn,
        "Pending · nothing has been executed",
    ));
    out.push_str(&fmt::note(
        style,
        "A human at this device decides · an AI agent may resolve nothing",
    ));
    if approval_id.is_empty() {
        out.push_str(&fmt::note(
            style,
            "Next step: punarctl approvals list — or answer it in the approval overlay",
        ));
    } else {
        out.push_str(&fmt::note(
            style,
            &format!(
                "Next step: punarctl approvals wait {approval_id} — or answer it in the approval overlay"
            ),
        ));
    }
    out
}

/// `punarctl privilege status` — the live grants, with what is left of
/// each. Privilege is visible for exactly as long as it exists.
pub fn privilege_status(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let status: model::PrivilegeStatus = parse(result)?;
    let mut out = fmt::masthead(style, "Privilege", &personal_context(hostname));
    out.push_str(&fmt::section(
        style,
        "Elevation · privilege you hold right now",
        "spec 48",
    ));
    if status.grants.is_empty() {
        out.push_str(&fmt::note(
            style,
            "No active grants — this device has no permanent administrator",
        ));
        out.push_str(&fmt::note(
            style,
            "Next step: punarctl privilege request --capability <id> --reason \"<why>\"",
        ));
        return Ok(out);
    }
    let rows: Vec<Row> = status
        .grants
        .iter()
        .map(|g| {
            let left = seconds_until(&g.expires_at);
            let slot = match left {
                Some(s) if s <= 0 => Slot::Bad,
                Some(s) if s < 60 => Slot::Warn,
                _ => Slot::Ok,
            };
            let word = left
                .map(remaining_words)
                .unwrap_or_else(|| "unknown".to_string());
            let mut desc = format!(
                "{} · expires {}",
                g.capability,
                fmt::timestamp(&g.expires_at)
            );
            if !g.granted_at.is_empty() {
                desc = format!("{} · granted {}", desc, fmt::timestamp(&g.granted_at));
            }
            if !g.reason.is_empty() {
                desc.push_str(&format!(" · \"{}\"", g.reason));
            }
            Row::new(&g.grant_id, &word, slot, &desc)
        })
        .collect();
    out.push_str(&fmt::rows(style, &rows));
    let checked = if status.checked_at.is_empty() {
        String::new()
    } else {
        format!(" · read {}", fmt::timestamp(&status.checked_at))
    };
    out.push_str(&fmt::note(
        style,
        &format!("One capability per grant · no wildcard · no root shell to fall back to{checked}"),
    ));
    out.push_str(&fmt::note(
        style,
        "Next step: punarctl privilege revoke <gnt_id> — extending means asking again, with a reason",
    ));
    Ok(out)
}

/// `punarctl privilege revoke` — a grant dropped early, on purpose.
pub fn privilege_revoked(
    style: &Style,
    result: &Value,
    hostname: &str,
    scope: &str,
) -> Result<String, String> {
    let revoke: model::PrivilegeRevoke = parse(result)?;
    let mut out = fmt::masthead(style, "Privilege", &personal_context(hostname));
    let count = revoke.revoked_count.unwrap_or(revoke.revoked.len() as u64);
    let mut rows = vec![Row::new(
        "Revoked",
        &count.to_string(),
        Slot::Ok,
        &format!("{scope} · privilege dropped immediately"),
    )];
    if !revoke.revoked.is_empty() {
        rows.push(Row::new(
            "Grants",
            "",
            Slot::Neutral,
            &revoke.revoked.join(" · "),
        ));
    }
    if !revoke.revoked_at.is_empty() {
        rows.push(Row::new(
            "At",
            "",
            Slot::Neutral,
            &fmt::timestamp(&revoke.revoked_at),
        ));
    }
    out.push_str(&fmt::rows(style, &rows));
    out.push_str(&fmt::verdict(
        style,
        Slot::Ok,
        &format!(
            "Revoked · {count} grant{} dropped",
            if count == 1 { "" } else { "s" }
        ),
    ));
    out.push_str(&fmt::note(style, "Recorded to the local audit log"));
    Ok(out)
}

/// `punarctl secrets list` — the credential classes and their effective
/// decision. **Never values**: after issuance the broker holds only
/// `sha256(token)`, so no method here could return one.
pub fn secrets_list(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let classes: model::CredentialClasses = parse(result)?;
    let mut out = fmt::masthead(style, "Secrets", &personal_context(hostname));
    out.push_str(&fmt::section(
        style,
        "Credential classes · what may be issued",
        "spec 29",
    ));
    if classes.classes.is_empty() {
        out.push_str(&fmt::note(style, "No credential classes are configured"));
        return Ok(out);
    }
    let rows: Vec<Row> = classes
        .classes
        .iter()
        .map(|c| {
            let mut desc = Vec::new();
            if let Some(ttl) = c.default_ttl {
                desc.push(format!("default ttl {ttl}s"));
            }
            if let Some(max) = c.max_ttl {
                desc.push(format!("max {max}s"));
            }
            if !c.policy_key.is_empty() {
                desc.push(format!("policy credentials.{}", c.policy_key));
            }
            if !c.provider.is_empty() {
                desc.push(format!("provider {}", c.provider));
            }
            Row::new(
                &c.credential,
                &c.decision,
                decision_slot(&c.decision),
                &desc.join(" · "),
            )
        })
        .collect();
    out.push_str(&fmt::rows(style, &rows));
    let provider = if classes.provider.is_empty() {
        "mock".to_string()
    } else {
        classes.provider.clone()
    };
    let checked = if classes.checked_at.is_empty() {
        String::new()
    } else {
        format!(" · read {}", fmt::timestamp(&classes.checked_at))
    };
    out.push_str(&fmt::note(
        style,
        &format!(
            "Provider {provider} · simulated · no real credential exists on this device{checked}"
        ),
    ));
    out.push_str(&fmt::note(
        style,
        "Issued values are never listed · the broker keeps only a hash",
    ));
    Ok(out)
}

/// The Plate D-012 issuance card — rendered to **stderr** so that the
/// value on stdout is the whole of stdout (milestone-9.md section 6.4):
/// `TOKEN=$(punarctl secrets get aws-dev)` works, and prose can never
/// contaminate the value.
///
/// The card carries what D-012 draws — class, requester, expiry, the
/// redaction promise, the simulation label — and, exactly as the plate
/// says, it has **no affordance that could show the value**.
pub fn secrets_card(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let issued: model::CredentialIssued = parse(result)?;
    let mut out = fmt::masthead(style, "Credential", &personal_context(hostname));
    let mut rows = vec![Row::new(
        "Credential",
        &issued.credential,
        Slot::Ok,
        "issued once · this value is not retrievable again",
    )];
    if !issued.agent_session_id.is_empty() {
        rows.push(Row::new(
            "Issued to",
            "",
            Slot::Neutral,
            &issued.agent_session_id,
        ));
    }
    if !issued.expires_at.is_empty() {
        let cell = match seconds_until(&issued.expires_at) {
            Some(s) if s > 0 => format!(
                "{} · {} left",
                fmt::timestamp(&issued.expires_at),
                remaining_words(s)
            ),
            _ => fmt::timestamp(&issued.expires_at),
        };
        rows.push(Row::new("Expires", "", Slot::Neutral, &cell));
    }
    let provider = if issued.provider.is_empty() {
        "mock".to_string()
    } else {
        issued.provider.clone()
    };
    rows.push(Row::new(
        "Provider",
        &provider,
        Slot::Warn,
        "not a real credential — nothing on the other end of it",
    ));
    out.push_str(&fmt::rows(style, &rows));
    out.push_str(&fmt::note(style, "Simulated · mock provider"));
    out.push_str(&fmt::note(
        style,
        "Never written to disk · never logged · the value is on stdout and nowhere else",
    ));
    out.push_str(&fmt::note(
        style,
        "Punar never writes it — a shell that redirects stdout to a file does",
    ));
    Ok(out)
}

/// `punarctl secrets validate` — the token arrives on **stdin** and is
/// never echoed back. Only the class, the verdict and the expiry are
/// printed, because they are the only properties worth drawing (D-012).
pub fn secrets_validate(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let v: model::CredentialValidate = parse(result)?;
    let mut out = fmt::masthead(style, "Credential", &personal_context(hostname));
    let mut rows = vec![
        Row::new(
            "Valid",
            if v.valid { "yes" } else { "no" },
            if v.valid { Slot::Ok } else { Slot::Bad },
            "checked against the clock · no timer, no sweep",
        ),
        Row::new("Credential", &v.credential, Slot::Neutral, ""),
    ];
    if !v.expires_at.is_empty() {
        let cell = match seconds_until(&v.expires_at) {
            Some(s) if s > 0 => format!(
                "{} · {} left",
                fmt::timestamp(&v.expires_at),
                remaining_words(s)
            ),
            _ => format!("{} · elapsed", fmt::timestamp(&v.expires_at)),
        };
        rows.push(Row::new("Expires", "", Slot::Neutral, &cell));
    }
    out.push_str(&fmt::rows(style, &rows));
    out.push_str(&fmt::note(
        style,
        "The value was read from stdin and is not echoed · never on argv",
    ));
    Ok(out)
}

/// A credential the broker refused to vouch for: `expired` (the TTL
/// lapsed) or `not_found` (it never issued this value, or already dropped
/// it). Both are legitimate verdicts rather than malfunctions, so the
/// word **INVALID** is rendered by this CLI from the wire `code` and does
/// not depend on the daemon's prose — while the daemon's own section 73
/// sentence is still printed verbatim beneath it.
pub fn secrets_invalid(style: &Style, code: &str, message: &str, hostname: &str) -> String {
    let mut out = fmt::masthead(style, "Credential", &personal_context(hostname));
    let why = match code {
        "expired" => "expired · the lifetime lapsed",
        "not_found" => "not found · the broker holds no such credential",
        other => other,
    };
    out.push_str(&fmt::rows(
        style,
        &[Row::new("Valid", "no", Slot::Bad, why)],
    ));
    if !message.is_empty() {
        out.push_str(message);
        if !message.ends_with('\n') {
            out.push('\n');
        }
    }
    out.push_str(&fmt::note(
        style,
        "The value was read from stdin and is not echoed · never on argv",
    ));
    out
}

/// `punarctl secrets revoke` — the token arrives on stdin, the entry is
/// dropped immediately, and the audit event names the class only.
pub fn secrets_revoked(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let r: model::CredentialRevoke = parse(result)?;
    let mut out = fmt::masthead(style, "Credential", &personal_context(hostname));
    let mut rows = vec![Row::new(
        "Revoked",
        if r.revoked == Some(false) {
            "no"
        } else {
            "yes"
        },
        if r.revoked == Some(false) {
            Slot::Bad
        } else {
            Slot::Ok
        },
        "dropped from the broker immediately",
    )];
    if !r.credential.is_empty() {
        rows.push(Row::new("Credential", &r.credential, Slot::Neutral, ""));
    }
    if !r.revoked_at.is_empty() {
        rows.push(Row::new(
            "At",
            "",
            Slot::Neutral,
            &fmt::timestamp(&r.revoked_at),
        ));
    }
    out.push_str(&fmt::rows(style, &rows));
    out.push_str(&fmt::note(
        style,
        "Recorded to the local audit log · the class only, never the value",
    ));
    Ok(out)
}

/// Local application catalog or installation-state list. The source word is
/// descriptive, never a trust claim; containment appears only in the detail
/// renderer after punard has verified live metadata.
pub fn apps(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let apps = result
        .get("apps")
        .and_then(Value::as_array)
        .ok_or_else(|| "apps result has no apps array".to_string())?;
    let mut out = fmt::masthead(style, "Applications", hostname);
    if apps.is_empty() {
        out.push_str(&fmt::note(style, "No catalog applications matched"));
        return Ok(out);
    }
    let rows: Vec<Row> = apps
        .iter()
        .map(|app| {
            let id = app.get("id").and_then(Value::as_str).unwrap_or("unknown");
            let source = app
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let installed = app.get("installed").and_then(Value::as_bool);
            let (state, slot) = match (source, installed) {
                (_, Some(true)) => ("installed", Slot::Ok),
                ("web", _) => ("web app", Slot::Neutral),
                (_, Some(false)) => ("available", Slot::Neutral),
                _ => (source, Slot::Neutral),
            };
            let name = app.get("name").and_then(Value::as_str).unwrap_or(id);
            let summary = app.get("summary").and_then(Value::as_str).unwrap_or("");
            let description = if summary.is_empty() {
                name.to_string()
            } else {
                format!("{name} · {summary}")
            };
            Row::new(id, state, slot, &description)
        })
        .collect();
    out.push_str(&fmt::rows(style, &rows));
    out.push_str(&fmt::note(
        style,
        "Inspect permissions before install · punarctl app show <id>",
    ));
    Ok(out)
}

pub fn app_detail(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let app = result
        .get("app")
        .and_then(Value::as_object)
        .ok_or_else(|| "apps.catalog result has no app object".to_string())?;
    let text = |key: &str| app.get(key).and_then(Value::as_str).unwrap_or("unknown");
    let mut out = fmt::masthead(style, text("name"), hostname);
    let source = text("source");
    let trust = text("trust_tier");
    let installed = app
        .get("installed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut rows = vec![
        Row::new("Catalog id", text("id"), Slot::Neutral, text("summary")),
        Row::new("Source", source, Slot::Neutral, text("publisher")),
        Row::new(
            "Trust",
            trust,
            if trust == "curated" {
                Slot::Ok
            } else {
                Slot::Warn
            },
            text("license"),
        ),
        Row::new(
            "State",
            if source == "web" {
                "open in browser"
            } else if installed {
                "installed"
            } else {
                "not installed"
            },
            if installed { Slot::Ok } else { Slot::Neutral },
            "",
        ),
    ];
    if let Some(inspection) = app.get("inspection").and_then(Value::as_object) {
        let flatpak_verified = inspection.get("verified").and_then(Value::as_bool) == Some(true);
        let vendor_pinned = inspection.get("pinned").and_then(Value::as_bool) == Some(true)
            && inspection
                .get("verified_on_install")
                .and_then(Value::as_bool)
                == Some(true);
        if flatpak_verified || vendor_pinned {
            let containment = inspection
                .get("containment")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            rows.push(Row::new(
                "Containment",
                containment,
                if matches!(containment, "sandboxed" | "hardened_native") {
                    Slot::Ok
                } else {
                    Slot::Bad
                },
                if flatpak_verified {
                    "computed from the pinned Flatpak metadata"
                } else {
                    "Punar wrapper · isolated home · package verified before extraction"
                },
            ));
            if flatpak_verified {
                rows.push(Row::new(
                    "Runtime",
                    inspection
                        .get("runtime")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown"),
                    Slot::Neutral,
                    "",
                ));
            }
        }
    }
    out.push_str(&fmt::rows(style, &rows));

    if let Some(permissions) = app
        .get("inspection")
        .and_then(|v| v.get("permissions"))
        .and_then(Value::as_array)
    {
        out.push_str(&fmt::section(style, "Permissions", "verified metadata"));
        for permission in permissions.iter().filter_map(Value::as_str) {
            out.push_str(&format!("{}\n", style.muted(&format!("· {permission}"))));
        }
    }
    if let Some(disclosures) = app.get("disclosures").and_then(Value::as_array) {
        for disclosure in disclosures {
            if let Some(message) = disclosure.get("text").and_then(Value::as_str) {
                out.push_str(&fmt::note(style, message));
            }
        }
    }
    if let Some(digest) = app
        .get("inspection")
        .and_then(|v| v.get("metadata_sha256").or_else(|| v.get("package_sha256")))
        .and_then(Value::as_str)
    {
        let label = if source == "vendor_deb" {
            "Package sha256"
        } else {
            "Metadata sha256"
        };
        out.push_str(&fmt::note(style, &format!("{label} · {digest}")));
    }
    Ok(out)
}

pub fn app_mutation(
    style: &Style,
    result: &Value,
    hostname: &str,
    verb: &str,
) -> Result<String, String> {
    let id = result
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| "application mutation result has no id".to_string())?;
    let changed = result
        .get("changed")
        .and_then(Value::as_bool)
        .ok_or_else(|| "application mutation result has no changed state".to_string())?;
    let mut out = fmt::masthead(style, "Application", hostname);
    out.push_str(&fmt::verdict(
        style,
        Slot::Ok,
        &format!(
            "✓ {id} · {}",
            if changed {
                verb.to_string()
            } else {
                "already in that state".to_string()
            }
        ),
    ));
    Ok(out)
}

pub fn app_updates(style: &Style, result: &Value, hostname: &str) -> Result<String, String> {
    let updated = result
        .get("updated")
        .and_then(Value::as_u64)
        .ok_or_else(|| "application update result has no updated count".to_string())?;
    let current = result
        .get("current")
        .and_then(Value::as_u64)
        .ok_or_else(|| "application update result has no current count".to_string())?;
    let failed = result
        .get("failed")
        .and_then(Value::as_u64)
        .ok_or_else(|| "application update result has no failed count".to_string())?;
    let mut out = fmt::masthead(style, "Application updates", hostname);
    let (slot, verdict) = if failed > 0 {
        (
            Slot::Bad,
            format!("Update incomplete · {updated} updated · {failed} failed"),
        )
    } else if updated > 0 {
        (Slot::Ok, format!("✓ {updated} application(s) updated"))
    } else {
        (Slot::Ok, "✓ Installed applications are current".to_string())
    };
    out.push_str(&fmt::verdict(style, slot, &verdict));
    out.push_str(&fmt::rows(
        style,
        &[
            Row::new(
                "Updated",
                &updated.to_string(),
                Slot::Ok,
                "signed catalog targets",
            ),
            Row::new(
                "Already current",
                &current.to_string(),
                Slot::Neutral,
                "no package change",
            ),
            Row::new(
                "Failed",
                &failed.to_string(),
                if failed > 0 { Slot::Bad } else { Slot::Neutral },
                if failed > 0 {
                    "retry after reviewing the named failures"
                } else {
                    "none"
                },
            ),
        ],
    ));
    if let Some(failures) = result.get("failures").and_then(Value::as_array) {
        for failure in failures {
            let id = failure
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("application");
            let reason = failure
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("the update did not complete");
            out.push_str(&fmt::note(style, &format!("{id} · {reason}")));
        }
    }
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
    fn update_apply_renders_only_the_verified_durable_outcome() {
        let text = update_apply(
            &Style::plain(),
            &json!({
                "v": 1,
                "staged_version": "2026.08.27.1",
                "staged_slot": "b",
                "requires_reboot": true,
                "bytes_written": 8192,
                "verified": true
            }),
        )
        .unwrap();
        assert!(
            text.contains("RELEASE       2026.08.27.1   slot B"),
            "{text}"
        );
        assert!(text.contains("PASSED"), "{text}");
        assert!(text.contains("REQUIRED"), "{text}");
    }

    #[test]
    fn update_rollback_names_both_local_selectors() {
        let text = update_rollback(
            &Style::plain(),
            &json!({
                "v": 1,
                "previous_default": "punar_2026.08.27.1*.efi",
                "new_default": "punar_2026.08.20.1*.efi",
                "requires_reboot": true
            }),
        )
        .unwrap();
        assert!(text.contains("PUNAR_2026.08.27.1*.EFI"), "{text}");
        assert!(text.contains("PUNAR_2026.08.20.1*.EFI"), "{text}");
        assert!(text.contains("already present locally"), "{text}");
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
                {"level": 3, "category": "mcp_servers", "milestone": "M11+",
                 "reason": "no tool or MCP gateway mediates MCP traffic yet"}
            ],
            "retention": {"days": 14, "active": true}
        });
        let text = agent_access(&style, &result).unwrap();
        // Named producer-less category: pending, with its milestone.
        let mcp = text
            .lines()
            .find(|l| l.starts_with("MCP SERVERS"))
            .unwrap_or_default();
        assert!(mcp.contains("NOT YET OBSERVED · M11+"), "{text}");
        // Unnamed empty category: an honest "none recorded", never a
        // borrowed milestone from another row.
        let repositories = text
            .lines()
            .find(|l| l.starts_with("REPOSITORIES"))
            .unwrap_or_default();
        assert!(repositories.contains("NONE RECORDED"), "{text}");
        assert!(!repositories.contains("M11+"), "{text}");
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
        // DESIGN_LANGUAGE section 8.1: this fixture is NOT enrolled, so the
        // words may not presuppose an authority. The wire value is unchanged
        // ("non_compliant" still crosses the socket); only the rendering moves.
        assert!(text.contains("DRIFTED"), "{text}");
        assert!(
            text.contains("no drift put back since daemon start"),
            "{text}"
        );
        // The rule itself, asserted rather than a single replacement string:
        // no compliance vocabulary and no scope-shaming on a personal device.
        assert!(!text.contains("COMPLIANT"), "{text}");
        assert!(!text.contains("PERSONAL SCOPE"), "{text}");
        // SPEC section 52 rows carry the friendly capability labels.
        assert!(text.contains("FIREWALL"), "{text}");
        assert!(text.contains("HOSTNAME"), "{text}");
        assert!(text.contains("TIMEZONE"), "{text}");
        // Personal compliance is not an org row (design section 8).
        let lower = text.to_lowercase();
        assert!(!lower.contains("org "));
        assert!(!lower.contains("acme"));
        assert!(text.contains("PERSONAL DEVICE"), "{text}");
        assert!(!text.contains("NO ORGANIZATION IS ENROLLED"), "{text}");
    }

    #[test]
    fn status_explains_the_observed_device_class() {
        let style = Style::plain();
        let result = json!({
            "protocol_version": 1,
            "daemon_version": "0.2.0",
            "device_id": "dev_9f3k2v8q1x",
            "mode": "personal",
            "enrolled": false,
            "hostname": "punar-pi",
            "capabilities_total": 3,
            "device": {
                "class": "appliance",
                "source": "observed",
                "facts": {
                    "memory_mib": 4096,
                    "logical_cores": 4,
                    "battery_present": false,
                    "display_connected": false
                }
            }
        });
        let text = status(&style, &result, &[]).unwrap();
        assert!(text.contains("DEVICE CLASS"), "{text}");
        assert!(text.contains("APPLIANCE"), "{text}");
        assert!(
            text.contains("4096 MiB RAM · 4 logical cores · no battery · headless · observed"),
            "{text}"
        );
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
        assert!(text.contains("PERSONAL DEVICE"), "{text}");
        assert!(!text.contains("NO ORGANIZATION IS ENROLLED"), "{text}");
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
        assert!(
            text.contains("MERGED FROM OS DEFAULTS + YOUR PREFERENCES"),
            "{text}"
        );
        assert!(!text.contains("PERSONAL DEVICE"), "{text}");
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
        assert!(!text.contains("PERSONAL DEVICE"), "{text}");

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
        assert!(text.contains("PERSONAL DEVICE"), "{text}");
        assert!(!text.contains("NO ORGANIZATION IS ENROLLED"), "{text}");
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

        // Without the explain follow-up the override is still stated — but it
        // no longer INVENTS an organization. `overridden` means something
        // ranked above your preference decided this, and on a personal device
        // that something may be a temporary approved exception rather than an
        // org, so the old wording asserted a counterparty that need not exist.
        let text = set(&style, &result, "punar-m5", None).unwrap();
        assert!(text.contains("WAS DECIDED ABOVE YOUR PREFERENCE"), "{text}");
        assert!(!text.contains("ORGANIZATION POLICY"), "{text}");
        // And the masthead does not call the device Managed without a source.
        assert!(!text.contains("· MANAGED"), "{text}");
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
        assert!(text.contains("PERSONAL MODE IS LOCAL-ONLY"), "{text}");
        assert!(!text.contains("NO ORGANIZATION IS ENROLLED"), "{text}");

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

    // ---- Milestone 9 -------------------------------------------------

    /// A pending capability-set approval, five minutes out. The
    /// envelope's `approval` member is exactly the spec section 28
    /// document; everything else is a sibling (contract section 14.3).
    fn pending_firewall_approval() -> serde_json::Value {
        json!({
            "v": 1,
            "approval": {
                "approval_id": "apr_7c1d9a4e",
                "requester": {"type": "ai_agent", "id": "agt_4f21c09ab3e1",
                              "agent_name": "claude-code"},
                "user": "punar",
                "capability": "security.firewall",
                "resource": "disabled",
                "reason": "Atlas integration test needs the host firewall down",
                "risk": "high",
                "status": "pending",
                "expires_at": "2126-08-25T10:05:00Z"
            },
            "kind": "capability_set",
            "created_at": "2126-08-25T10:00:00Z",
            "contract": "SetFirewall(disabled)",
            "policy": {"name": "Personal preference", "policy_id": "personal-defaults"},
            "resolved_at": null, "resolved_by": null,
            "consumed_at": null, "execution": null
        })
    }

    /// Plate D-003, register by register: the identity chain, the live
    /// countdown, the contract block with the exact typed call, the
    /// policy citation and the audit promise that holds either way.
    #[test]
    fn a_pending_approval_renders_the_d003_contract_card() {
        let style = Style::plain();
        let text = approval_get(&style, &pending_firewall_approval(), "punar-m9", true).unwrap();

        // Masthead + the approval id and its status.
        assert!(text.contains("A P P R O V A L"), "{text}");
        assert!(text.contains("APR_7C1D9A4E"), "{text}");
        assert!(text.contains("pending · capability set"), "{text}");
        // Identity chain, one line, in the plate's order.
        assert!(
            text.contains("AI agent · claude-code · agt_4f21c09ab3e1 · punar"),
            "{text}"
        );
        // The exact typed capability that will run — never a root shell.
        assert!(
            text.contains("ONE-TIME EXECUTION · SETFIREWALL(DISABLED)"),
            "{text}"
        );
        assert!(
            text.contains("POLICY · PERSONAL PREFERENCE · PERSONAL DEFAULTS"),
            "{text}"
        );
        // The exact typed call keeps its spelling in the row register.
        assert!(text.contains("SetFirewall(disabled)"), "{text}");
        assert!(
            text.contains("RECORDED TO LOCAL AUDIT EITHER WAY"),
            "{text}"
        );
        // Risk pill, and a live countdown (the fixture expires far out).
        assert!(text.contains("HIGH"), "{text}");
        assert!(text.contains("left"), "{text}");
    }

    /// The reason is SHOWN — section 73 requires *why* and *who requested
    /// it*, and a gate whose justification is hidden is a rubber stamp —
    /// but it is quoted and attributed to the requester, never rendered
    /// as a system statement (milestone-9.md section 8.3).
    #[test]
    fn the_requester_reason_is_shown_in_a_quoted_requester_voice() {
        let style = Style::plain();
        let text = approval_get(&style, &pending_firewall_approval(), "punar-m9", true).unwrap();
        assert!(
            text.contains(
                "claude-code says: \"Atlas integration test needs the host firewall down\""
            ),
            "{text}"
        );
        // The system's own sentence about the request is separate prose,
        // and the two never share a line.
        assert!(
            text.contains("claude-code wants to set security.firewall to disabled."),
            "{text}"
        );
    }

    /// Resolution is human-only (contract section 14.5), so the `[A]` /
    /// `[D]` affordance of Plate D-014 register 05 appears only for a
    /// peer eligible to use it. An agent sees the card, the countdown,
    /// and no buttons — and is told, in the section 73 voice, who does
    /// decide.
    #[test]
    fn the_resolve_affordance_is_drawn_only_for_an_eligible_peer() {
        let style = Style::plain();
        let approval = pending_firewall_approval();

        let human = approval_get(&style, &approval, "punar-m9", true).unwrap();
        assert!(
            human.contains("[A] PUNARCTL APPROVALS RESOLVE APR_7C1D9A4E --DECISION APPROVED"),
            "{human}"
        );
        assert!(human.contains("[D] "), "{human}");

        let agent = approval_get(&style, &approval, "punar-m9", false).unwrap();
        assert!(!agent.contains("[A]"), "{agent}");
        assert!(!agent.contains("[D]"), "{agent}");
        assert!(agent.contains("AN AI AGENT MAY RESOLVE NOTHING"), "{agent}");
        assert!(agent.contains("ROUTED TO PUNAR"), "{agent}");
    }

    /// Plate D-003's three verdicts, verbatim — including the audit
    /// pointer, which is what ties the card to the trail without
    /// extending `audit-event.json` (contract section 14.3).
    #[test]
    fn the_three_verdicts_carry_the_audit_pointer() {
        let style = Style::plain();

        let mut approved = pending_firewall_approval();
        approved["approval"]["status"] = json!("approved");
        approved["resolved_at"] = json!("2126-08-25T10:01:00Z");
        approved["resolved_by"] = json!({"uid": 1000, "user": "punar", "pid": 812});
        approved["execution"] =
            json!({"result": "success", "changed": true, "audit_event_id": "evt_501"});
        let text = approval_resolved(&style, &approved, "punar-m9").unwrap();
        assert!(
            text.contains("✓ APPROVED · SETFIREWALL(DISABLED) EXECUTED · AUDIT EVT_501"),
            "{text}"
        );
        assert!(text.contains("punar · uid 1000 · pid 812"), "{text}");
        assert!(
            text.contains("THE AGENT DID IT · THE HUMAN ALLOWED IT · THE TRAIL SAYS BOTH"),
            "{text}"
        );

        let mut denied = pending_firewall_approval();
        denied["approval"]["status"] = json!("denied");
        denied["execution"] = json!({"result": "not_executed", "audit_event_id": "evt_502"});
        let text = approval_resolved(&style, &denied, "punar-m9").unwrap();
        assert!(
            text.contains("DENIED · NOTHING EXECUTED · AUDIT EVT_502"),
            "{text}"
        );

        let mut expired = pending_firewall_approval();
        expired["approval"]["status"] = json!("expired");
        expired["execution"] = json!({"result": "not_executed", "audit_event_id": "evt_503"});
        let text = approval_resolved(&style, &expired, "punar-m9").unwrap();
        assert!(
            text.contains("EXPIRED · DENIED BY TIMEOUT · NOTHING EXECUTED · AUDIT EVT_503"),
            "{text}"
        );
    }

    /// A credential approval is flipped by punard and spent later by the
    /// broker (contract section 14.6). The card must not claim an
    /// execution punard never performed.
    #[test]
    fn an_approved_credential_claims_no_execution_it_did_not_perform() {
        let style = Style::plain();
        let approval = json!({
            "approval": {
                "approval_id": "apr_11ba32cd",
                "requester": {"type": "ai_agent", "id": "agt_4f21", "agent_name": "claude-code"},
                "user": "punar", "capability": "credential.request", "resource": "aws-dev",
                "reason": "Atlas needs the dev account", "risk": "medium",
                "status": "approved", "expires_at": "2126-08-25T10:05:00Z"
            },
            "kind": "credential_request",
            "contract": "IssueCredential(aws-dev)",
            "consumed_at": null, "execution": null
        });
        let text = approval_resolved(&style, &approval, "punar-m9").unwrap();
        assert!(text.contains("✓ APPROVED · AWAITING ISSUANCE"), "{text}");
        assert!(!text.contains("EXECUTED"), "{text}");

        let mut consumed = approval;
        consumed["consumed_at"] = json!("2126-08-25T10:02:00Z");
        let text = approval_resolved(&style, &consumed, "punar-m9").unwrap();
        assert!(text.contains("✓ APPROVED · CREDENTIAL ISSUED"), "{text}");
    }

    /// Exit 4 is not a failure report. The section 73 four beats: what is
    /// pending, who must decide, how long it lasts, what to do next —
    /// and, loudest of all, that **nothing was executed**.
    #[test]
    fn the_approval_required_surface_says_nothing_ran() {
        let style = Style::plain();
        let details = json!({
            "approval_id": "apr_7c1d9a4e",
            "expires_at": "2126-08-25T10:05:00Z",
            "capability": "security.firewall",
            "resource": "disabled",
            "decision": "approval_required",
            "policy_ids": ["personal-defaults"]
        });
        let text = approval_required(
            &style,
            "Claude Code may not disable the host firewall without your approval.",
            Some(&details),
            "punar-m9",
        );
        // The daemon's own prose passes through verbatim.
        assert!(
            text.contains("Claude Code may not disable the host firewall without your approval."),
            "{text}"
        );
        assert!(text.contains("APR_7C1D9A4E"), "{text}");
        assert!(
            text.contains("PENDING · NOTHING HAS BEEN EXECUTED"),
            "{text}"
        );
        assert!(
            text.contains("pending · nothing has been executed"),
            "{text}"
        );
        assert!(text.contains("SECURITY.FIREWALL(DISABLED)"), "{text}");
        assert!(text.contains("APPROVAL_REQUIRED"), "{text}");
        assert!(text.contains("personal defaults"), "{text}");
        assert!(text.contains("left to answer"), "{text}");
        assert!(
            text.contains("A HUMAN AT THIS DEVICE DECIDES · AN AI AGENT MAY RESOLVE NOTHING"),
            "{text}"
        );
        assert!(
            text.contains("NEXT STEP: PUNARCTL APPROVALS WAIT APR_7C1D9A4E"),
            "{text}"
        );
    }

    /// punard deliberately keeps the spoofable display name off the
    /// authorization surfaces, so the usual card keys on the attested
    /// `agt_` id. It must still read as a sentence.
    #[test]
    fn a_requester_with_no_display_name_keys_on_the_attested_id() {
        let style = Style::plain();
        let mut approval = pending_firewall_approval();
        approval["approval"]["requester"] = json!({"type": "ai_agent", "id": "agt_4f21c09ab3e1"});
        let text = approval_get(&style, &approval, "punar-m9", true).unwrap();
        assert!(
            text.contains("This AI agent wants to set security.firewall"),
            "{text}"
        );
        assert!(
            text.contains("agt_4f21c09ab3e1 says: \"Atlas integration"),
            "{text}"
        );
        // The chain keys on the id, with no invented display name.
        assert!(
            text.contains("AI agent · agt_4f21c09ab3e1 · punar"),
            "{text}"
        );
    }

    /// A daemon that sends no `details` still gets a usable surface: the
    /// message and a next step, and never an invented approval id.
    #[test]
    fn the_approval_required_surface_survives_a_bare_error() {
        let style = Style::plain();
        let text = approval_required(&style, "Approval is required.", None, "punar-m9");
        assert!(text.contains("Approval is required."), "{text}");
        assert!(
            text.contains("NEXT STEP: PUNARCTL APPROVALS LIST"),
            "{text}"
        );
        assert!(!text.contains("APR_"), "{text}");
    }

    /// The list is the "what is waiting on you" register: pending count
    /// in the section header, the typed call, and the time left.
    #[test]
    fn approvals_list_leads_with_what_is_pending() {
        let style = Style::plain();
        let result = json!({
            "approvals": [pending_firewall_approval()],
            "checked_at": "2126-08-25T10:00:30Z"
        });
        let text = approvals_list(&style, &result, "punar-m9").unwrap();
        assert!(text.contains("1 PENDING"), "{text}");
        assert!(text.contains("APR_7C1D9A4E"), "{text}");
        assert!(text.contains("SetFirewall(disabled)"), "{text}");
        assert!(
            text.contains("A PENDING APPROVAL EXECUTES NOTHING UNTIL A HUMAN ANSWERS"),
            "{text}"
        );

        let empty = json!({"approvals": [], "checked_at": "2126-08-25T10:00:30Z"});
        let text = approvals_list(&style, &empty, "punar-m9").unwrap();
        assert!(text.contains("NOTHING IS GATED RIGHT NOW"), "{text}");
    }

    /// Plate D-012 Sect I.03: privilege is visible for exactly as long as
    /// it exists, and the absence of a grant is the loud default — this
    /// device has no permanent administrator.
    #[test]
    fn privilege_status_renders_grants_and_their_absence() {
        let style = Style::plain();
        let none = json!({"grants": [], "checked_at": "2126-08-25T10:00:00Z"});
        let text = privilege_status(&style, &none, "punar-m9").unwrap();
        assert!(
            text.contains("NO ACTIVE GRANTS — THIS DEVICE HAS NO PERMANENT ADMINISTRATOR"),
            "{text}"
        );
        assert!(text.contains("PUNARCTL PRIVILEGE REQUEST"), "{text}");

        let live = json!({
            "grants": [{"grant_id": "gnt_2b8e11c4", "capability": "time.timezone",
                        "reason": "Reproducing the Atlas net bug",
                        "granted_at": "2126-08-25T10:00:00Z",
                        "expires_at": "2126-08-25T10:15:00Z"}],
            "checked_at": "2126-08-25T10:00:30Z"
        });
        let text = privilege_status(&style, &live, "punar-m9").unwrap();
        assert!(text.contains("GNT_2B8E11C4"), "{text}");
        assert!(text.contains("time.timezone"), "{text}");
        assert!(text.contains("\"Reproducing the Atlas net bug\""), "{text}");
        assert!(
            text.contains("ONE CAPABILITY PER GRANT · NO WILDCARD · NO ROOT SHELL"),
            "{text}"
        );
    }

    /// `secrets list` shows classes and decisions and **never** a value —
    /// after issuance the broker holds only a hash, so there is no method
    /// that could produce one. The mock provider is labelled loudly.
    #[test]
    fn secrets_list_shows_decisions_and_never_a_value() {
        let style = Style::plain();
        let result = json!({
            "classes": [
                {"credential": "github", "decision": "allow", "policy_key": "github",
                 "default_ttl": 3600, "max_ttl": 3600, "provider": "mock"},
                {"credential": "aws-dev", "decision": "request", "policy_key": "aws_dev",
                 "default_ttl": 3600, "max_ttl": 3600, "provider": "mock"},
                {"credential": "aws-prod", "decision": "deny", "policy_key": "aws_prod",
                 "default_ttl": 0, "max_ttl": 0, "provider": "mock"}
            ],
            "provider": "mock",
            "checked_at": "2126-08-25T10:00:00Z"
        });
        let text = secrets_list(&style, &result, "punar-m9").unwrap();
        // Kebab-case on the wire and on every surface (section 16.3).
        assert!(text.contains("AWS-DEV"), "{text}");
        assert!(text.contains("AWS-PROD"), "{text}");
        assert!(!text.contains("aws_dev  "), "{text}");
        // The snake_case policy key is named as the declared mapping.
        assert!(text.contains("policy credentials.aws_dev"), "{text}");
        assert!(text.contains("ALLOW"), "{text}");
        assert!(text.contains("REQUEST"), "{text}");
        assert!(text.contains("DENY"), "{text}");
        assert!(
            text.contains("SIMULATED · NO REAL CREDENTIAL EXISTS ON THIS DEVICE"),
            "{text}"
        );
        assert!(
            text.contains("ISSUED VALUES ARE NEVER LISTED · THE BROKER KEEPS ONLY A HASH"),
            "{text}"
        );
    }

    /// Plate D-012 Sect II: the issuance card says what it may say and
    /// has **no affordance that could show the value** — the redaction
    /// rule stated on the surface and enforced on the surface.
    #[test]
    fn the_issuance_card_never_carries_the_value() {
        let style = Style::plain();
        const TOKEN: &str = "punar-mock-aws-dev-9Qw3ZzmXk1";
        let result = json!({
            "credential": "aws-dev",
            "value": TOKEN,
            "expires_at": "2126-08-25T11:00:00Z",
            "provider": "mock",
            "agent_session_id": "agt_4f21c09ab3e1"
        });
        let card = secrets_card(&style, &result, "punar-m9").unwrap();
        // The headline assertion of this milestone, at the CLI boundary.
        assert!(!card.contains(TOKEN), "{card}");
        assert!(!card.contains("punar-mock"), "{card}");
        assert!(card.contains("AWS-DEV"), "{card}");
        assert!(
            card.contains("NEVER WRITTEN TO DISK · NEVER LOGGED · THE VALUE IS ON STDOUT"),
            "{card}"
        );
        assert!(card.contains("SIMULATED · MOCK PROVIDER"), "{card}");
        assert!(card.contains("not a real credential"), "{card}");
        assert!(card.contains("PUNAR NEVER WRITES IT"), "{card}");
        assert!(card.contains("agt_4f21c09ab3e1"), "{card}");
    }

    /// `validate` prints a verdict and an expiry and never the value it
    /// was handed; `expired` and `not_found` are verdicts rather than
    /// malfunctions, and the word INVALID comes from the wire code.
    #[test]
    fn validate_renders_a_verdict_without_echoing_the_value() {
        let style = Style::plain();
        let ok = json!({"valid": true, "credential": "github",
                        "expires_at": "2126-08-25T11:00:00Z"});
        let text = secrets_validate(&style, &ok, "punar-m9").unwrap();
        assert!(text.contains("YES"), "{text}");
        assert!(text.contains("GITHUB"), "{text}");
        assert!(
            text.contains("THE VALUE WAS READ FROM STDIN AND IS NOT ECHOED · NEVER ON ARGV"),
            "{text}"
        );

        let text = secrets_invalid(
            &style,
            "expired",
            "That credential's lifetime has ended.",
            "punar-m9",
        );
        assert!(text.contains("VALID"), "{text}");
        assert!(text.contains("NO"), "{text}");
        assert!(text.contains("expired · the lifetime lapsed"), "{text}");
        assert!(
            text.contains("That credential's lifetime has ended."),
            "{text}"
        );
    }

    /// The countdown is tabular and never negative: past zero the card
    /// says EXPIRED in words rather than drawing a negative clock.
    #[test]
    fn the_countdown_never_runs_backwards() {
        assert_eq!(countdown(299), "4:59");
        assert_eq!(countdown(60), "1:00");
        assert_eq!(countdown(9), "0:09");
        assert_eq!(countdown(0), "0:00");
        assert_eq!(countdown(-42), "0:00");
    }

    /// An approval whose `expires_at` has passed reads as expired
    /// everywhere, whether or not the daemon has swept it yet (contract
    /// section 14.4).
    #[test]
    fn a_lapsed_pending_approval_reads_as_expired_before_the_sweep() {
        let style = Style::plain();
        let mut approval = pending_firewall_approval();
        approval["approval"]["expires_at"] = json!("2020-01-01T00:00:00Z");
        let text = approval_get(&style, &approval, "punar-m9", true).unwrap();
        assert!(text.contains("expired 2020-01-01 00:00:00"), "{text}");
    }
}
