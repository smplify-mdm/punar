//! The SPEC section 72 fleet aggregate — and the one rule that matters
//! more than the aggregate (milestone-10.md section 12).
//!
//! > **`0` and `—` are different, and the mock must render them
//! > differently.** `0` is a claim, and a claim requires a device that
//! > actually answered at the scope that would have produced it. `—` means
//! > nobody answered.
//!
//! That rule is why [`FleetValue`] is an enum rather than a `u64` with a
//! sentinel: a row that nobody answered *cannot be formatted as a number*,
//! because it does not hold one. Section 72's "0 production credentials" is
//! a **finding**; printing it from an absence of data would be the single
//! most dangerous dishonesty available to this feature, because it is the
//! line an administrator would most like to believe.
//!
//! The mock aggregates only what devices **sent** it: `inventory.report`
//! and `compliance.report` (M5) and answered `admin.ai_query` payloads
//! (M10). It builds no per-person profile and stores no field that would
//! let it (section 12.2).

use std::collections::BTreeSet;

use punar_common::query::QueryScope;
use serde::Serialize;
use serde_json::{Value, json};

use crate::state::{QueryStatus, StateStore};

/// A fleet number, or the honest absence of one.
///
/// The `Serialize` impl is hand-written so the **structured** result is as
/// honest as the text one: an absence serializes as the em dash string,
/// never as `null` or `0`. A JSON consumer that treats `null` as zero is a
/// bug waiting to happen, and the rule of section 12 is precisely that this
/// particular zero must be impossible to produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FleetValue {
    /// A real count, backed by at least one device that answered at the
    /// scope which produces it.
    Count(u64),
    /// Nobody answered. Renders as `—`, never as `0`.
    NotAnswered,
}

impl Serialize for FleetValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            FleetValue::Count(n) => serializer.serialize_u64(*n),
            FleetValue::NotAnswered => serializer.serialize_str(NOT_ANSWERED_CELL),
        }
    }
}

/// The em dash, defined once. `0` is a claim; this is the absence of one.
pub const NOT_ANSWERED_CELL: &str = "—";

impl FleetValue {
    /// A count **only if** something answered at the producing scope.
    pub fn counted(answered_at_scope: bool, count: u64) -> FleetValue {
        if answered_at_scope {
            FleetValue::Count(count)
        } else {
            FleetValue::NotAnswered
        }
    }

    /// The rendered cell. The em dash is the whole point.
    pub fn cell(self) -> String {
        match self {
            FleetValue::Count(n) => n.to_string(),
            FleetValue::NotAnswered => NOT_ANSWERED_CELL.to_string(),
        }
    }
}

/// One labelled row with its value and the reason behind it.
#[derive(Debug, Clone, Serialize)]
pub struct FleetRow {
    pub label: String,
    pub value: FleetValue,
    pub note: String,
}

/// The whole section 72 aggregate, as structured data (`admin.fleet`) and
/// as text (`punar-mock-smplify --fleet`).
#[derive(Debug, Clone, Serialize)]
pub struct FleetView {
    pub devices_enrolled: u64,
    pub devices_reporting: u64,
    pub active_ai_users: FleetValue,
    pub active_ai_users_note: String,
    pub agents: Vec<FleetRow>,
    pub shadow_ai: ShadowAi,
    pub findings: Vec<FleetRow>,
    pub answered_scopes: Vec<String>,
    pub oldest_answer_at: Option<String>,
    pub newest_answer_at: Option<String>,
}

/// The shadow-AI panel of section 72, deduplicated by `signature_id`
/// (milestone-10.md section 4.3: an administrator needs "how many distinct
/// unmanaged things", not process churn).
#[derive(Debug, Clone, Serialize)]
pub struct ShadowAi {
    pub unmanaged_agents: FleetValue,
    pub devices: FleetValue,
    pub distinct_signatures: FleetValue,
}

/// Build the aggregate from what the mock legitimately received.
pub fn aggregate(state: &StateStore) -> FleetView {
    let devices_enrolled = state.devices().count() as u64;
    let devices_reporting = state
        .devices()
        .filter(|(_, r)| r.last_sync.is_some())
        .count() as u64;

    let mut answered_scopes: BTreeSet<String> = BTreeSet::new();
    let mut oldest: Option<String> = None;
    let mut newest: Option<String> = None;

    let mut managed = 0u64;
    let mut observed = 0u64;
    let mut unknown = 0u64;
    let mut by_agent: Vec<(String, String)> = Vec::new(); // (agent, classification)
    let mut signatures: BTreeSet<String> = BTreeSet::new();
    let mut shadow_devices: BTreeSet<String> = BTreeSet::new();
    let mut unmanaged_detections = 0u64;
    let mut repositories = 0u64;

    for entry in state.queries() {
        if entry.status != QueryStatus::Answered {
            continue;
        }
        let Some(answer) = &entry.answer else {
            continue;
        };
        answered_scopes.insert(entry.requested_scope.clone());
        if let Some(at) = entry.answered_at.clone() {
            if oldest.as_ref().is_none_or(|o| at < *o) {
                oldest = Some(at.clone());
            }
            if newest.as_ref().is_none_or(|n| at > *n) {
                newest = Some(at);
            }
        }
        let payload = answer.get("payload").unwrap_or(&Value::Null);
        match QueryScope::from_wire(&entry.requested_scope) {
            Some(QueryScope::Inventory) => {
                let counts = payload.get("counts");
                managed += count_of(counts, "managed");
                observed += count_of(counts, "observed");
                unknown += count_of(counts, "unknown");
                if let Some(sessions) = payload.get("sessions").and_then(Value::as_array) {
                    for session in sessions {
                        by_agent.push((text(session, "agent"), text(session, "classification")));
                    }
                }
                if let Some(detections) = payload.get("detections").and_then(Value::as_array) {
                    for detection in detections {
                        by_agent
                            .push((text(detection, "agent"), text(detection, "classification")));
                        unmanaged_detections += 1;
                        shadow_devices.insert(entry.device_id.clone());
                        let signature = text(detection, "signature_id");
                        if !signature.is_empty() {
                            signatures.insert(signature);
                        }
                    }
                }
            }
            Some(QueryScope::ResourceSummary) => {
                // The only finding row M10 can ever produce from data, and
                // only when a device actually answered at this scope.
                repositories += payload
                    .get("summary")
                    .and_then(|s| s.get("repositories"))
                    .and_then(Value::as_array)
                    .map(|r| r.len() as u64)
                    .unwrap_or(0);
            }
            _ => {}
        }
    }

    let inventory_answered = answered_scopes.contains(QueryScope::Inventory.as_str());
    let resource_answered = answered_scopes.contains(QueryScope::ResourceSummary.as_str());

    let named = |needle: &str| -> u64 {
        by_agent
            .iter()
            .filter(|(agent, class)| agent == needle && class != "unknown")
            .count() as u64
    };
    let other = by_agent
        .iter()
        .filter(|(agent, class)| class != "unknown" && agent != "claude-code" && agent != "codex")
        .count() as u64;
    let _ = (managed, observed);

    let agents = vec![
        FleetRow {
            label: "Claude Code".to_string(),
            value: FleetValue::counted(inventory_answered, named("claude-code")),
            note: String::new(),
        },
        FleetRow {
            label: "Codex".to_string(),
            value: FleetValue::counted(inventory_answered, named("codex")),
            note: String::new(),
        },
        FleetRow {
            label: "Other".to_string(),
            value: FleetValue::counted(inventory_answered, other),
            note: String::new(),
        },
        FleetRow {
            label: "Unknown".to_string(),
            value: FleetValue::counted(inventory_answered, unknown),
            note: "suspected, not certain".to_string(),
        },
    ];

    let findings = vec![
        FleetRow {
            label: "accessing source repositories".to_string(),
            value: FleetValue::counted(resource_answered, repositories),
            note: if resource_answered {
                "from answered resource_summary queries".to_string()
            } else {
                "not answered at resource_summary scope".to_string()
            },
        },
        FleetRow {
            label: "accessing corporate APIs".to_string(),
            // Permanently NotAnswered in M10: no observer exists, so there
            // is no scope at which any device could produce this.
            value: FleetValue::NotAnswered,
            note: "not observable before M12 (punar-netd)".to_string(),
        },
        FleetRow {
            label: "production credentials".to_string(),
            value: FleetValue::NotAnswered,
            note: "not observable: credentials are mediated for managed sessions only (M9)"
                .to_string(),
        },
    ];

    FleetView {
        devices_enrolled,
        devices_reporting,
        // Deliberate deviation from the section 12.1 mockup, in the spirit
        // of section 12.2's binding rule: a device exports no user identity
        // at any scope (section 8.2 omits `user` entirely), so the mock has
        // no honest way to count distinct users and says so instead of
        // printing a device count under a user label.
        active_ai_users: FleetValue::NotAnswered,
        active_ai_users_note: "devices never export a user identity at any scope (section 8.2)"
            .to_string(),
        agents,
        shadow_ai: ShadowAi {
            unmanaged_agents: FleetValue::counted(inventory_answered, unmanaged_detections),
            devices: FleetValue::counted(inventory_answered, shadow_devices.len() as u64),
            distinct_signatures: FleetValue::counted(inventory_answered, signatures.len() as u64),
        },
        findings,
        answered_scopes: answered_scopes.into_iter().collect(),
        oldest_answer_at: oldest,
        newest_answer_at: newest,
    }
}

fn count_of(counts: Option<&Value>, key: &str) -> u64 {
    counts
        .and_then(|c| c.get(key))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

impl FleetView {
    /// `admin.fleet`'s structured result.
    pub fn to_json(&self) -> Value {
        json!({ "fleet": serde_json::to_value(self).unwrap_or(Value::Null) })
    }

    /// The `--fleet` text output (milestone-10.md section 12.1).
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(
            "AI FLEET                                   dev/CI mock — not a product component\n\n",
        );
        out.push_str(&row(
            "Devices",
            &self.devices_enrolled.to_string(),
            &format!("enrolled · {} reporting", self.devices_reporting),
        ));
        out.push_str(&row(
            "Active AI users",
            &self.active_ai_users.cell(),
            &self.active_ai_users_note,
        ));
        out.push('\n');
        for entry in &self.agents {
            out.push_str(&row(&entry.label, &entry.value.cell(), &entry.note));
        }
        out.push_str("\nSHADOW AI DETAIL\n");
        out.push_str(&format!(
            "{} unmanaged agent · {} device · {} distinct signature\n\n",
            self.shadow_ai.unmanaged_agents.cell(),
            self.shadow_ai.devices.cell(),
            self.shadow_ai.distinct_signatures.cell(),
        ));
        for finding in &self.findings {
            out.push_str(&format!(
                "  {:<36} {:>3}   {}\n",
                finding.label,
                finding.value.cell(),
                finding.note
            ));
        }
        out.push('\n');
        match (&self.oldest_answer_at, &self.newest_answer_at) {
            (Some(oldest), Some(newest)) => out.push_str(&format!(
                "Answers are as fresh as each device's last sync · oldest {oldest} · \
                 newest {newest}\n"
            )),
            _ => out.push_str(
                "Answers are as fresh as each device's last sync · no device has answered \
                 a query yet\n",
            ),
        }
        out.push_str(
            "— means nobody answered at the scope that would produce the number · it is \
             never 0\n",
        );
        out
    }
}

fn row(label: &str, value: &str, note: &str) -> String {
    if note.is_empty() {
        format!("{label:<26} {value:>3}\n")
    } else {
        format!("{label:<26} {value:>3}     {note}\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "punar-mock-fleet-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn inventory_answer() -> Value {
        json!({
            "result_category": "answered",
            "authorization_decision": "allow",
            "granted_scope": "inventory",
            "payload": {
                "counts": {"managed": 1, "observed": 0, "unknown": 1},
                "sessions": [{"session_id": "agt_4f21c09ab3e1", "agent": "claude-code",
                              "classification": "managed", "status": "active",
                              "started_at": "2026-08-25T13:44:02Z"}],
                "detections": [{"signature_id": "sig_9b02aa11cc22", "agent": "foo-agent",
                                "classification": "unknown", "suspected": true,
                                "zone": "downloads", "first_seen": "2026-08-25T13:59:41Z",
                                "live": true}]
            }
        })
    }

    /// The rule of milestone-10.md section 12: before any device answers,
    /// every derived row is `—`. Not a single `0` is printed, because not a
    /// single claim can be made.
    #[test]
    fn nothing_answered_renders_em_dashes_and_never_zero() {
        let dir = tmp_dir("empty");
        let mut store = StateStore::open(&dir).unwrap();
        store.register("dev_abc").unwrap();
        let view = aggregate(&store);
        let text = view.render();

        assert!(text.contains('—'), "{text}");
        for row in &view.agents {
            assert_eq!(row.value, FleetValue::NotAnswered, "{}", row.label);
        }
        assert_eq!(view.shadow_ai.unmanaged_agents, FleetValue::NotAnswered);
        assert!(
            !text.contains("0 production credentials"),
            "the most dangerous available dishonesty: {text}"
        );
        // "Devices" is a thing the mock legitimately knows (they enrolled),
        // so it is a number, not a dash.
        assert_eq!(view.devices_enrolled, 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_answered_inventory_query_produces_counts_but_not_findings() {
        let dir = tmp_dir("answered");
        let mut store = StateStore::open(&dir).unwrap();
        store.register("dev_abc").unwrap();
        store
            .append_compliance("dev_abc", &json!({"overall": "compliant"}))
            .unwrap();
        let entry = store
            .enqueue_query("dev_abc", "cio@acme.com", "acme.com", "inventory", None)
            .unwrap();
        store
            .record_answer("dev_abc", &entry.query_id, &inventory_answer())
            .unwrap();

        let view = aggregate(&store);
        let text = view.render();

        assert_eq!(view.devices_reporting, 1);
        assert_eq!(view.agents[0].value, FleetValue::Count(1)); // Claude Code
        assert_eq!(view.agents[1].value, FleetValue::Count(0)); // Codex — a real 0
        assert_eq!(view.agents[3].value, FleetValue::Count(1)); // Unknown
        assert!(text.contains("Unknown"), "{text}");
        assert!(
            text.contains("1 unmanaged agent · 1 device · 1 distinct signature"),
            "{text}"
        );
        assert_eq!(view.shadow_ai.distinct_signatures, FleetValue::Count(1));

        // No device answered at resource_summary, so the finding rows are
        // still dashes — an inventory answer is not evidence about
        // repositories.
        assert_eq!(view.findings[0].value, FleetValue::NotAnswered);
        assert_eq!(view.findings[1].value, FleetValue::NotAnswered);
        assert_eq!(view.findings[2].value, FleetValue::NotAnswered);
        assert!(
            text.contains("not answered at resource_summary scope"),
            "{text}"
        );
        assert!(text.contains("not observable before M12"), "{text}");
        assert!(!text.contains("0 production credentials"), "{text}");
        assert!(view.newest_answer_at.is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A *refused* answer is not data. It must move no row off `—`.
    #[test]
    fn a_refused_query_contributes_nothing_to_the_aggregate() {
        let dir = tmp_dir("refused");
        let mut store = StateStore::open(&dir).unwrap();
        store.register("dev_abc").unwrap();
        let entry = store
            .enqueue_query(
                "dev_abc",
                "secops@acme.com",
                "acme.com",
                "resource_summary",
                None,
            )
            .unwrap();
        store
            .record_answer(
                "dev_abc",
                &entry.query_id,
                &json!({"result_category": "refused", "refusal_reason": "out_of_scope"}),
            )
            .unwrap();
        let view = aggregate(&store);
        assert_eq!(view.findings[0].value, FleetValue::NotAnswered);
        assert!(view.answered_scopes.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
