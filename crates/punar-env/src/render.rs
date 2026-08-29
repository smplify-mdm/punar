//! `punar-env status` rendering — Plate D-014 grammar
//! (`docs/design/mockups/cli-grammar.html`) in the exact layout the M6
//! plan's target render fixes (docs/development/milestone-6.md section 7):
//! masthead + U+2500 rule, middle-dot separators, aligned columns, ANSI
//! color only on the state word, **no org rows ever** (unmanaged-first —
//! an environment manifest is the user's declaration).
//!
//! Every permission block carries its current enforcement state, in the
//! human view and in the `--json` object alike, so no consumer can scrape
//! a value and drop the honesty label (SPEC 1.22).

use std::env;
use std::io::IsTerminal;

use serde_json::{Value, json};

use crate::engine::{ContainerState, project_grade};
use crate::manifest::{FilesystemAccess, Manifest};

/// Masthead rule width — the M6 plan's target render (56 × U+2500).
pub const RULE_WIDTH: usize = 56;
/// Top label column ("Environment" + 3).
const LABEL_W: usize = 14;
/// Inner single-name column (toolchains, services), after the 2-space indent.
const NAME_W: usize = 12;
/// Permissions category column.
const CAT_W: usize = 12;
/// Permissions zone column.
const ZONE_W: usize = 13;
/// Permissions value column.
const VALUE_W: usize = 13;

/// Everything `status` shows, gathered before rendering.
pub struct StatusData {
    pub manifest: Manifest,
    pub container: String,
    pub state: ContainerState,
    /// Host-side project directory (the bind-mount source).
    pub src: String,
}

/// ANSI on/off. Color is spent only on the state word (D-014).
#[derive(Debug, Clone, Copy)]
pub struct Style {
    pub color: bool,
}

impl Style {
    /// Color only when stdout is a TTY and `NO_COLOR` is unset or empty
    /// (no-color.org convention) — pipes and scripts see clean columns.
    pub fn detect() -> Self {
        let no_color = env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        Style {
            color: std::io::stdout().is_terminal() && !no_color,
        }
    }

    #[cfg(test)]
    pub const fn plain() -> Self {
        Style { color: false }
    }

    fn paint(&self, sgr: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{sgr}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    /// The state word: green running, amber stopped, muted not created.
    fn state(&self, state: ContainerState) -> String {
        match state {
            ContainerState::Running => self.paint("32", state.as_str()),
            ContainerState::Stopped => self.paint("33", state.as_str()),
            ContainerState::NotCreated => self.paint("90", state.as_str()),
        }
    }
}

fn pad(text: &str, width: usize) -> String {
    let len = text.chars().count();
    if len >= width {
        format!("{text} ")
    } else {
        format!("{text}{}", " ".repeat(width - len))
    }
}

/// The human D-014 view.
pub fn render_human(d: &StatusData, style: &Style) -> String {
    let m = &d.manifest;
    let mut out = String::new();

    // Masthead + rule.
    out.push_str(&format!("PUNAR-ENV · {}\n", m.project.name.to_uppercase()));
    out.push_str(&"─".repeat(RULE_WIDTH));
    out.push('\n');

    // Top rows.
    out.push_str(&pad("Environment", LABEL_W));
    out.push_str(&format!(
        "{} · {} · {}\n",
        m.environment.environment_type,
        style.state(d.state),
        d.container
    ));
    out.push_str(&pad("Workspace", LABEL_W));
    out.push_str(&workspace_line(d));
    out.push('\n');
    out.push_str(&pad("Network", LABEL_W));
    out.push_str("none · deny enforced · allow declared (Phase 2)\n");

    // Toolchains — declared, reported, not installed (M6 plan section 5.5).
    out.push_str("\nTOOLCHAINS · DECLARED · provisioning arrives with the network story\n");
    let name_w = inner_width(m.toolchains.iter().map(|(k, _)| k));
    for (name, version) in m.toolchains.iter() {
        out.push_str(&format!("  {}{version}\n", pad(name, name_w)));
    }

    // Services — skipped in M6 by decision (M6 plan section 5.6).
    out.push_str("\nSERVICES · DECLARED · not started in M6\n");
    let name_w = inner_width(m.services.iter().map(String::as_str));
    for service in &m.services {
        out.push_str(&format!("  {}declared\n", pad(service, name_w)));
    }

    // AI agents — sessions arrive M7.
    out.push_str("\nAI AGENTS · DECLARED · sessions arrive M7\n");
    out.push_str(&format!("  {}\n", m.ai.agents.join(" · ")));

    // Permissions — the section 17 block, verbatim values, per-row labels.
    out.push_str("\nPERMISSIONS · DECLARED · enforcement milestones per row\n");
    let zone_w = permissions_zone_width(m);
    let value_w = permissions_value_width(m);
    for (zone, grade) in m.permissions.filesystem.iter() {
        out.push_str(&permission_row(
            "filesystem",
            zone,
            grade.as_str(),
            &filesystem_label(d, zone, *grade),
            zone_w,
            value_w,
        ));
    }
    for (zone, decision) in m.permissions.network.iter() {
        out.push_str(&permission_row(
            "network",
            zone,
            decision.as_str(),
            "enforced (agent scope) · container: deny only",
            zone_w,
            value_w,
        ));
    }
    for (class, grant) in m.permissions.credentials.iter() {
        out.push_str(&permission_row(
            "credentials",
            class,
            grant.as_str(),
            "declared · enforced M9",
            zone_w,
            value_w,
        ));
    }

    out
}

fn workspace_line(d: &StatusData) -> String {
    let grade = project_grade(&d.manifest);
    match grade {
        FilesystemAccess::Deny => "no project mount · deny (filesystem.project)".to_string(),
        _ => {
            let applied = if d.state == ContainerState::NotCreated {
                "declared"
            } else {
                "applied · bind mount"
            };
            format!("{} → /workspace · {} ({applied})", d.src, grade.as_str())
        }
    }
}

/// The per-row label for filesystem zones. `project` is the one grant M6
/// realizes (via the bind mount); every other zone has no M6 realization.
fn filesystem_label(d: &StatusData, zone: &str, grade: FilesystemAccess) -> String {
    if zone != "project" {
        return "declared · not realized in M6".to_string();
    }
    if d.state == ContainerState::NotCreated {
        return "declared · applied on up".to_string();
    }
    match grade {
        FilesystemAccess::Deny => "applied (no mount)".to_string(),
        _ => "applied (bind mount)".to_string(),
    }
}

fn permission_row(
    category: &str,
    zone: &str,
    value: &str,
    label: &str,
    zone_w: usize,
    value_w: usize,
) -> String {
    format!(
        "  {}{}{}{label}\n",
        pad(category, CAT_W),
        pad(zone, zone_w),
        pad(value, value_w)
    )
}

fn inner_width<'a>(names: impl Iterator<Item = &'a str>) -> usize {
    names
        .map(|n| n.chars().count() + 2)
        .max()
        .unwrap_or(0)
        .max(NAME_W)
}

fn permissions_zone_width(m: &Manifest) -> usize {
    let longest = m
        .permissions
        .filesystem
        .iter()
        .map(|(z, _)| z.chars().count())
        .chain(m.permissions.network.iter().map(|(z, _)| z.chars().count()))
        .chain(
            m.permissions
                .credentials
                .iter()
                .map(|(z, _)| z.chars().count()),
        )
        .max()
        .unwrap_or(0);
    (longest + 2).max(ZONE_W)
}

fn permissions_value_width(m: &Manifest) -> usize {
    let longest = m
        .permissions
        .filesystem
        .iter()
        .map(|(_, v)| v.as_str().len())
        .chain(m.permissions.network.iter().map(|(_, v)| v.as_str().len()))
        .chain(
            m.permissions
                .credentials
                .iter()
                .map(|(_, v)| v.as_str().len()),
        )
        .max()
        .unwrap_or(0);
    (longest + 2).max(VALUE_W)
}

/// The machine object (M6 plan section 7): declared values plus the
/// enforcement labels — the honesty travels with the data.
pub fn render_json(d: &StatusData) -> Value {
    let m = &d.manifest;
    json!({
        "v": 1,
        "project": m.project.name,
        "container": d.container,
        "state": d.state.as_str(),
        "workspace": {
            "src": d.src,
            "dst": "/workspace",
            "mode": project_grade(m).as_str(),
        },
        "toolchains": serde_json::to_value(&m.toolchains).expect("toolchains serialize"),
        "services": m.services,
        "ai": { "agents": m.ai.agents },
        "permissions": serde_json::to_value(&m.permissions).expect("permissions serialize"),
        "enforcement": {
            "network": "enforced",
            "credentials": "M9",
            "ai": "M7",
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest;
    use crate::podman::container_name;

    const ATLAS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/projects/atlas/project-environment.yaml"
    ));

    fn atlas_status(state: ContainerState) -> StatusData {
        let manifest = manifest::parse_str(ATLAS).unwrap().manifest;
        let container = container_name(&manifest.project.name);
        StatusData {
            manifest,
            container,
            state,
            src: "/home/punar/atlas".to_string(),
        }
    }

    /// The M6 plan section 7 target render, snapshot-exact (fixture
    /// values verbatim — m6-check greps these tokens).
    #[test]
    fn atlas_running_matches_the_plan_target_render() {
        let out = render_human(&atlas_status(ContainerState::Running), &Style::plain());
        let expected = format!(
            "PUNAR-ENV · ATLAS\n\
             {}\n\
             Environment   devcontainer · running · punar-env-atlas\n\
             Workspace     /home/punar/atlas → /workspace · read_write (applied · bind mount)\n\
             Network       none · deny enforced · allow declared (Phase 2)\n\
             \n\
             TOOLCHAINS · DECLARED · provisioning arrives with the network story\n\
             \x20 node        24\n\
             \x20 rust        stable\n\
             \n\
             SERVICES · DECLARED · not started in M6\n\
             \x20 postgres    declared\n\
             \n\
             AI AGENTS · DECLARED · sessions arrive M7\n\
             \x20 claude-code · codex\n\
             \n\
             PERMISSIONS · DECLARED · enforcement milestones per row\n\
             \x20 filesystem  project      read_write   applied (bind mount)\n\
             \x20 network     internet     allow        enforced (agent scope) · container: deny only\n\
             \x20 network     corp_dev     allow        enforced (agent scope) · container: deny only\n\
             \x20 network     corp_prod    deny         enforced (agent scope) · container: deny only\n\
             \x20 credentials github       allow        declared · enforced M9\n\
             \x20 credentials aws_dev      request      declared · enforced M9\n\
             \x20 credentials aws_prod     deny         declared · enforced M9\n",
            "─".repeat(RULE_WIDTH)
        );
        assert_eq!(out, expected);
    }

    #[test]
    fn not_created_state_stays_honest() {
        let out = render_human(&atlas_status(ContainerState::NotCreated), &Style::plain());
        assert!(out.contains("devcontainer · not created · punar-env-atlas"));
        assert!(out.contains("read_write (declared)"));
        assert!(out.contains("read_write   declared · applied on up"));
        assert!(!out.contains("applied (bind mount)"));
    }

    /// No org rows, ever — unmanaged-first.
    #[test]
    fn no_organization_rows() {
        for state in [ContainerState::Running, ContainerState::NotCreated] {
            let out = render_human(&atlas_status(state), &Style::plain());
            assert!(!out.to_lowercase().contains("organization"));
        }
    }

    #[test]
    fn color_is_spent_only_on_the_state_word() {
        let style = Style { color: true };
        let out = render_human(&atlas_status(ContainerState::Running), &style);
        assert!(out.contains("\x1b[32mrunning\x1b[0m"));
        assert_eq!(out.matches('\x1b').count(), 2, "one colored word only");
    }

    #[test]
    fn json_carries_declared_values_and_enforcement_labels() {
        let v = render_json(&atlas_status(ContainerState::Running));
        assert_eq!(v["v"], 1);
        assert_eq!(v["project"], "atlas");
        assert_eq!(v["container"], "punar-env-atlas");
        assert_eq!(v["state"], "running");
        assert_eq!(v["workspace"]["src"], "/home/punar/atlas");
        assert_eq!(v["workspace"]["dst"], "/workspace");
        assert_eq!(v["workspace"]["mode"], "read_write");
        assert_eq!(v["toolchains"]["node"], "24");
        assert_eq!(v["toolchains"]["rust"], "stable");
        assert_eq!(v["services"][0], "postgres");
        assert_eq!(v["ai"]["agents"][1], "codex");
        assert_eq!(v["permissions"]["filesystem"]["project"], "read_write");
        assert_eq!(v["permissions"]["network"]["corp_prod"], "deny");
        assert_eq!(v["permissions"]["credentials"]["aws_dev"], "request");
        assert_eq!(v["enforcement"]["network"], "enforced");
        assert_eq!(v["enforcement"]["credentials"], "M9");
        assert_eq!(v["enforcement"]["ai"], "M7");
    }

    #[test]
    fn json_state_words_match_the_human_states() {
        for (state, word) in [
            (ContainerState::Running, "running"),
            (ContainerState::Stopped, "stopped"),
            (ContainerState::NotCreated, "not created"),
        ] {
            assert_eq!(render_json(&atlas_status(state))["state"], word);
        }
    }
}
