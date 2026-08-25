//! The ProjectEnvironment manifest (SPEC section 17).
//!
//! Types mirror `schemas/project/project-environment.json` field-for-field;
//! the schema is the contract, these structs conform to it, never the
//! reverse (M6 plan section 4.3). Parsing is two-phase: serde_norway reads
//! the YAML into a `Value`, then a hand-written validation pass builds the
//! typed manifest with **path-qualified** error messages
//! (`permissions.network.corp_prod: …`) and collects **warnings** for
//! unknown fields — unknown fields warn, they do not fail, so a manifest
//! written for a later schema still drives an M6 environment (forward
//! compatibility); every value the schema *does* define is validated
//! strictly, including the schema's deliberate asymmetry: `request` is a
//! credential grant and **invalid** as a network decision.
//!
//! Maps preserve manifest order ([`OrderedMap`]) so `status` renders zones
//! in the order the author declared them (the Atlas fixture's network block
//! is `internet, corp_dev, corp_prod` — not alphabetical).

use std::fmt;
use std::path::{Path, PathBuf};

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use serde_norway::{Mapping, Value};

/// The pinned manifest API version (schema `const`).
pub const API_VERSION: &str = "punar.dev/v1alpha1";
/// The pinned document kind (schema `const`).
pub const KIND: &str = "ProjectEnvironment";

/// Canonical manifest filename (M6 plan section 4.1).
pub const CANONICAL_FILENAME: &str = "punar-env.yaml";
/// Accepted filenames, in lookup order. `project-environment.yaml` is the
/// Atlas fixture's name, matching the schema file.
pub const ACCEPTED_FILENAMES: [&str; 3] = [
    "punar-env.yaml",
    "punar-env.yml",
    "project-environment.yaml",
];

/// The `init` scaffold template, embedded at build time. A byte-identical
/// copy belongs in `schemas/project/examples/` so the schema validator
/// guards it forever (M6 plan section 4.4).
pub const SCAFFOLD: &str = include_str!("../assets/punar-env.scaffold.yaml");
/// The project-name line `init` substitutes in [`SCAFFOLD`].
pub const SCAFFOLD_NAME_LINE: &str = "  name: my-project";

/// A mapping that remembers manifest order. Serializes as a map.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OrderedMap<V>(pub Vec<(String, V)>);

impl<V> OrderedMap<V> {
    pub fn get(&self, key: &str) -> Option<&V> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &V)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }
}

impl<V: Serialize> Serialize for OrderedMap<V> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

/// Filesystem access grade (schema `$defs/filesystem_access`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemAccess {
    ReadWrite,
    Read,
    Deny,
}

impl FilesystemAccess {
    pub fn as_str(self) -> &'static str {
        match self {
            FilesystemAccess::ReadWrite => "read_write",
            FilesystemAccess::Read => "read",
            FilesystemAccess::Deny => "deny",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "read_write" => Some(FilesystemAccess::ReadWrite),
            "read" => Some(FilesystemAccess::Read),
            "deny" => Some(FilesystemAccess::Deny),
            _ => None,
        }
    }
}

impl fmt::Display for FilesystemAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Network decision (shared decision def: allow | deny — never `request`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDecision {
    Allow,
    Deny,
}

impl NetworkDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkDecision::Allow => "allow",
            NetworkDecision::Deny => "deny",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(NetworkDecision::Allow),
            "deny" => Some(NetworkDecision::Deny),
            _ => None,
        }
    }
}

impl fmt::Display for NetworkDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Credential grant mode (schema `$defs/credential_grant`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialGrant {
    Allow,
    Deny,
    Request,
}

impl CredentialGrant {
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialGrant::Allow => "allow",
            CredentialGrant::Deny => "deny",
            CredentialGrant::Request => "request",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(CredentialGrant::Allow),
            "deny" => Some(CredentialGrant::Deny),
            "request" => Some(CredentialGrant::Request),
            _ => None,
        }
    }
}

impl fmt::Display for CredentialGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Project {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Environment {
    /// Always `devcontainer` in v1alpha1 (schema enum of one).
    #[serde(rename = "type")]
    pub environment_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ai {
    pub agents: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Permissions {
    pub filesystem: OrderedMap<FilesystemAccess>,
    pub network: OrderedMap<NetworkDecision>,
    pub credentials: OrderedMap<CredentialGrant>,
}

/// One parsed, validated ProjectEnvironment document.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Manifest {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub project: Project,
    pub environment: Environment,
    pub toolchains: OrderedMap<String>,
    pub services: Vec<String>,
    pub ai: Ai,
    pub permissions: Permissions,
}

/// A successful parse: the manifest plus any forward-compat warnings
/// (unknown fields — warn, never fail).
#[derive(Debug)]
pub struct Parsed {
    pub manifest: Manifest,
    pub warnings: Vec<String>,
}

/// Kebab/dotted name per the schema's service/agent pattern
/// `^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`. Also required of `project.name`
/// by punar-env (stricter than the schema's free-form string): the name
/// becomes the container name `punar-env-<name>` and rides a fixed podman
/// argv, so shell metacharacters, spaces, and leading dashes are rejected
/// here rather than trusted anywhere downstream. Capped at 50 characters
/// so the derived container name stays under podman's 63-character cap.
pub fn is_valid_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    let inner_ok =
        |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-');
    let edge_ok = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    !bytes.is_empty()
        && bytes.len() <= 50
        && edge_ok(bytes[0])
        && edge_ok(bytes[bytes.len() - 1])
        && bytes.iter().all(|&b| inner_ok(b))
}

/// Map-key pattern `^[a-z][a-z0-9_]*$` (toolchain names, permission zones).
fn is_valid_key(s: &str) -> bool {
    let bytes = s.as_bytes();
    !bytes.is_empty()
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// How the manifest file was (not) resolved in a project directory.
#[derive(Debug)]
pub enum Resolution {
    /// Exactly one accepted manifest file.
    Found(PathBuf),
    /// No accepted manifest file (init's scaffold case).
    Missing,
    /// More than one accepted filename present — never guess.
    Conflict(Vec<String>),
}

/// Resolve the manifest file in `dir` per the accepted-filename list.
pub fn resolve(dir: &Path) -> Resolution {
    let present: Vec<String> = ACCEPTED_FILENAMES
        .iter()
        .filter(|name| dir.join(name).is_file())
        .map(|name| (*name).to_string())
        .collect();
    match present.len() {
        0 => Resolution::Missing,
        1 => Resolution::Found(dir.join(&present[0])),
        _ => Resolution::Conflict(present),
    }
}

/// Parse and validate one manifest document. `Err` is the list of
/// path-qualified problems; `Ok` carries unknown-field warnings.
pub fn parse_str(src: &str) -> Result<Parsed, Vec<String>> {
    let value: Value = match serde_norway::from_str(src) {
        Ok(v) => v,
        Err(e) => return Err(vec![format!("YAML syntax: {e}")]),
    };
    let mut cx = Cx::default();
    let manifest = build(&mut cx, &value);
    match manifest {
        Some(m) if cx.problems.is_empty() => Ok(Parsed {
            manifest: m,
            warnings: cx.warnings,
        }),
        _ => Err(cx.problems),
    }
}

/// Validation context: collected problems (fatal) and warnings (not).
#[derive(Default)]
struct Cx {
    problems: Vec<String>,
    warnings: Vec<String>,
}

impl Cx {
    fn problem(&mut self, path: &str, message: &str) {
        self.problems.push(format!("{path}: {message}"));
    }

    /// Unknown fields warn, never fail — a manifest written for a later
    /// schema revision still drives an M6 environment.
    fn warn_unknown(&mut self, path: &str, field: &str) {
        let at = if path.is_empty() {
            field.to_string()
        } else {
            format!("{path}.{field}")
        };
        self.warnings.push(format!(
            "{at}: unknown field — ignored (not part of {API_VERSION}; kept for forward compatibility)"
        ));
    }

    fn mapping<'v>(&mut self, path: &str, value: &'v Value) -> Option<&'v Mapping> {
        match value {
            Value::Mapping(m) => Some(m),
            _ => {
                self.problem(path, "must be a mapping");
                None
            }
        }
    }

    fn string(&mut self, path: &str, value: &Value) -> Option<String> {
        match value {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => {
                self.problem(
                    path,
                    &format!("must be a string; YAML parsed {n} as a number — quote it (\"{n}\")"),
                );
                None
            }
            _ => {
                self.problem(path, "must be a string");
                None
            }
        }
    }
}

/// Fetch `key` from `map`, recording a problem when absent. Scans entries
/// rather than leaning on `Mapping`'s index API — key lookup by string is
/// all we need and the scan is unambiguous across serde_yaml lineages.
fn required<'v>(cx: &mut Cx, path: &str, map: &'v Mapping, key: &str) -> Option<&'v Value> {
    let found = map
        .iter()
        .find(|(k, _)| matches!(k, Value::String(s) if s == key))
        .map(|(_, v)| v);
    if found.is_none() {
        let at = if path.is_empty() {
            key.to_string()
        } else {
            format!("{path}.{key}")
        };
        cx.problems.push(format!("{at}: missing (required)"));
    }
    found
}

/// Warn about keys not in `known` (and reject non-string keys).
fn check_known(cx: &mut Cx, path: &str, map: &Mapping, known: &[&str]) {
    for key in map.keys() {
        match key {
            Value::String(s) => {
                if !known.contains(&s.as_str()) {
                    cx.warn_unknown(path, s);
                }
            }
            other => cx.problem(path, &format!("map keys must be strings (found {other:?})")),
        }
    }
}

fn build(cx: &mut Cx, value: &Value) -> Option<Manifest> {
    let root = cx.mapping("(document)", value)?;
    check_known(
        cx,
        "",
        root,
        &[
            "apiVersion",
            "kind",
            "project",
            "environment",
            "toolchains",
            "services",
            "ai",
            "permissions",
        ],
    );

    let api_version = required(cx, "", root, "apiVersion")
        .and_then(|v| cx.string("apiVersion", v))
        .inspect(|s| {
            if s != API_VERSION {
                cx.problem(
                    "apiVersion",
                    &format!("expected '{API_VERSION}', found '{s}'"),
                );
            }
        });
    let kind = required(cx, "", root, "kind")
        .and_then(|v| cx.string("kind", v))
        .inspect(|s| {
            if s != KIND {
                cx.problem("kind", &format!("expected '{KIND}', found '{s}'"));
            }
        });

    let project = required(cx, "", root, "project").and_then(|v| build_project(cx, v));
    let environment = required(cx, "", root, "environment").and_then(|v| build_environment(cx, v));
    let toolchains = required(cx, "", root, "toolchains").and_then(|v| build_toolchains(cx, v));
    let services = required(cx, "", root, "services").and_then(|v| build_services(cx, v));
    let ai = required(cx, "", root, "ai").and_then(|v| build_ai(cx, v));
    let permissions = required(cx, "", root, "permissions").and_then(|v| build_permissions(cx, v));

    Some(Manifest {
        api_version: api_version?,
        kind: kind?,
        project: project?,
        environment: environment?,
        toolchains: toolchains?,
        services: services?,
        ai: ai?,
        permissions: permissions?,
    })
}

fn build_project(cx: &mut Cx, value: &Value) -> Option<Project> {
    let map = cx.mapping("project", value)?;
    check_known(cx, "project", map, &["name"]);
    let name = required(cx, "project", map, "name").and_then(|v| cx.string("project.name", v))?;
    if !is_valid_name(&name) {
        cx.problem(
            "project.name",
            &format!(
                "'{name}' is not a usable project name — punar-env derives the container name \
                 punar-env-<name> from it; use lowercase letters, digits, '.', '_' or '-' \
                 (starting and ending alphanumeric, at most 50 characters)"
            ),
        );
        return None;
    }
    Some(Project { name })
}

fn build_environment(cx: &mut Cx, value: &Value) -> Option<Environment> {
    let map = cx.mapping("environment", value)?;
    check_known(cx, "environment", map, &["type"]);
    let environment_type =
        required(cx, "environment", map, "type").and_then(|v| cx.string("environment.type", v))?;
    if environment_type != "devcontainer" {
        cx.problem(
            "environment.type",
            &format!("'{environment_type}' is not a known environment type (known: devcontainer)"),
        );
        return None;
    }
    Some(Environment { environment_type })
}

fn build_toolchains(cx: &mut Cx, value: &Value) -> Option<OrderedMap<String>> {
    let map = cx.mapping("toolchains", value)?;
    if map.is_empty() {
        cx.problem("toolchains", "must declare at least one toolchain");
        return None;
    }
    let mut out = Vec::new();
    for (key, version) in map {
        let Value::String(name) = key else {
            cx.problem(
                "toolchains",
                &format!("map keys must be strings (found {key:?})"),
            );
            continue;
        };
        if !is_valid_key(name) {
            cx.problem(
                &format!("toolchains.{name}"),
                "toolchain names are snake_case: lowercase letter first, then lowercase letters, digits or '_'",
            );
            continue;
        }
        let path = format!("toolchains.{name}");
        if let Some(v) = cx.string(&path, version) {
            if v.is_empty() {
                cx.problem(&path, "version request must be non-empty");
            } else {
                out.push((name.clone(), v));
            }
        }
    }
    Some(OrderedMap(out))
}

/// A sequence of unique kebab/dotted names (services, ai.agents).
fn build_name_list(cx: &mut Cx, path: &str, value: &Value, what: &str) -> Option<Vec<String>> {
    let Value::Sequence(seq) = value else {
        cx.problem(path, "must be a list");
        return None;
    };
    if seq.is_empty() {
        cx.problem(path, &format!("must declare at least one {what}"));
        return None;
    }
    let mut out: Vec<String> = Vec::new();
    for (i, item) in seq.iter().enumerate() {
        let item_path = format!("{path}[{i}]");
        let Some(name) = cx.string(&item_path, item) else {
            continue;
        };
        if !is_valid_name(&name) {
            cx.problem(
                &item_path,
                &format!(
                    "'{name}' is not a valid {what} name — lowercase letters, digits, '.', '_' or \
                     '-', starting and ending alphanumeric"
                ),
            );
            continue;
        }
        if out.contains(&name) {
            cx.problem(&item_path, &format!("duplicate {what} '{name}'"));
            continue;
        }
        out.push(name);
    }
    Some(out)
}

fn build_services(cx: &mut Cx, value: &Value) -> Option<Vec<String>> {
    build_name_list(cx, "services", value, "service")
}

fn build_ai(cx: &mut Cx, value: &Value) -> Option<Ai> {
    let map = cx.mapping("ai", value)?;
    check_known(cx, "ai", map, &["agents"]);
    let agents = required(cx, "ai", map, "agents")
        .and_then(|v| build_name_list(cx, "ai.agents", v, "agent"))?;
    Some(Ai { agents })
}

/// One permissions sub-map: zone-name keys, values parsed by `parse`.
fn build_grant_map<T>(
    cx: &mut Cx,
    path: &str,
    value: &Value,
    allowed: &str,
    parse: impl Fn(&str) -> Option<T>,
    reject_hint: impl Fn(&str) -> Option<String>,
) -> Option<OrderedMap<T>> {
    let map = cx.mapping(path, value)?;
    if map.is_empty() {
        cx.problem(path, "must declare at least one entry");
        return None;
    }
    let mut out = Vec::new();
    for (key, grant) in map {
        let Value::String(zone) = key else {
            cx.problem(path, &format!("map keys must be strings (found {key:?})"));
            continue;
        };
        let entry_path = format!("{path}.{zone}");
        if !is_valid_key(zone) {
            cx.problem(
                &entry_path,
                "zone names are snake_case: lowercase letter first, then lowercase letters, digits or '_'",
            );
            continue;
        }
        let Some(raw) = cx.string(&entry_path, grant) else {
            continue;
        };
        match parse(&raw) {
            Some(parsed) => out.push((zone.clone(), parsed)),
            None => {
                let hint = reject_hint(&raw)
                    .unwrap_or_else(|| format!("'{raw}' is not one of: {allowed}"));
                cx.problem(&entry_path, &hint);
            }
        }
    }
    Some(OrderedMap(out))
}

fn build_permissions(cx: &mut Cx, value: &Value) -> Option<Permissions> {
    let map = cx.mapping("permissions", value)?;
    check_known(
        cx,
        "permissions",
        map,
        &["filesystem", "network", "credentials"],
    );

    let filesystem = required(cx, "permissions", map, "filesystem").and_then(|v| {
        build_grant_map(
            cx,
            "permissions.filesystem",
            v,
            "read_write, read, deny",
            FilesystemAccess::parse,
            |_| None,
        )
    });
    let network = required(cx, "permissions", map, "network").and_then(|v| {
        build_grant_map(
            cx,
            "permissions.network",
            v,
            "allow, deny",
            NetworkDecision::parse,
            |raw| {
                (raw == "request").then(|| {
                    "'request' is a credential grant, not a network decision (allow, deny) — \
                     the schema keeps this asymmetry deliberately"
                        .to_string()
                })
            },
        )
    });
    let credentials = required(cx, "permissions", map, "credentials").and_then(|v| {
        build_grant_map(
            cx,
            "permissions.credentials",
            v,
            "allow, deny, request",
            CredentialGrant::parse,
            |_| None,
        )
    });

    Some(Permissions {
        filesystem: filesystem?,
        network: network?,
        credentials: credentials?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Atlas fixture, path-relative to the repo — the spec section 17
    /// example byte-verbatim (fixtures/projects/atlas/README.md).
    pub const ATLAS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/projects/atlas/project-environment.yaml"
    ));

    fn parse_ok(src: &str) -> Parsed {
        parse_str(src).expect("manifest should parse")
    }

    fn parse_problems(src: &str) -> Vec<String> {
        parse_str(src).expect_err("manifest should be rejected")
    }

    #[test]
    fn atlas_fixture_parses_with_every_field_and_no_warnings() {
        let parsed = parse_ok(ATLAS);
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        let m = parsed.manifest;
        assert_eq!(m.api_version, API_VERSION);
        assert_eq!(m.kind, KIND);
        assert_eq!(m.project.name, "atlas");
        assert_eq!(m.environment.environment_type, "devcontainer");
        assert_eq!(
            m.toolchains.0,
            vec![
                ("node".to_string(), "24".to_string()),
                ("rust".to_string(), "stable".to_string()),
            ]
        );
        assert_eq!(m.services, vec!["postgres"]);
        assert_eq!(m.ai.agents, vec!["claude-code", "codex"]);
        assert_eq!(
            m.permissions.filesystem.0,
            vec![("project".to_string(), FilesystemAccess::ReadWrite)]
        );
        // Manifest order preserved — internet first, not alphabetical.
        assert_eq!(
            m.permissions.network.0,
            vec![
                ("internet".to_string(), NetworkDecision::Allow),
                ("corp_dev".to_string(), NetworkDecision::Allow),
                ("corp_prod".to_string(), NetworkDecision::Deny),
            ]
        );
        assert_eq!(
            m.permissions.credentials.0,
            vec![
                ("github".to_string(), CredentialGrant::Allow),
                ("aws_dev".to_string(), CredentialGrant::Request),
                ("aws_prod".to_string(), CredentialGrant::Deny),
            ]
        );
    }

    /// Serialize → reparse → identical manifest: no data loss through the
    /// typed representation (M6 plan section 4.3 round-trip requirement).
    #[test]
    fn atlas_fixture_round_trips_without_data_loss() {
        let first = parse_ok(ATLAS).manifest;
        let yaml = serde_norway::to_string(&first).expect("serialize");
        let second = parse_ok(&yaml).manifest;
        assert_eq!(first, second);
    }

    #[test]
    fn scaffold_is_valid_and_carries_the_substitution_line_once() {
        let parsed = parse_ok(SCAFFOLD);
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        assert_eq!(parsed.manifest.project.name, "my-project");
        assert_eq!(SCAFFOLD.matches(SCAFFOLD_NAME_LINE).count(), 1);
        // The scaffold declares the full section 17 shape, like the schema
        // requires — every top-level key present and non-empty.
        assert!(!parsed.manifest.toolchains.0.is_empty());
        assert!(!parsed.manifest.services.is_empty());
        assert!(!parsed.manifest.ai.agents.is_empty());
    }

    #[test]
    fn unknown_fields_warn_but_do_not_fail() {
        let src = ATLAS.replace(
            "permissions:",
            "future_block:\n  anything: goes\n\npermissions:\n  future_key: yes_really",
        );
        let parsed = parse_ok(&src);
        assert_eq!(parsed.manifest.project.name, "atlas");
        let joined = parsed.warnings.join("\n");
        assert!(joined.contains("future_block: unknown field"), "{joined}");
        assert!(
            joined.contains("permissions.future_key: unknown field"),
            "{joined}"
        );
    }

    #[test]
    fn wrong_api_version_is_rejected_with_path() {
        let src = ATLAS.replace("punar.dev/v1alpha1", "punar.dev/v2");
        let problems = parse_problems(&src);
        assert!(
            problems.iter().any(|p| p.starts_with("apiVersion: ")),
            "{problems:?}"
        );
    }

    #[test]
    fn request_in_network_is_rejected_with_the_asymmetry_hint() {
        let src = ATLAS.replace("corp_dev: allow", "corp_dev: request");
        let problems = parse_problems(&src);
        let hit = problems
            .iter()
            .find(|p| p.starts_with("permissions.network.corp_dev: "))
            .expect("path-qualified problem");
        assert!(hit.contains("credential grant"), "{hit}");
    }

    #[test]
    fn empty_toolchains_is_rejected() {
        let src = ATLAS.replace(
            "toolchains:\n  node: \"24\"\n  rust: stable",
            "toolchains: {}",
        );
        let problems = parse_problems(&src);
        assert!(
            problems.iter().any(|p| p.starts_with("toolchains: ")),
            "{problems:?}"
        );
    }

    #[test]
    fn unquoted_numeric_toolchain_version_gets_the_quote_hint() {
        let src = ATLAS.replace("node: \"24\"", "node: 24");
        let problems = parse_problems(&src);
        let hit = problems
            .iter()
            .find(|p| p.starts_with("toolchains.node: "))
            .expect("path-qualified problem");
        assert!(hit.contains("quote"), "{hit}");
    }

    #[test]
    fn hostile_project_names_are_rejected_before_any_argv_exists() {
        for name in [
            "atlas; rm -rf /",
            "$(reboot)",
            "atlas atlas",
            "-leading-dash",
            "Atlas",
            "",
            "a☂",
        ] {
            assert!(!is_valid_name(name), "{name:?} must be rejected");
            let src = ATLAS.replace("name: atlas", &format!("name: {:?}", name));
            let problems = parse_problems(&src);
            assert!(
                problems.iter().any(|p| p.starts_with("project.name: ")),
                "{name:?}: {problems:?}"
            );
        }
        for name in ["atlas", "atlas-2", "a", "my.project_x"] {
            assert!(is_valid_name(name), "{name:?} must be accepted");
        }
    }

    #[test]
    fn missing_required_blocks_are_all_reported() {
        let problems = parse_problems("apiVersion: punar.dev/v1alpha1\nkind: ProjectEnvironment\n");
        for path in [
            "project",
            "environment",
            "toolchains",
            "services",
            "ai",
            "permissions",
        ] {
            assert!(
                problems.iter().any(|p| p.starts_with(&format!("{path}: "))),
                "{path}: {problems:?}"
            );
        }
    }

    #[test]
    fn resolve_conflict_lists_every_present_name() {
        let dir = std::env::temp_dir().join(format!("punar-env-resolve-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(matches!(resolve(&dir), Resolution::Missing));
        std::fs::write(dir.join("punar-env.yaml"), ATLAS).unwrap();
        assert!(matches!(resolve(&dir), Resolution::Found(_)));
        std::fs::write(dir.join("project-environment.yaml"), ATLAS).unwrap();
        match resolve(&dir) {
            Resolution::Conflict(names) => {
                assert_eq!(names, vec!["punar-env.yaml", "project-environment.yaml"]);
            }
            other => panic!("expected conflict, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
