//! AI Agent Gateway adapters, as **data** (SPEC section 26 — "Adapters
//! should be modular"; docs/development/milestone-7.md section 5.4).
//!
//! An adapter is one `schemas/ai-agent/agent-definition.json` document
//! staged at `/usr/share/punar/agents/adapters/*.json`. Everything the
//! launch path needs — the command argv, the version probe, the detection
//! signature the daemon scans with, and the dev/CI mock override — lives
//! in `adapter_config`, the schema's explicitly extensible object. Adding
//! an agent is therefore adding a file: the shipped `generic-shell`
//! adapter is the modularity proof (same launch path, different data,
//! zero new code).
//!
//! Two rules this module enforces, both about not trusting data with the
//! host shell (M6 section 3.2, carried into M7):
//!
//! - a command is an **argv array**, never a string — nothing here is ever
//!   handed to `/bin/sh`;
//! - the definition's `name` must match the registry-record `agent`
//!   pattern before it can ride an IPC field or a systemd unit name.
//!
//! Definitions are matched by their `name` field, not by filename: the
//! generic adapter ships as `generic.json` and is named `generic-shell`
//! (the SPEC section 26 "generic shell/agent adapter").

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::engine::EnvError;

/// Where the desktop image stages adapter definitions (contract path,
/// `punar_common::agent::ADAPTERS_DIR`).
pub const ADAPTERS_DIR: &str = punar_common::agent::ADAPTERS_DIR;

/// Test/dev override for [`ADAPTERS_DIR`]. Never set in the image.
pub const ADAPTERS_DIR_ENV: &str = "PUNAR_AGENT_ADAPTERS_DIR";

/// The one environment variable that swaps the adapter's real command for
/// the mock stand-in (milestone-7.md section 5.5). Nothing sets it by
/// default; `m7-check` sets it because the CI VM has no network and no
/// real agent binary.
pub const MOCK_ENV: &str = "PUNAR_AGENT_MOCK";

/// The loud label printed whenever the mock command is used. First line of
/// the launch block, greppable, uppercase MOCK.
pub const MOCK_LABEL: &str = "MOCK AGENT · dev/CI stand-in — not a real AI agent";

/// One agent definition (`schemas/ai-agent/agent-definition.json`).
/// Deliberately lenient on unknown top-level fields: the schema is strict,
/// the *reader* stays forward-compatible, exactly like the manifest
/// reader (M6 section 4.3).
#[derive(Debug, Clone, Deserialize)]
pub struct AgentDefinition {
    /// Canonical agent product name, e.g. `claude-code`.
    pub name: String,
    /// Gateway adapter id, e.g. `claude_code` (SPEC section 26).
    pub adapter: String,
    #[serde(default)]
    pub launch: Option<Launch>,
    #[serde(default)]
    pub adapter_config: AdapterConfig,
}

/// The managed launch method (SPEC section 27).
#[derive(Debug, Clone, Deserialize)]
pub struct Launch {
    /// Schema enum of one: `managed`.
    pub method: String,
    /// The documented `punar-env` invocation, e.g.
    /// `punar-env agent claude-code`. Display/documentation only — it is
    /// never executed; the argv comes from `adapter_config.command`.
    #[allow(dead_code)]
    pub command: String,
}

/// Adapter-specific configuration (the schema's extensible object). The
/// adapter author validates it; this is that validation for the two
/// adapters Punar ships.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AdapterConfig {
    /// Argv of the real agent — never a shell string.
    #[serde(default)]
    pub command: Vec<String>,
    /// Argv of a fast version probe; absent means "no probe" and the
    /// session records `version: "unknown"`.
    #[serde(default)]
    pub version_command: Vec<String>,
    /// Argv of the dev/CI stand-in, used only under `PUNAR_AGENT_MOCK=1`.
    #[serde(default)]
    pub mock_command: Vec<String>,
    /// Detection signature consumed by `punar-agentd`'s scan
    /// (milestone-7.md section 7.1). Read here only so a malformed
    /// adapter is rejected at launch time too.
    #[serde(default)]
    pub signature: Signature,
}

/// The `/proc`-walk signature for a known agent.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Signature {
    #[serde(default)]
    pub comm: Vec<String>,
    #[serde(default)]
    pub exe_glob: Vec<String>,
}

impl AgentDefinition {
    /// Validate the fields the launch path depends on. The JSON schema is
    /// the contract for the file; this is the runtime mirror of the parts
    /// that must hold before a name rides an IPC field or a unit name.
    fn validate(&self, source: &Path) -> Result<(), EnvError> {
        let mut problems: Vec<String> = Vec::new();
        if !punar_common::agent::agent_name_ok(&self.name) {
            problems.push(format!(
                "name '{}' must match ^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$",
                self.name
            ));
        }
        if !adapter_id_ok(&self.adapter) {
            problems.push(format!(
                "adapter '{}' must match ^[a-z][a-z0-9_]*$",
                self.adapter
            ));
        }
        match &self.launch {
            Some(launch) if launch.method != "managed" => problems.push(format!(
                "launch.method '{}' is not a launch method this punar-env knows \
                 (the schema defines exactly one: managed)",
                launch.method
            )),
            _ => {}
        }
        if self.adapter_config.command.is_empty() {
            problems.push(
                "adapter_config.command must be a non-empty argv array (a command is an \
                 argv array, never a shell string)"
                    .to_string(),
            );
        }
        for (field, argv) in [
            ("adapter_config.command", &self.adapter_config.command),
            (
                "adapter_config.version_command",
                &self.adapter_config.version_command,
            ),
            (
                "adapter_config.mock_command",
                &self.adapter_config.mock_command,
            ),
        ] {
            if argv.iter().any(|a| a.is_empty()) {
                problems.push(format!("{field} contains an empty argument"));
            }
        }
        // The signature is `punar-agentd`'s scan input, not punar-env's,
        // but an empty pattern would match everything: a malformed
        // signature is refused here too, at the file's first reader.
        for (field, patterns) in [
            (
                "adapter_config.signature.comm",
                &self.adapter_config.signature.comm,
            ),
            (
                "adapter_config.signature.exe_glob",
                &self.adapter_config.signature.exe_glob,
            ),
        ] {
            if patterns.iter().any(|p| p.trim().is_empty()) {
                problems.push(format!(
                    "{field} contains an empty pattern (an empty detection pattern \
                     would match every process)"
                ));
            }
        }
        if problems.is_empty() {
            return Ok(());
        }
        let listed = problems
            .iter()
            .map(|p| format!("\n  {p}"))
            .collect::<String>();
        Err(EnvError::Runtime(format!(
            "the agent adapter definition {} is not usable:{listed}\n\
             Schema: schemas/ai-agent/agent-definition.json (SPEC sections 19.1, 26).\n\
             Next step: fix the staged adapter file, or remove it so punar-env stops \
             offering the agent.",
            source.display()
        )))
    }

    /// The argv this session should launch: the mock stand-in when
    /// `PUNAR_AGENT_MOCK=1` is set **and** the adapter declares one, the
    /// real command otherwise (milestone-7.md section 5.5).
    pub fn launch_argv(&self, mock_requested: bool) -> Launched {
        if mock_requested && !self.adapter_config.mock_command.is_empty() {
            return Launched {
                argv: self.adapter_config.mock_command.clone(),
                mock: true,
            };
        }
        Launched {
            argv: self.adapter_config.command.clone(),
            mock: false,
        }
    }
}

/// The chosen command plus whether it is the stand-in — the caller must
/// print the label when it is (SPEC 1.22: a mock never passes for real).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launched {
    pub argv: Vec<String>,
    pub mock: bool,
}

/// `^[a-z][a-z0-9_]*$` — the schema's adapter-id pattern.
fn adapter_id_ok(id: &str) -> bool {
    let bytes = id.as_bytes();
    !bytes.is_empty()
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

/// Whether this process was asked for the mock stand-in.
pub fn mock_requested() -> bool {
    std::env::var(MOCK_ENV).is_ok_and(|v| v == "1")
}

/// The staged adapter directory, honoring the test/dev override.
pub fn adapters_dir() -> PathBuf {
    std::env::var_os(ADAPTERS_DIR_ENV)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(ADAPTERS_DIR))
}

/// One loaded definition and the file it came from.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub definition: AgentDefinition,
    pub source: PathBuf,
}

/// Load every `*.json` adapter definition in `dir`, in filename order.
/// A definition that does not parse or does not validate is a hard error:
/// silently skipping it would make an agent disappear with no explanation.
pub fn load_all(dir: &Path) -> Result<Vec<Loaded>, EnvError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(EnvError::Runtime(format!(
                "cannot read the agent adapter directory {}: {e}.\n\
                 Adapters are data shipped with the Punar image (SPEC section 26).\n\
                 Next step: check the directory's permissions, or reinstall the image.",
                dir.display()
            )));
        }
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();

    let mut loaded = Vec::with_capacity(files.len());
    for file in files {
        let src = std::fs::read_to_string(&file).map_err(|e| {
            EnvError::Runtime(format!(
                "cannot read the agent adapter definition {}: {e}.\n\
                 Next step: check the file's permissions.",
                file.display()
            ))
        })?;
        let definition: AgentDefinition = serde_json::from_str(&src).map_err(|e| {
            EnvError::Runtime(format!(
                "the agent adapter definition {} is not valid JSON for \
                 schemas/ai-agent/agent-definition.json: {e}.\n\
                 Next step: fix the staged adapter file, or remove it.",
                file.display()
            ))
        })?;
        definition.validate(&file)?;
        loaded.push(Loaded {
            definition,
            source: file,
        });
    }
    Ok(loaded)
}

/// Find the definition whose `name` is `name` (matching is on the field,
/// not the filename — `generic.json` is named `generic-shell`).
///
/// A declared agent with no installed adapter is an honest runtime error
/// naming the file punar-env looked for (milestone-7.md section 5.1
/// step 1) — Atlas declares `codex`, and Punar ships no codex adapter.
pub fn find(dir: &Path, name: &str) -> Result<Loaded, EnvError> {
    let all = load_all(dir)?;
    if let Some(found) = all.iter().find(|l| l.definition.name == name) {
        return Ok(found.clone());
    }
    let installed: Vec<&str> = all.iter().map(|l| l.definition.name.as_str()).collect();
    let installed_line = if installed.is_empty() {
        "none are installed".to_string()
    } else {
        installed.join(" · ")
    };
    Err(EnvError::Runtime(format!(
        "no gateway adapter is installed for agent '{name}'.\n\
         '{name}' is declared in this environment's manifest, but punar-env found no \
         definition naming it in {} (installed adapters: {installed_line}).\n\
         Next step: install an adapter definition for '{name}' (SPEC section 26), or \
         launch one of the installed agents.",
        dir.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two adapters the desktop image stages, read from the tree that
    /// actually ships them — the test and the image can never drift.
    const STAGED_DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../os/images/mkosi.profiles/desktop/mkosi.extra/usr/share/punar/agents/adapters"
    );

    fn staged() -> Vec<Loaded> {
        load_all(Path::new(STAGED_DIR)).expect("staged adapters load")
    }

    #[test]
    fn the_shipped_adapters_parse_and_validate() {
        let all = staged();
        let names: Vec<&str> = all.iter().map(|l| l.definition.name.as_str()).collect();
        assert_eq!(names, vec!["claude-code", "generic-shell"]);
    }

    /// SPEC section 26: the initial Claude Code adapter, with the launch
    /// method section 27 defines.
    #[test]
    fn claude_code_adapter_carries_the_managed_launch_contract() {
        let found = find(Path::new(STAGED_DIR), "claude-code").unwrap();
        let d = &found.definition;
        assert_eq!(d.adapter, "claude_code");
        let launch = d.launch.as_ref().expect("claude-code declares launch");
        assert_eq!(launch.method, "managed");
        assert_eq!(launch.command, "punar-env agent claude-code");
        assert_eq!(d.adapter_config.command, vec!["claude"]);
        // Declared, but never executed before the ADR-004 boundary.
        assert_eq!(d.adapter_config.version_command, ["claude", "--version"]);
        assert_eq!(d.adapter_config.signature.comm, vec!["claude"]);
    }

    /// The second adapter (SPEC section 26's "generic shell/agent
    /// adapter") is the modularity proof: same launch path, different
    /// data. Its signature arrays are deliberately empty — a plain
    /// `/bin/sh` must never be flagged as an observed AI agent.
    #[test]
    fn generic_adapter_is_a_second_adapter_with_no_detection_signature() {
        let found = find(Path::new(STAGED_DIR), "generic-shell").unwrap();
        let d = &found.definition;
        assert_eq!(d.adapter, "generic");
        assert_eq!(d.adapter_config.command, vec!["/bin/sh"]);
        assert!(d.adapter_config.signature.comm.is_empty());
        assert!(d.adapter_config.signature.exe_glob.is_empty());
        assert!(
            d.adapter_config.version_command.is_empty(),
            "no version probe declared"
        );
        // Matched by `name`, not filename: the file is generic.json.
        assert_eq!(
            found.source.file_name().unwrap().to_string_lossy(),
            "generic.json"
        );
    }

    #[test]
    fn mock_override_applies_only_when_requested() {
        let d = find(Path::new(STAGED_DIR), "claude-code")
            .unwrap()
            .definition;
        let real = d.launch_argv(false);
        assert_eq!(real.argv, vec!["claude"]);
        assert!(!real.mock);
        let mock = d.launch_argv(true);
        assert_eq!(mock.argv, vec!["/usr/lib/punar/punar-mock-agent"]);
        assert!(mock.mock);
    }

    /// An adapter with no mock command stays real even under the flag —
    /// the label must never appear over a real agent.
    #[test]
    fn mock_flag_without_a_mock_command_launches_the_real_command() {
        let d: AgentDefinition = serde_json::from_str(
            r#"{"name":"x","adapter":"generic","adapter_config":{"command":["/bin/true"]}}"#,
        )
        .unwrap();
        let chosen = d.launch_argv(true);
        assert_eq!(chosen.argv, vec!["/bin/true"]);
        assert!(!chosen.mock);
    }

    #[test]
    fn a_declared_agent_without_an_adapter_is_an_honest_error() {
        let err = find(Path::new(STAGED_DIR), "codex").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no gateway adapter is installed"), "{msg}");
        assert!(msg.contains("claude-code · generic-shell"), "{msg}");
        assert!(msg.contains("Next step"), "{msg}");
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn a_missing_adapter_directory_is_empty_not_a_crash() {
        let dir = std::env::temp_dir().join("punar-env-adapters-absent");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(load_all(&dir).unwrap().is_empty());
        let err = find(&dir, "claude-code").unwrap_err();
        assert!(err.to_string().contains("none are installed"), "{err}");
    }

    #[test]
    fn definitions_that_could_smuggle_a_shell_string_are_refused() {
        let dir =
            std::env::temp_dir().join(format!("punar-env-adapters-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Empty command: nothing to launch.
        std::fs::write(
            dir.join("a.json"),
            r#"{"name":"a","adapter":"generic","adapter_config":{"command":[]}}"#,
        )
        .unwrap();
        let err = load_all(&dir).unwrap_err();
        assert!(err.to_string().contains("non-empty argv array"), "{err}");

        // A name that would not survive the record schema or a unit name.
        std::fs::write(
            dir.join("a.json"),
            r#"{"name":"A; rm -rf /","adapter":"generic","adapter_config":{"command":["x"]}}"#,
        )
        .unwrap();
        let err = load_all(&dir).unwrap_err();
        assert!(err.to_string().contains("name 'A; rm -rf /'"), "{err}");

        // An unknown launch method is never guessed at.
        std::fs::write(
            dir.join("a.json"),
            r#"{"name":"a","adapter":"generic","launch":{"method":"exec","command":"x"},
                "adapter_config":{"command":["x"]}}"#,
        )
        .unwrap();
        let err = load_all(&dir).unwrap_err();
        assert!(err.to_string().contains("launch.method 'exec'"), "{err}");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unparseable_definitions_name_the_file() {
        let dir =
            std::env::temp_dir().join(format!("punar-env-adapters-junk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("broken.json"), "{not json").unwrap();
        let err = load_all(&dir).unwrap_err();
        assert!(err.to_string().contains("broken.json"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
