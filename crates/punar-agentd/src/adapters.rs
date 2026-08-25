//! Adapters and heuristic signatures — **as data**, not code (spec section
//! 26: "adapters should be modular"; milestone-7.md sections 5.4 and 7.1).
//!
//! Two inputs, both read at startup and never written:
//!
//! - `/usr/share/punar/agents/adapters/*.json` — one
//!   `schemas/ai-agent/agent-definition.json`-valid document per known
//!   agent. Everything the runtime needs beyond `name`/`adapter` lives in
//!   the schema's explicitly extensible `adapter_config`, so adding an
//!   adapter changes no schema and no Rust. `punar-agentd` reads only
//!   `name` and `adapter_config.signature`; the launch keys are
//!   `punar-env`'s business.
//! - `/usr/share/punar/agents/signatures/suspected.json` — the suspected
//!   glob patterns (spec section 23). Deliberately *not* a schema: it is an
//!   internal heuristic input, versioned by review.
//!
//! Both loaders degrade honestly: an unreadable directory or a malformed
//! document is reported as a warning and skipped, never fatal and never
//! silently treated as "nothing suspicious exists". A daemon that refuses
//! to start because one adapter file has a typo would take the whole
//! registry down with it.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Signature of a *known* agent product: how its processes look from
/// outside the managed runtime. A match outside a managed scope is the
/// `observed` classification (spec section 19.1).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct Signature {
    /// Exact `/proc/<pid>/comm` names.
    #[serde(default)]
    pub comm: Vec<String>,
    /// Glob patterns matched against the executable and its absolute
    /// arguments (`*` matches any run of characters, `/` included).
    #[serde(default)]
    pub exe_glob: Vec<String>,
}

impl Signature {
    /// Whether this signature says anything at all. The generic
    /// shell adapter ships empty arrays on purpose — a plain `/bin/sh`
    /// must never be flagged as an AI agent by comm matching.
    pub fn is_empty(&self) -> bool {
        self.comm.is_empty() && self.exe_glob.is_empty()
    }
}

/// The subset of `adapter_config` this daemon reads. Unknown keys are
/// ignored by design: the schema declares the object extensible, and other
/// components (the launcher) own the rest of it.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AdapterConfig {
    #[serde(default)]
    pub signature: Signature,
}

/// An `agent-definition.json` document as the registry reads it.
#[derive(Debug, Clone, Deserialize)]
pub struct AdapterDefinition {
    pub name: String,
    pub adapter: String,
    #[serde(default)]
    pub adapter_config: AdapterConfig,
}

impl AdapterDefinition {
    /// Does any known-agent signature match this process?
    ///
    /// Returns the matched path (for `comm` matches, the process's display
    /// path), which is the only piece of the process's command line that is
    /// ever retained (`crate::proc` module note).
    pub fn matches(&self, entry: &crate::proc::ProcEntry) -> Option<String> {
        let signature = &self.adapter_config.signature;
        if signature.is_empty() {
            return None;
        }
        if signature.comm.contains(&entry.comm) {
            return Some(entry.display_path());
        }
        for path in entry.candidate_paths() {
            if signature
                .exe_glob
                .iter()
                .any(|pattern| glob_match(pattern, path))
            {
                return Some(path.to_string());
            }
        }
        None
    }
}

/// One suspected-signature pattern (spec section 23 — *suspected*, never
/// certain).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SuspectedPattern {
    /// Stable id reported as `signature_id` on the detection row.
    pub id: String,
    /// Glob matched against the executable and its absolute arguments.
    pub exe_glob: String,
    /// Human note explaining why this pattern exists (never displayed as
    /// an accusation; it documents the heuristic for reviewers).
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SuspectedFile {
    #[serde(default)]
    v: u32,
    #[serde(default)]
    patterns: Vec<SuspectedPattern>,
}

/// Everything the detector was able to load, plus what it could not — the
/// warnings are printed once at startup rather than swallowed.
#[derive(Debug, Clone, Default)]
pub struct SignatureSet {
    pub adapters: Vec<AdapterDefinition>,
    pub suspected: Vec<SuspectedPattern>,
    pub warnings: Vec<String>,
}

impl SignatureSet {
    /// Load the staged adapter directory and the suspected-pattern file.
    pub fn load(adapters_dir: &Path, suspected_path: &Path) -> SignatureSet {
        let mut set = SignatureSet::default();
        set.load_adapters(adapters_dir);
        set.load_suspected(suspected_path);
        set
    }

    fn load_adapters(&mut self, dir: &Path) {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => {
                self.warnings.push(format!(
                    "adapter directory {} is unreadable ({e}); no known-agent \
                     signatures are loaded, so nothing can be classified \
                     'observed' this boot",
                    dir.display()
                ));
                return;
            }
        };
        let mut paths: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .collect();
        paths.sort();
        for path in paths {
            match std::fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|text| {
                    serde_json::from_str::<AdapterDefinition>(&text).map_err(|e| e.to_string())
                }) {
                Ok(definition) => self.adapters.push(definition),
                Err(reason) => self.warnings.push(format!(
                    "adapter definition {} was skipped: {reason}",
                    path.display()
                )),
            }
        }
    }

    fn load_suspected(&mut self, path: &Path) {
        match std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|text| {
                serde_json::from_str::<SuspectedFile>(&text).map_err(|e| e.to_string())
            }) {
            Ok(file) => {
                if file.v != 1 {
                    self.warnings.push(format!(
                        "suspected-signature file {} declares version {} (this build \
                         understands 1); its patterns are still applied as written",
                        path.display(),
                        file.v
                    ));
                }
                self.suspected = file.patterns;
            }
            Err(reason) => self.warnings.push(format!(
                "suspected-signature file {} was not loaded: {reason}; detection \
                 falls back to known-agent signatures only",
                path.display()
            )),
        }
    }

    /// First known-agent adapter matching this process, with the matched
    /// path.
    pub fn match_known(
        &self,
        entry: &crate::proc::ProcEntry,
    ) -> Option<(&AdapterDefinition, String)> {
        self.adapters
            .iter()
            .find_map(|adapter| adapter.matches(entry).map(|path| (adapter, path)))
    }

    /// First suspected pattern matching this process, with the matched
    /// path.
    pub fn match_suspected(
        &self,
        entry: &crate::proc::ProcEntry,
    ) -> Option<(&SuspectedPattern, String)> {
        for pattern in &self.suspected {
            for path in entry.candidate_paths() {
                if glob_match(&pattern.exe_glob, path) {
                    return Some((pattern, path.to_string()));
                }
            }
        }
        None
    }
}

/// Shell-style glob match where `*` matches any run of characters —
/// **including `/`** — and `?` matches exactly one. Patterns like
/// `*/Downloads/*-agent` are meant to span directories, so the usual
/// path-segment restriction would defeat them.
///
/// Iterative with backtracking: linear in the common case, and bounded
/// regardless of input (no recursion, no catastrophic blowup).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0usize, 0usize);
    // Where to resume if the current `*` guess fails.
    let mut star: Option<usize> = None;
    let mut star_text = 0usize;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            star_text = t;
            p += 1;
        } else if let Some(star_p) = star {
            // Let the last `*` swallow one more character.
            p = star_p + 1;
            star_text += 1;
            t = star_text;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proc::ProcRoot;
    use crate::testsupport::{
        fake_process, fixture_adapters, fixture_proc, fixture_suspected, temp_dir,
    };

    #[test]
    fn glob_matches_across_directory_separators() {
        assert!(glob_match(
            "*/Downloads/foo-agent",
            "/home/punar/Downloads/foo-agent"
        ));
        assert!(glob_match(
            "*/Downloads/*-agent",
            "/home/punar/Downloads/helper-agent"
        ));
        assert!(glob_match("*/claude", "/usr/bin/claude"));
        assert!(glob_match("*", "/anything"));
        assert!(glob_match("/bin/sh", "/bin/sh"));
        assert!(glob_match("/bin/s?", "/bin/sh"));

        assert!(!glob_match(
            "*/Downloads/foo-agent",
            "/home/punar/Documents/foo-agent"
        ));
        assert!(!glob_match("*/claude", "/usr/bin/claude-helper"));
        assert!(!glob_match("/bin/sh", "/bin/bash"));
        assert!(!glob_match("/bin/s?", "/bin/dash"));
        // No catastrophic backtracking on a pathological pattern.
        assert!(!glob_match("*a*a*a*a*b", &"a".repeat(64)));
    }

    #[test]
    fn loads_the_two_shipped_adapters_and_the_suspected_patterns() {
        let dir = temp_dir("signatures");
        let adapters = fixture_adapters(&dir);
        let suspected = fixture_suspected(&dir);
        let set = SignatureSet::load(&adapters, &suspected);
        assert!(set.warnings.is_empty(), "{:?}", set.warnings);
        let names: Vec<&str> = set.adapters.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["claude-code", "generic-shell"]);
        assert_eq!(set.suspected.len(), 2);
        assert_eq!(set.suspected[0].id, "downloads-foo-agent");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_inputs_warn_instead_of_pretending_nothing_is_suspicious() {
        let dir = temp_dir("signatures-missing");
        let set = SignatureSet::load(&dir.join("absent"), &dir.join("absent.json"));
        assert!(set.adapters.is_empty());
        assert!(set.suspected.is_empty());
        assert_eq!(set.warnings.len(), 2, "{:?}", set.warnings);
        assert!(set.warnings.iter().any(|w| w.contains("observed")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_adapter_is_skipped_not_fatal() {
        let dir = temp_dir("signatures-broken");
        let adapters = fixture_adapters(&dir);
        std::fs::write(adapters.join("broken.json"), "{ not json").unwrap();
        let set = SignatureSet::load(&adapters, &fixture_suspected(&dir));
        assert_eq!(set.adapters.len(), 2, "the good adapters still load");
        assert_eq!(set.warnings.len(), 1);
        assert!(set.warnings[0].contains("broken.json"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn known_signatures_match_comm_and_glob_but_never_a_plain_shell() {
        let dir = temp_dir("signature-match");
        let set = SignatureSet::load(&fixture_adapters(&dir), &fixture_suspected(&dir));
        let root = fixture_proc("signature-match");
        fake_process(
            &root,
            11,
            "claude",
            "/usr/bin/claude",
            &["/usr/bin/claude"],
            1000,
            "/user.slice",
        );
        fake_process(
            &root,
            12,
            "sh",
            "/bin/sh",
            &["/bin/sh"],
            1000,
            "/user.slice",
        );
        fake_process(
            &root,
            13,
            "foo-agent",
            "/usr/bin/dash",
            &["/bin/sh", "/home/punar/Downloads/foo-agent"],
            1000,
            "/user.slice",
        );
        let proc = ProcRoot::new(&root);

        let (adapter, path) = set.match_known(&proc.entry(11).unwrap()).unwrap();
        assert_eq!(adapter.name, "claude-code");
        assert_eq!(path, "/usr/bin/claude");

        // The generic adapter's empty signature must not claim /bin/sh.
        assert!(set.match_known(&proc.entry(12).unwrap()).is_none());
        assert!(set.match_suspected(&proc.entry(12).unwrap()).is_none());

        // A script's identity lives in its arguments, not its exe link.
        let (pattern, path) = set.match_suspected(&proc.entry(13).unwrap()).unwrap();
        assert_eq!(pattern.id, "downloads-foo-agent");
        assert_eq!(path, "/home/punar/Downloads/foo-agent");

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
