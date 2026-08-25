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

/// One **executable-provenance** rule — Milestone 10's single new
/// detection input (spec section 23; milestone-10.md section 3.5), and
/// like everything else here it is **data, not code**.
///
/// A match requires a path prefix that means *unmanaged* (`~/Downloads/`,
/// `/tmp/`, `~/.local/bin/`) **and** an agent-like token in the
/// executable's own name. `require: "both"` is the whole decision:
///
/// - path alone would classify every downloaded binary as suspected AI,
///   which is how a detection product becomes a thing users turn off;
/// - name alone is already M7's glob list.
///
/// Requiring both keeps the false-positive posture defensible and keeps
/// the rule reviewable by a human reading one JSON file.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ProvenanceRule {
    /// Stable id reported as the matched signature name.
    pub id: String,
    /// Path prefixes. `~/` means the **owning user's** home directory,
    /// resolved from `/etc/passwd` at match time — never a wildcard and
    /// never another user's home.
    #[serde(default)]
    pub unmanaged_path_prefixes: Vec<String>,
    /// Case-insensitive substrings looked for in the executable's own
    /// file name (never in its arguments — an argument vector can carry a
    /// prompt, and `crate::proc` never retains one).
    #[serde(default)]
    pub name_tokens: Vec<String>,
    /// Must be the literal `"both"`. Any other value — including a
    /// missing one — makes the rule **inert**, with a warning: a
    /// heuristic must never be widened by a typo or an omission.
    #[serde(default)]
    pub require: String,
    #[serde(default)]
    pub note: String,
}

/// The only accepted value of [`ProvenanceRule::require`].
pub const REQUIRE_BOTH: &str = "both";

impl ProvenanceRule {
    /// Whether this rule is well-formed enough to be applied at all.
    /// Fail-closed: an unusable rule matches nothing, rather than
    /// degrading into "either half is enough".
    pub fn is_armed(&self) -> Option<String> {
        if self.require != REQUIRE_BOTH {
            return Some(format!(
                "provenance rule {:?} declares require={:?}; only {REQUIRE_BOTH:?} is \
                 understood, so the rule is inert. Path provenance alone would flag every \
                 downloaded binary, and a name alone is already a suspected glob \
                 (milestone-10.md section 3.5).",
                self.id, self.require
            ));
        }
        if self.unmanaged_path_prefixes.is_empty() || self.name_tokens.is_empty() {
            return Some(format!(
                "provenance rule {:?} names no {} and is inert: \"both\" needs both halves.",
                self.id,
                if self.unmanaged_path_prefixes.is_empty() {
                    "unmanaged_path_prefixes"
                } else {
                    "name_tokens"
                }
            ));
        }
        None
    }

    /// Does this rule match `path`, for a process owned by a user whose
    /// home directory is `home`?
    ///
    /// Both halves, always — there is no code path through this function
    /// that returns `true` on one of them.
    pub fn matches_path(&self, path: &str, home: Option<&str>) -> bool {
        if self.is_armed().is_some() {
            return false;
        }
        let lower = path.to_ascii_lowercase();
        let prefix_ok = self.unmanaged_path_prefixes.iter().any(|prefix| {
            expand_home(prefix, home).is_some_and(|expanded| lower.starts_with(&expanded))
        });
        if !prefix_ok {
            return false;
        }
        let file_name = lower.rsplit('/').next().unwrap_or(&lower).to_string();
        self.name_tokens
            .iter()
            .any(|token| !token.is_empty() && file_name.contains(&token.to_ascii_lowercase()))
    }
}

/// Resolve a `~/`-rooted prefix against the owning user's home, lowercased
/// for the case-insensitive comparison. A `~/` prefix with **no** known
/// home resolves to nothing at all — never to `/`, which would make the
/// rule match the whole filesystem.
fn expand_home(prefix: &str, home: Option<&str>) -> Option<String> {
    match prefix.strip_prefix("~/") {
        Some(rest) => {
            let home = home?.trim_end_matches('/');
            (!home.is_empty()).then(|| format!("{home}/{rest}").to_ascii_lowercase())
        }
        None => Some(prefix.to_ascii_lowercase()),
    }
}

#[derive(Debug, Clone, Deserialize)]
struct SuspectedFile {
    #[serde(default)]
    v: u32,
    #[serde(default)]
    patterns: Vec<SuspectedPattern>,
    /// M10's provenance rules, in the same reviewable file.
    #[serde(default)]
    provenance: Vec<ProvenanceRule>,
}

/// Everything the detector was able to load, plus what it could not — the
/// warnings are printed once at startup rather than swallowed.
#[derive(Debug, Clone, Default)]
pub struct SignatureSet {
    pub adapters: Vec<AdapterDefinition>,
    pub suspected: Vec<SuspectedPattern>,
    /// M10's executable-provenance rules (milestone-10.md section 3.5).
    pub provenance: Vec<ProvenanceRule>,
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
                // A provenance rule that is not fully armed is loaded but
                // inert, and says so once at startup: silently dropping
                // it would hide a broken detection rule, and silently
                // widening it would be worse.
                for rule in &file.provenance {
                    if let Some(reason) = rule.is_armed() {
                        self.warnings.push(reason);
                    }
                }
                self.provenance = file.provenance;
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

    /// First **provenance** rule matching this process, with the matched
    /// path (milestone-10.md section 3.5).
    ///
    /// Tried *after* [`SignatureSet::match_suspected`] on purpose: a
    /// hand-written glob names a specific thing and is the better label
    /// for the alert card, while provenance is the general rule that
    /// catches what no glob names. Specific before general is also what
    /// keeps M7's shipped `signature_id` values stable for processes both
    /// rules would match.
    pub fn match_provenance(
        &self,
        entry: &crate::proc::ProcEntry,
        home: Option<&str>,
    ) -> Option<(&ProvenanceRule, String)> {
        for rule in &self.provenance {
            for path in entry.candidate_paths() {
                if rule.matches_path(path, home) {
                    return Some((rule, path.to_string()));
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
        // M10's provenance rule ships in the same file, as data.
        assert_eq!(set.provenance.len(), 1);
        assert_eq!(set.provenance[0].id, "unmanaged-path-agentlike");
        assert_eq!(set.provenance[0].require, REQUIRE_BOTH);
        assert_eq!(set.provenance[0].is_armed(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `require: "both"` is the decision, so the tests are written as
    /// "either half alone is **not** a signal" (milestone-10.md 3.5).
    #[test]
    fn provenance_needs_both_halves_and_never_either_alone() {
        let rule = ProvenanceRule {
            id: "unmanaged-path-agentlike".into(),
            unmanaged_path_prefixes: vec![
                "~/Downloads/".into(),
                "/tmp/".into(),
                "~/.local/bin/".into(),
            ],
            name_tokens: vec!["agent".into(), "-ai".into(), "llm".into(), "copilot".into()],
            require: REQUIRE_BOTH.into(),
            note: String::new(),
        };
        let home = Some("/home/punar");

        // Both halves.
        assert!(rule.matches_path("/home/punar/Downloads/foo-agent", home));
        assert!(rule.matches_path("/tmp/local-llm-runner", home));
        assert!(rule.matches_path("/home/punar/.local/bin/my-copilot", home));

        // Path alone: downloading a binary does not make you a suspect.
        assert!(!rule.matches_path("/home/punar/Downloads/tax-return.pdf", home));
        assert!(!rule.matches_path("/tmp/installer", home));
        // Name alone: an agent-named binary in a managed location is not
        // provenance evidence (a known-agent signature may still name it).
        assert!(!rule.matches_path("/usr/bin/some-agent", home));
        assert!(!rule.matches_path("/home/punar/src/agent-runner", home));

        // A `~/` prefix with no resolvable home matches nothing at all —
        // never `/`, which would flag the whole filesystem.
        assert!(!rule.matches_path("/home/punar/Downloads/foo-agent", None));
        assert!(
            rule.matches_path("/tmp/foo-agent", None),
            "an absolute prefix still works without a home"
        );
        // And never another user's home.
        assert!(!rule.matches_path("/home/other/Downloads/foo-agent", home));
    }

    #[test]
    fn an_unarmed_provenance_rule_is_inert_and_says_so() {
        let base = ProvenanceRule {
            id: "typo".into(),
            unmanaged_path_prefixes: vec!["/tmp/".into()],
            name_tokens: vec!["agent".into()],
            require: "either".into(),
            note: String::new(),
        };
        assert!(base.is_armed().is_some());
        assert!(
            !base.matches_path("/tmp/foo-agent", None),
            "an unrecognized `require` must never widen the rule"
        );

        let missing = ProvenanceRule {
            require: REQUIRE_BOTH.into(),
            name_tokens: Vec::new(),
            ..base.clone()
        };
        assert!(missing.is_armed().is_some());
        assert!(!missing.matches_path("/tmp/foo-agent", None));

        // And the loader reports it once rather than swallowing it.
        let dir = temp_dir("provenance-unarmed");
        let path = dir.join("suspected.json");
        std::fs::write(
            &path,
            r#"{"v":1,"patterns":[],"provenance":[
                 {"id":"typo","unmanaged_path_prefixes":["/tmp/"],
                  "name_tokens":["agent"],"require":"either"}]}"#,
        )
        .unwrap();
        let set = SignatureSet::load(&fixture_adapters(&dir), &path);
        assert_eq!(set.provenance.len(), 1);
        assert!(
            set.warnings.iter().any(|w| w.contains("inert")),
            "{:?}",
            set.warnings
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The shipped data file is the contract, so it is parsed here as
    /// well as by `m10-check`'s `jq`: a broken rule must fail in CI, not
    /// in the VM.
    #[test]
    fn the_shipped_signature_file_parses_and_arms_the_provenance_rule() {
        let path = std::path::Path::new(
            "../../os/images/mkosi.profiles/desktop/mkosi.extra/usr/share/punar/agents/\
             signatures/suspected.json",
        );
        if !path.exists() {
            // The crate is buildable outside the image tree; skip rather
            // than fail on a checkout that does not carry `os/`.
            return;
        }
        let dir = temp_dir("shipped-signatures");
        let set = SignatureSet::load(&fixture_adapters(&dir), path);
        assert!(
            set.warnings.is_empty(),
            "the shipped file must load clean: {:?}",
            set.warnings
        );
        let rule = set
            .provenance
            .iter()
            .find(|r| r.id == "unmanaged-path-agentlike")
            .expect("the M10 provenance rule ships");
        assert_eq!(rule.require, REQUIRE_BOTH);
        assert_eq!(rule.is_armed(), None);
        assert!(rule.matches_path("/home/punar/Downloads/foo-agent", Some("/home/punar")));
        assert!(!rule.matches_path("/home/punar/Downloads/holiday.jpg", Some("/home/punar")));
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
