//! Persistent daemon state — Milestone 4 layered stores and the device id
//! (docs/development/milestone-4.md section 3; docs/api/ipc.md section 5.1).
//!
//! The M3 single `desired.json` store is **gone** (`DesiredStore` deleted);
//! desired state now lives in layers merged through `punar-policy`:
//!
//! - OS defaults: compiled into the backends where fixed
//!   ([`crate::capability::Capability::default_desired`]) plus
//!   first-observation seeds persisted in `os-defaults.json` ([`OsDefaultsStore`])
//!   so open-valued defaults are stable across boots and drift stays
//!   meaningful;
//! - user preferences: `preferences.json` ([`PreferencesStore`]), written
//!   only by `capabilities.set`;
//! - org layers: `policy.d/` envelopes ([`crate::policy`] loads them; the
//!   directory is empty in the shipped image — design language section 8).
//!
//! Both stores are private daemon files (peer of `device-id`): 0600, atomic
//! writes, documented in milestone-4.md — deliberately not public schemas.
//! A one-shot [`migrate_m3_store`] moves an M3 `desired.json` into the
//! layers on the first M4 start (milestone-4.md section 3.3).

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::capability::Registry;
use crate::util::{random_alnum, write_atomic};

/// `preferences.json` / `os-defaults.json` format version.
const STORE_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// User preferences (rank 5 layer)
// ---------------------------------------------------------------------------

/// One recorded user preference (milestone-4.md section 3.1 shape).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PreferenceEntry {
    pub value: Value,
    /// RFC 3339, when the preference was recorded.
    pub set_at: String,
    /// Who set it: the audit `user_id` (`"root"`), or `"migrated"` for
    /// entries carried over from the M3 store.
    pub set_by: String,
}

#[derive(Serialize, Deserialize)]
struct PreferencesFile {
    version: u32,
    preferences: BTreeMap<String, PreferenceEntry>,
}

/// `/var/lib/punar/preferences.json` — the User Preference layer (SPEC
/// section 39 rank 5). Created lazily on the first `capabilities.set`;
/// 0600, atomically rewritten on every change.
pub struct PreferencesStore {
    path: PathBuf,
    map: Mutex<BTreeMap<String, PreferenceEntry>>,
}

impl PreferencesStore {
    /// Load the store, or start empty when the file does not exist yet
    /// (the file itself is created on the first [`PreferencesStore::set`]).
    /// A corrupt file is an error — silently discarding recorded
    /// preferences would be worse than refusing to start.
    pub fn load(path: &Path) -> io::Result<Self> {
        let map = match fs::read_to_string(path) {
            Ok(content) => {
                let file: PreferencesFile = serde_json::from_str(&content).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{} is corrupt: {e}", path.display()),
                    )
                })?;
                if file.version != STORE_VERSION {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{} has unsupported version {} (this daemon writes {STORE_VERSION})",
                            path.display(),
                            file.version
                        ),
                    ));
                }
                file.preferences
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e),
        };
        Ok(PreferencesStore {
            path: path.to_path_buf(),
            map: Mutex::new(map),
        })
    }

    pub fn get(&self, capability: &str) -> Option<PreferenceEntry> {
        self.map.lock().unwrap().get(capability).cloned()
    }

    /// All recorded preferences (path → entry).
    pub fn entries(&self) -> BTreeMap<String, PreferenceEntry> {
        self.map.lock().unwrap().clone()
    }

    /// Record a preference and persist the store (0600, atomic).
    pub fn set(&self, capability: &str, entry: PreferenceEntry) -> io::Result<()> {
        let mut map = self.map.lock().unwrap();
        map.insert(capability.to_string(), entry);
        persist_preferences(&self.path, &map)
    }
}

fn persist_preferences(path: &Path, map: &BTreeMap<String, PreferenceEntry>) -> io::Result<()> {
    let file = PreferencesFile {
        version: STORE_VERSION,
        preferences: map.clone(),
    };
    let bytes = serde_json::to_vec_pretty(&file).expect("preference maps serialize");
    write_atomic(path, &bytes, 0o600)
}

// ---------------------------------------------------------------------------
// Persisted OS-default seeds (rank 6 layer, observation-seeded part)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct OsDefaultsFile {
    version: u32,
    defaults: BTreeMap<String, Value>,
}

/// `/var/lib/punar/os-defaults.json` — first-observation seeds for
/// capabilities whose OS default is not compiled in (open value spaces:
/// `system.hostname`, `time.timezone`). Persisting the seed keeps the OS
/// default stable across boots, so drift against it stays meaningful
/// (milestone-4.md section 3.1). 0600, atomic.
pub struct OsDefaultsStore {
    path: PathBuf,
    map: Mutex<BTreeMap<String, Value>>,
}

impl OsDefaultsStore {
    /// Load the store, or start empty when the file does not exist yet.
    pub fn load(path: &Path) -> io::Result<Self> {
        let map = match fs::read_to_string(path) {
            Ok(content) => {
                let file: OsDefaultsFile = serde_json::from_str(&content).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{} is corrupt: {e}", path.display()),
                    )
                })?;
                if file.version != STORE_VERSION {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{} has unsupported version {} (this daemon writes {STORE_VERSION})",
                            path.display(),
                            file.version
                        ),
                    ));
                }
                file.defaults
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e),
        };
        Ok(OsDefaultsStore {
            path: path.to_path_buf(),
            map: Mutex::new(map),
        })
    }

    pub fn get(&self, capability: &str) -> Option<Value> {
        self.map.lock().unwrap().get(capability).cloned()
    }

    /// Seed a default without overwriting an existing entry; persists only
    /// when something was actually added. Used at startup and by migration.
    pub fn seed(&self, capability: &str, default: Value) -> io::Result<bool> {
        let mut map = self.map.lock().unwrap();
        if map.contains_key(capability) {
            return Ok(false);
        }
        map.insert(capability.to_string(), default);
        let file = OsDefaultsFile {
            version: STORE_VERSION,
            defaults: map.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&file).expect("default maps serialize");
        write_atomic(&self.path, &bytes, 0o600)?;
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// One-shot migration of the M3 desired.json (milestone-4.md section 3.3)
// ---------------------------------------------------------------------------

/// What [`migrate_m3_store`] did, for logging and the `state.migrate`
/// audit event.
#[derive(Debug, Default, PartialEq)]
pub struct MigrationOutcome {
    /// Capabilities whose recorded value differed from the compiled OS
    /// default → carried as UserPreference entries (`set_by: "migrated"`).
    pub migrated_preferences: Vec<String>,
    /// Observation-seeded capabilities (no compiled default) → recorded
    /// values became persisted OS-default seeds. Documented tradeoff:
    /// unknowable provenance defaults DOWN the ladder — a genuinely
    /// user-set value explains as "OS default" after migration; the
    /// effective value is identical, only the provenance label is
    /// conservative (the alternative would fabricate a user action).
    pub seeded_defaults: Vec<String>,
    /// Values equal to the compiled OS default → dropped (the OS-default
    /// layer regenerates them).
    pub dropped: Vec<String>,
    /// Recorded ids with no registered capability → left behind in the
    /// renamed file, never re-read.
    pub ignored_unknown: Vec<String>,
}

/// Migrate the M3 `desired.json` into the layered stores, once.
///
/// Trigger (checked by the caller deciding whether the preferences file
/// exists yet, and here again defensively): `preferences.json` absent AND
/// `desired.json` present. On completion `desired.json` is renamed to
/// `desired.json.pre-m4` and never read again, so the trigger cannot
/// re-fire. Returns `Ok(None)` when there is nothing to migrate — every
/// fresh install (and every CI image boot) takes that path, which is why
/// migration is covered by host `cargo test` only (milestone-4.md 10.3).
pub fn migrate_m3_store(
    state_dir: &Path,
    registry: &Registry,
    preferences: &PreferencesStore,
    os_defaults: &OsDefaultsStore,
    now_rfc3339: &str,
) -> io::Result<Option<MigrationOutcome>> {
    let desired_path = state_dir.join("desired.json");
    let preferences_path = state_dir.join("preferences.json");
    if preferences_path.exists() || !desired_path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&desired_path)?;
    let recorded: BTreeMap<String, Value> = serde_json::from_str(&content).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is corrupt: {e}", desired_path.display()),
        )
    })?;

    let mut outcome = MigrationOutcome::default();
    for (id, value) in recorded {
        let Some(cap) = registry.get(&id) else {
            outcome.ignored_unknown.push(id);
            continue;
        };
        match cap.default_desired() {
            // Fixed compiled default (security.firewall): a differing value
            // can only have come from a root `capabilities.set` — a user
            // action — so it becomes a User Preference.
            Some(compiled) if compiled == value => outcome.dropped.push(id),
            Some(_) => {
                preferences.set(
                    &id,
                    PreferenceEntry {
                        value,
                        set_at: now_rfc3339.to_string(),
                        set_by: "migrated".to_string(),
                    },
                )?;
                outcome.migrated_preferences.push(id);
            }
            // Observation-seeded capability: seed vs. set is unknowable in
            // the M3 store — default DOWN the ladder (doc on
            // `seeded_defaults`).
            None => {
                os_defaults.seed(&id, value)?;
                outcome.seeded_defaults.push(id);
            }
        }
    }

    fs::rename(&desired_path, state_dir.join("desired.json.pre-m4"))?;
    Ok(Some(outcome))
}

// ---------------------------------------------------------------------------
// Device id (unchanged from M3)
// ---------------------------------------------------------------------------

/// Load `/var/lib/punar/device-id` or create it on first start:
/// `dev_` + 10 random alphanumerics, mode 0600 (spec section 11.1 "device
/// identity", first slice).
pub fn load_or_create_device_id(path: &Path) -> io::Result<String> {
    match fs::read_to_string(path) {
        Ok(content) => {
            let id = content.trim().to_string();
            if is_valid_device_id(&id) {
                return Ok(id);
            }
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} does not contain a valid device id", path.display()),
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let id = format!("dev_{}", random_alnum(10)?);
            write_atomic(path, format!("{id}\n").as_bytes(), 0o600)?;
            Ok(id)
        }
        Err(e) => Err(e),
    }
}

fn is_valid_device_id(id: &str) -> bool {
    id.strip_prefix("dev_")
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric()))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::capability::mock::MockCapability;

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("punard-state-{tag}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn entry(value: &str, set_by: &str) -> PreferenceEntry {
        PreferenceEntry {
            value: json!(value),
            set_at: "2026-08-25T09:14:02Z".to_string(),
            set_by: set_by.to_string(),
        }
    }

    #[test]
    fn preferences_store_persists_and_reloads() {
        let dir = tmp("prefs");
        let path = dir.join("preferences.json");
        let store = PreferencesStore::load(&path).unwrap();
        assert_eq!(store.get("security.firewall"), None);
        assert!(!path.exists(), "created lazily on first set");
        store
            .set("security.firewall", entry("enabled", "root"))
            .unwrap();
        assert!(path.exists());

        let reloaded = PreferencesStore::load(&path).unwrap();
        let got = reloaded.get("security.firewall").unwrap();
        assert_eq!(got.value, json!("enabled"));
        assert_eq!(got.set_by, "root");

        // The documented file shape (milestone-4.md section 3.1).
        let raw: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(raw["version"], 1);
        assert_eq!(raw["preferences"]["security.firewall"]["value"], "enabled");
        assert_eq!(raw["preferences"]["security.firewall"]["set_by"], "root");
        assert!(raw["preferences"]["security.firewall"]["set_at"].is_string());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_or_wrong_version_preferences_refuse_to_load() {
        let dir = tmp("prefs-bad");
        let path = dir.join("preferences.json");
        fs::write(&path, "{oops").unwrap();
        assert!(PreferencesStore::load(&path).is_err());
        fs::write(&path, r#"{"version": 99, "preferences": {}}"#).unwrap();
        assert!(PreferencesStore::load(&path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn os_defaults_seed_does_not_overwrite() {
        let dir = tmp("osdef");
        let path = dir.join("os-defaults.json");
        let store = OsDefaultsStore::load(&path).unwrap();
        assert!(store.seed("time.timezone", json!("UTC")).unwrap());
        assert!(!store.seed("time.timezone", json!("Europe/Berlin")).unwrap());
        assert_eq!(store.get("time.timezone"), Some(json!("UTC")));

        let reloaded = OsDefaultsStore::load(&path).unwrap();
        assert_eq!(reloaded.get("time.timezone"), Some(json!("UTC")));
        let _ = fs::remove_dir_all(&dir);
    }

    fn migration_registry() -> Registry {
        // `mock.fixed` models security.firewall (compiled default);
        // `mock.seeded` models hostname/timezone (observation-seeded).
        Registry::new(vec![
            Box::new(MockCapability::with_default(
                "mock.fixed",
                json!("enabled"),
                json!("enabled"),
            )),
            Box::new(MockCapability::new("mock.seeded", json!("observed"))),
        ])
    }

    #[test]
    fn migration_splits_the_m3_store_by_provenance_rule() {
        let dir = tmp("migrate");
        fs::write(
            dir.join("desired.json"),
            serde_json::to_string(&json!({
                "mock.fixed": "disabled",      // differs from compiled default
                "mock.seeded": "recorded",     // unknowable → down the ladder
                "mock.gone": "whatever"        // no registered capability
            }))
            .unwrap(),
        )
        .unwrap();
        let registry = migration_registry();
        let preferences = PreferencesStore::load(&dir.join("preferences.json")).unwrap();
        let os_defaults = OsDefaultsStore::load(&dir.join("os-defaults.json")).unwrap();

        let outcome = migrate_m3_store(
            &dir,
            &registry,
            &preferences,
            &os_defaults,
            "2026-08-25T09:14:02Z",
        )
        .unwrap()
        .expect("migration must run");

        assert_eq!(outcome.migrated_preferences, ["mock.fixed"]);
        assert_eq!(outcome.seeded_defaults, ["mock.seeded"]);
        assert!(outcome.dropped.is_empty());
        assert_eq!(outcome.ignored_unknown, ["mock.gone"]);

        let migrated = preferences.get("mock.fixed").unwrap();
        assert_eq!(migrated.value, json!("disabled"));
        assert_eq!(migrated.set_by, "migrated");
        assert_eq!(os_defaults.get("mock.seeded"), Some(json!("recorded")));

        // The M3 store is renamed, kept, and never re-read.
        assert!(!dir.join("desired.json").exists());
        assert!(dir.join("desired.json.pre-m4").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn migration_drops_values_equal_to_the_compiled_default() {
        let dir = tmp("migrate-drop");
        fs::write(dir.join("desired.json"), r#"{"mock.fixed": "enabled"}"#).unwrap();
        let registry = migration_registry();
        let preferences = PreferencesStore::load(&dir.join("preferences.json")).unwrap();
        let os_defaults = OsDefaultsStore::load(&dir.join("os-defaults.json")).unwrap();

        let outcome = migrate_m3_store(
            &dir,
            &registry,
            &preferences,
            &os_defaults,
            "2026-08-25T09:14:02Z",
        )
        .unwrap()
        .unwrap();
        assert_eq!(outcome.dropped, ["mock.fixed"]);
        assert!(outcome.migrated_preferences.is_empty());
        assert_eq!(preferences.get("mock.fixed"), None);
        assert!(!dir.join("preferences.json").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn migration_is_one_shot_and_skipped_on_fresh_installs() {
        let dir = tmp("migrate-skip");
        let registry = migration_registry();
        let preferences = PreferencesStore::load(&dir.join("preferences.json")).unwrap();
        let os_defaults = OsDefaultsStore::load(&dir.join("os-defaults.json")).unwrap();

        // Fresh install: no desired.json → nothing to migrate.
        let outcome = migrate_m3_store(&dir, &registry, &preferences, &os_defaults, "now").unwrap();
        assert_eq!(outcome, None);

        // Existing preferences.json blocks migration even if a stray
        // desired.json appears (one-shot trigger).
        preferences
            .set("mock.fixed", entry("disabled", "root"))
            .unwrap();
        fs::write(dir.join("desired.json"), r#"{"mock.fixed": "enabled"}"#).unwrap();
        let outcome = migrate_m3_store(&dir, &registry, &preferences, &os_defaults, "now").unwrap();
        assert_eq!(outcome, None);
        assert!(dir.join("desired.json").exists(), "left untouched");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_m3_store_refuses_migration() {
        let dir = tmp("migrate-corrupt");
        fs::write(dir.join("desired.json"), "{oops").unwrap();
        let registry = migration_registry();
        let preferences = PreferencesStore::load(&dir.join("preferences.json")).unwrap();
        let os_defaults = OsDefaultsStore::load(&dir.join("os-defaults.json")).unwrap();
        assert!(
            migrate_m3_store(&dir, &registry, &preferences, &os_defaults, "now").is_err(),
            "a corrupt store refuses to start, same posture as M3"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_id_is_created_once_and_stable() {
        let dir = tmp("devid");
        let path = dir.join("device-id");
        let first = load_or_create_device_id(&path).unwrap();
        assert!(is_valid_device_id(&first));
        assert_eq!(first.len(), 4 + 10);
        let second = load_or_create_device_id(&path).unwrap();
        assert_eq!(first, second);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_persisted_device_id_is_an_error() {
        let dir = tmp("devid-bad");
        let path = dir.join("device-id");
        fs::write(&path, "not-a-device-id\n").unwrap();
        assert!(load_or_create_device_id(&path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
