//! Role-based access control for the admin surface — **dev/CI fidelity,
//! not a real IdP** (milestone-10.md section 9.1).
//!
//! `fixtures/organizations/acme/admins.json` maps admin identities to roles
//! and roles to the closed [`QueryScope`] vocabulary. `admin.ai_query`
//! checks it *before* enqueuing, so an administrator without the role
//! cannot even ask — the cheapest possible refusal, and the query never
//! reaches a device.
//!
//! # The honest boundary, restated where it is implemented
//!
//! These identities are **fixture strings, not authenticated principals**.
//! There is no IdP, no SSO, no signature and no session. This check is
//! defence in depth and nothing more: the device re-evaluates authorization
//! from its own `enrollment.json` and refuses whatever that file does not
//! grant, regardless of anything decided here (SPEC section 59.4,
//! milestone-10.md section 9.2). Of the two checks, **the device's is the
//! one that decides**; this one only makes the org-side half of SPEC
//! section 24.1 ("RBAC applies") independently true.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use punar_common::query::{QueryScope, ScopeSet};
use serde_json::Value;

/// Roles and admins as read from the fixture. An **absent or unreadable**
/// fixture yields [`AdminDirectory::empty`], which knows nobody and permits
/// nothing: the admin surface then refuses every call naming the missing
/// file. Fail closed — a mock that grants everything when its role table is
/// missing would teach exactly the wrong lesson.
#[derive(Debug, Clone, Default)]
pub struct AdminDirectory {
    /// Where the table came from, for the startup log and refusal text.
    pub source: Option<PathBuf>,
    /// Values in the fixture this build has no name for, kept so startup
    /// can say so rather than silently ignoring them.
    pub unrecognised_scopes: Vec<String>,
    roles: BTreeMap<String, ScopeSet>,
    admins: BTreeMap<String, String>,
}

impl AdminDirectory {
    /// Knows nobody, permits nothing.
    pub fn empty() -> AdminDirectory {
        AdminDirectory::default()
    }

    /// Load `admins.json` from a fixture directory. A missing file is not
    /// an error: the M5 image predates this fixture, and the admin surface
    /// refuses with a message naming the file rather than failing startup
    /// for the five M5 methods that do not need it.
    pub fn load(dir: &Path) -> AdminDirectory {
        let path = dir.join(ADMINS_FILE);
        let Ok(bytes) = std::fs::read(&path) else {
            return AdminDirectory::empty();
        };
        let Ok(document) = serde_json::from_slice::<Value>(&bytes) else {
            eprintln!(
                "punar-mock-smplify: {} is not valid JSON — the admin surface will \
                 refuse every call (fail closed)",
                path.display()
            );
            return AdminDirectory::empty();
        };
        let mut roles = BTreeMap::new();
        let mut unrecognised_scopes = Vec::new();
        if let Some(map) = document.get("roles").and_then(Value::as_object) {
            for (role, scopes) in map {
                let (parsed, unknown) = ScopeSet::parse_json(Some(scopes));
                unrecognised_scopes.extend(unknown);
                roles.insert(role.clone(), parsed);
            }
        }
        let mut admins = BTreeMap::new();
        if let Some(map) = document.get("admins").and_then(Value::as_object) {
            for (admin, role) in map {
                if let Some(role) = role.as_str() {
                    admins.insert(admin.clone(), role.to_string());
                }
            }
        }
        AdminDirectory {
            source: Some(path),
            unrecognised_scopes,
            roles,
            admins,
        }
    }

    /// The role name this identity carries, if the fixture knows it.
    pub fn role_of(&self, admin: &str) -> Option<&str> {
        self.admins.get(admin).map(String::as_str)
    }

    /// The scopes this identity's role permits. Unknown admin ⇒ `None`
    /// (which is different from "a role that permits nothing").
    pub fn scopes_of(&self, admin: &str) -> Option<&ScopeSet> {
        self.roles.get(self.admins.get(admin)?)
    }

    /// Whether this identity's role permits asking at `scope`.
    pub fn permits(&self, admin: &str, scope: QueryScope) -> bool {
        self.scopes_of(admin).is_some_and(|s| s.contains(scope))
    }

    /// The fleet view is role-gated to `fleet_viewer` and above
    /// (milestone-10.md section 12.1). Expressed as a *scope* rather than
    /// as a role name so a fixture that renames roles cannot silently open
    /// the view: the gate is "a role that may ask about authority".
    pub fn permits_fleet(&self, admin: &str) -> bool {
        self.permits(admin, QueryScope::Authority)
    }

    /// Number of known identities (startup log).
    pub fn admin_count(&self) -> usize {
        self.admins.len()
    }

    /// Number of defined roles (startup log).
    pub fn role_count(&self) -> usize {
        self.roles.len()
    }

    /// Whether a role table was found at all.
    pub fn is_loaded(&self) -> bool {
        self.source.is_some()
    }
}

/// Fixture file name inside the organization directory.
pub const ADMINS_FILE: &str = "admins.json";

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_dir(tag: &str, body: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "punar-mock-rbac-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(ADMINS_FILE), body).unwrap();
        dir
    }

    const SHIPPED: &str = include_str!("../../../fixtures/organizations/acme/admins.json");

    #[test]
    fn the_shipped_fixture_carries_the_three_documented_roles() {
        let dir = fixture_dir("shipped", SHIPPED);
        let rbac = AdminDirectory::load(&dir);
        assert!(rbac.is_loaded());
        assert_eq!(rbac.role_count(), 3);
        assert_eq!(rbac.admin_count(), 3);
        assert!(rbac.unrecognised_scopes.is_empty());

        assert_eq!(rbac.role_of("helpdesk@acme.com"), Some("helpdesk"));
        assert_eq!(rbac.role_of("cio@acme.com"), Some("fleet_viewer"));
        assert_eq!(rbac.role_of("secops@acme.com"), Some("security_admin"));
        assert_eq!(rbac.role_of("nobody@acme.com"), None);

        // helpdesk → inventory only; the security_events probe of
        // milestone-10.md section 16 group 8 is refused by the mock.
        assert!(rbac.permits("helpdesk@acme.com", QueryScope::Inventory));
        assert!(!rbac.permits("helpdesk@acme.com", QueryScope::SecurityEvents));
        assert!(!rbac.permits("helpdesk@acme.com", QueryScope::Authority));

        assert!(rbac.permits("cio@acme.com", QueryScope::Authority));
        assert!(!rbac.permits("cio@acme.com", QueryScope::ResourceSummary));

        for scope in QueryScope::ALL {
            assert!(rbac.permits("secops@acme.com", scope));
        }

        // Fleet: fleet_viewer and above, never helpdesk.
        assert!(!rbac.permits_fleet("helpdesk@acme.com"));
        assert!(rbac.permits_fleet("cio@acme.com"));
        assert!(rbac.permits_fleet("secops@acme.com"));
        assert!(!rbac.permits_fleet("nobody@acme.com"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_absent_or_corrupt_table_knows_nobody_and_permits_nothing() {
        let empty_dir =
            std::env::temp_dir().join(format!("punar-mock-rbac-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&empty_dir);
        std::fs::create_dir_all(&empty_dir).unwrap();
        let absent = AdminDirectory::load(&empty_dir);
        assert!(!absent.is_loaded());
        assert!(!absent.permits("secops@acme.com", QueryScope::Inventory));
        assert!(!absent.permits_fleet("secops@acme.com"));
        std::fs::remove_dir_all(&empty_dir).unwrap();

        let dir = fixture_dir("corrupt", "{ not json");
        let corrupt = AdminDirectory::load(&dir);
        assert!(!corrupt.is_loaded());
        assert_eq!(corrupt.admin_count(), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_role_asking_for_an_unknown_scope_gets_only_the_scopes_that_exist() {
        let dir = fixture_dir(
            "unknown",
            r#"{"v":1,"roles":{"wizard":["inventory","telepathy"]},
                "admins":{"merlin@acme.com":"wizard"}}"#,
        );
        let rbac = AdminDirectory::load(&dir);
        assert_eq!(rbac.unrecognised_scopes, vec!["telepathy".to_string()]);
        assert!(rbac.permits("merlin@acme.com", QueryScope::Inventory));
        assert_eq!(
            rbac.scopes_of("merlin@acme.com").unwrap().as_words(),
            vec!["inventory"]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
