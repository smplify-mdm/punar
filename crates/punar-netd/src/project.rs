//! Locate and compile the two user-authored network documents for a session.
//!
//! The registry carries a username and project id, not a caller-supplied
//! path. The home directory comes from the trusted local passwd database;
//! both path components are validated before joining. Any read or parse
//! failure yields an explicit all-deny fallback for that session.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::model::{Decision, ZoneDefinition, validate_project_id};
use crate::policy::{
    BoundBy, CompiledProject, ContainerNetwork, EffectiveRule, PolicyError, compile_project,
};
use crate::view::ManagedSession;

pub const MANIFEST_FILE: &str = "project-environment.yaml";
pub const POLICY_FILE: &str = "project-network-policy.json";

#[derive(Debug, Error)]
pub enum ProjectError {
    #[error("passwd database could not be read: {0}")]
    Passwd(io::Error),
    #[error("no local home directory is recorded for user {0:?}")]
    UnknownUser(String),
    #[error("home directory for user {user:?} is not a safe absolute path: {home:?}")]
    UnsafeHome { user: String, home: String },
    #[error("project file {path:?} could not be read: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

#[derive(Debug, Clone)]
pub struct ProjectLocator {
    passwd_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct LoadedProject {
    pub manifest_path: PathBuf,
    pub policy_path: PathBuf,
    pub compiled: CompiledProject,
}

impl ProjectLocator {
    pub fn production() -> Self {
        Self {
            passwd_file: PathBuf::from("/etc/passwd"),
        }
    }

    pub fn new(passwd_file: PathBuf) -> Self {
        Self { passwd_file }
    }

    pub fn locate(&self, session: &ManagedSession) -> Result<(PathBuf, PathBuf), ProjectError> {
        validate_project_id(&session.project_id).map_err(PolicyError::from)?;
        let passwd = fs::read_to_string(&self.passwd_file).map_err(ProjectError::Passwd)?;
        let home = home_for_user(&passwd, &session.user)
            .ok_or_else(|| ProjectError::UnknownUser(session.user.clone()))?;
        validate_home(&session.user, home)?;
        let root = Path::new(home).join(&session.project_id);
        Ok((root.join(MANIFEST_FILE), root.join(POLICY_FILE)))
    }

    pub fn load(
        &self,
        session: &ManagedSession,
        zones: &BTreeMap<String, ZoneDefinition>,
    ) -> Result<LoadedProject, ProjectError> {
        let (manifest_path, policy_path) = self.locate(session)?;
        let manifest = read_project_file(&manifest_path)?;
        let policy = read_project_file(&policy_path)?;
        let compiled = compile_project(&manifest, &policy, zones)?;
        Ok(LoadedProject {
            manifest_path,
            policy_path,
            compiled,
        })
    }
}

pub fn deny_all(project_id: &str, zones: &BTreeMap<String, ZoneDefinition>) -> CompiledProject {
    CompiledProject {
        project_id: project_id.to_string(),
        rules: zones
            .keys()
            .map(|zone| EffectiveRule {
                zone: zone.clone(),
                decision: Decision::Deny,
                bound_by: BoundBy::Residual,
                manifest_decision: None,
                policy_decision: None,
            })
            .collect(),
        container_network: ContainerNetwork {
            mode: "none".into(),
            reason: "deny_by_construction".into(),
        },
    }
}

fn read_project_file(path: &Path) -> Result<String, ProjectError> {
    fs::read_to_string(path).map_err(|source| ProjectError::Read {
        path: path.to_path_buf(),
        source,
    })
}

fn home_for_user<'a>(passwd: &'a str, user: &str) -> Option<&'a str> {
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == user).then(|| fields.nth(4)).flatten()
    })
}

fn validate_home(user: &str, home: &str) -> Result<(), ProjectError> {
    let path = Path::new(home);
    if !path.is_absolute()
        || path == Path::new("/")
        || home.contains('\0')
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(ProjectError::UnsafeHome {
            user: user.to_string(),
            home: home.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::model::ZoneKind;
    use crate::policy::index_zones;

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "punar-netd-project-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn session(root: &Path) -> (ManagedSession, PathBuf) {
        let passwd = root.join("passwd");
        fs::write(
            &passwd,
            format!("punar:x:1000:1000:Punar:{}:/bin/bash\n", root.display()),
        )
        .unwrap();
        (
            ManagedSession {
                session_id: "agt_1".into(),
                project_id: "atlas".into(),
                user: "punar".into(),
                process_id: 42,
                cgroup_path: "/user.slice/punar-agent-agt_1.scope".into(),
            },
            passwd,
        )
    }

    fn zones() -> BTreeMap<String, ZoneDefinition> {
        index_zones(vec![ZoneDefinition {
            name: "internet".into(),
            display_name: Some("Internet".into()),
            description: None,
            kind: ZoneKind::Internet,
            relay_mode: None,
        }])
        .unwrap()
    }

    #[test]
    fn passwd_home_and_validated_identifiers_define_the_only_paths() {
        let root = root();
        let (session, passwd) = session(&root);
        let (manifest, policy) = ProjectLocator::new(passwd).locate(&session).unwrap();
        assert_eq!(manifest, root.join("atlas/project-environment.yaml"));
        assert_eq!(policy, root.join("atlas/project-network-policy.json"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn load_compiles_both_documents_and_missing_input_has_deny_fallback() {
        let root = root();
        let (session, passwd) = session(&root);
        fs::create_dir_all(root.join("atlas")).unwrap();
        fs::write(
            root.join("atlas/project-environment.yaml"),
            "project: { name: atlas }\npermissions:\n  network:\n    internet: allow\n",
        )
        .unwrap();
        fs::write(
            root.join("atlas/project-network-policy.json"),
            r#"{"project_id":"atlas","rules":[{"zone":"internet","decision":"deny"}]}"#,
        )
        .unwrap();
        let loaded = ProjectLocator::new(passwd)
            .load(&session, &zones())
            .unwrap();
        assert_eq!(
            loaded.compiled.rule("internet").unwrap().decision,
            Decision::Deny
        );
        let fallback = deny_all("atlas", &zones());
        assert!(
            fallback
                .rules
                .iter()
                .all(|rule| rule.decision == Decision::Deny)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsafe_or_unknown_homes_are_refused() {
        let root = root();
        let (session, passwd) = session(&root);
        fs::write(&passwd, "punar:x:1000:1000:Punar:/:/bin/bash\n").unwrap();
        assert!(matches!(
            ProjectLocator::new(passwd.clone()).locate(&session),
            Err(ProjectError::UnsafeHome { .. })
        ));
        fs::write(&passwd, "other:x:1001:1001:Other:/home/other:/bin/bash\n").unwrap();
        assert!(matches!(
            ProjectLocator::new(passwd).locate(&session),
            Err(ProjectError::UnknownUser(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }
}
