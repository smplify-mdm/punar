//! The typed capability contract (SPEC sections 10, 41) and the registry.
//!
//! Every privileged change flows through a [`Capability`] implementation —
//! observe / apply / verify with a schema-conformant descriptor. There is no
//! other mutation path in the daemon.
//!
//! INTERFACE NOTE (for the M3 integrate agent): [`Descriptor`] serializes to
//! the `schemas/capability/capability-descriptor.json` shape verbatim. If
//! the concurrent `punar-common` work lands a shared descriptor struct (for
//! `punarctl`'s typed rendering), replace this one with it — the field set
//! and names here are the schema's, so the swap should be mechanical.

use std::fmt;

use punar_common::CapabilityId;
use serde::Serialize;
use serde_json::Value;

/// Backend failure (observe/apply/verify). Message text is operator-facing
/// and must never contain secret values (SPEC section 53; no M3 backend
/// handles secrets).
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct BackendError(pub String);

impl BackendError {
    pub fn new(msg: impl Into<String>) -> Self {
        BackendError(msg.into())
    }
}

/// Static (state-independent) part of a capability's descriptor.
#[derive(Debug, Clone)]
pub struct DescriptorMeta {
    pub capability: CapabilityId,
    pub risk: &'static str,
    pub verification: &'static str,
    pub audit_category: &'static str,
    pub state_schema: Option<Value>,
    pub allowed_desired_states: Option<Vec<Value>>,
}

/// A full capability-registry descriptor, serializing exactly per
/// `schemas/capability/capability-descriptor.json`.
///
/// M3 constants (docs/development/milestone-3.md section 4): every shipped
/// capability is supported, mutable, reboot-free, locally managed
/// (personal mode), root-gated, and approval-free.
#[derive(Debug, Clone, Serialize)]
pub struct Descriptor {
    pub capability: String,
    pub supported: bool,
    pub current_state: Value,
    pub desired_state: Value,
    pub mutable: bool,
    pub requires_reboot: bool,
    pub risk: String,
    pub managed_by: String,
    pub verification: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_schema: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_desired_states: Option<Vec<Value>>,
    pub privilege_required: String,
    pub approval_requirement: String,
    pub audit_category: String,
}

impl Descriptor {
    /// Build the full descriptor from static meta plus live state.
    pub fn from_meta(meta: &DescriptorMeta, current_state: Value, desired_state: Value) -> Self {
        Descriptor {
            capability: meta.capability.to_string(),
            supported: true,
            current_state,
            desired_state,
            mutable: true,
            requires_reboot: false,
            risk: meta.risk.to_string(),
            managed_by: "local".to_string(),
            verification: meta.verification.to_string(),
            state_schema: meta.state_schema.clone(),
            allowed_desired_states: meta.allowed_desired_states.clone(),
            privilege_required: "root".to_string(),
            approval_requirement: "allow".to_string(),
            audit_category: meta.audit_category.to_string(),
        }
    }
}

/// A typed capability backend: the only interface through which punard
/// touches privileged system state.
pub trait Capability: Send + Sync {
    /// Static descriptor parts; the registry injects live state.
    fn descriptor(&self) -> DescriptorMeta;

    /// Cheap syntactic/semantic validation of a proposed desired state.
    /// Runs before authorization; failures surface as `invalid_params`.
    fn validate(&self, desired: &Value) -> Result<(), String>;

    /// Observe the live, normalized actual state (never cached).
    fn observe(&self) -> Result<Value, BackendError>;

    /// Drive the system toward `desired`. Callers must have authorized and
    /// validated first.
    fn apply(&self, desired: &Value) -> Result<(), BackendError>;

    /// Re-observe and report whether the actual state equals `desired`.
    fn verify(&self, desired: &Value) -> Result<bool, BackendError> {
        Ok(&self.observe()? == desired)
    }

    /// Desired-state default seeded on first boot; `None` means "seed from
    /// first observation" (docs/development/milestone-3.md section 3).
    fn default_desired(&self) -> Option<Value> {
        None
    }
}

impl fmt::Debug for dyn Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Capability({})", self.descriptor().capability)
    }
}

/// Ordered id → backend mapping. Static after construction; order is the
/// presentation order (firewall, hostname, timezone in the real daemon).
pub struct Registry {
    caps: Vec<Box<dyn Capability>>,
}

impl Registry {
    pub fn new(caps: Vec<Box<dyn Capability>>) -> Self {
        Registry { caps }
    }

    pub fn get(&self, id: &str) -> Option<&dyn Capability> {
        self.caps
            .iter()
            .find(|c| c.descriptor().capability.as_str() == id)
            .map(|c| c.as_ref())
    }

    pub fn iter(&self) -> impl Iterator<Item = &dyn Capability> {
        self.caps.iter().map(|c| c.as_ref())
    }

    pub fn len(&self) -> usize {
        self.caps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.caps.is_empty()
    }
}

pub mod mock {
    //! Test-support capability with scriptable failure modes. Used by the
    //! integration tests; kept in the library so external test binaries can
    //! build registries around it. Not part of the shipped daemon wiring.

    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;

    #[derive(Clone)]
    pub struct MockCapability {
        inner: Arc<MockInner>,
    }

    struct MockInner {
        id: CapabilityId,
        state: Mutex<Value>,
        apply_calls: AtomicUsize,
        fail_apply: AtomicBool,
        verify_false: AtomicBool,
    }

    impl MockCapability {
        pub fn new(id: &str, initial_state: Value) -> Self {
            MockCapability {
                inner: Arc::new(MockInner {
                    id: CapabilityId::new(id).expect("valid mock capability id"),
                    state: Mutex::new(initial_state),
                    apply_calls: AtomicUsize::new(0),
                    fail_apply: AtomicBool::new(false),
                    verify_false: AtomicBool::new(false),
                }),
            }
        }

        /// Directly set the "actual" state (simulates external drift).
        pub fn set_state(&self, state: Value) {
            *self.inner.state.lock().unwrap() = state;
        }

        pub fn state(&self) -> Value {
            self.inner.state.lock().unwrap().clone()
        }

        pub fn apply_calls(&self) -> usize {
            self.inner.apply_calls.load(Ordering::SeqCst)
        }

        pub fn fail_next_applies(&self, fail: bool) {
            self.inner.fail_apply.store(fail, Ordering::SeqCst);
        }

        /// Make verify report a mismatch even after a successful apply.
        pub fn force_verify_false(&self, force: bool) {
            self.inner.verify_false.store(force, Ordering::SeqCst);
        }
    }

    impl Capability for MockCapability {
        fn descriptor(&self) -> DescriptorMeta {
            DescriptorMeta {
                capability: self.inner.id.clone(),
                risk: "low",
                verification: "mock",
                audit_category: "system",
                state_schema: Some(serde_json::json!({ "type": "string" })),
                allowed_desired_states: None,
            }
        }

        fn validate(&self, desired: &Value) -> Result<(), String> {
            if desired.is_string() {
                Ok(())
            } else {
                Err("mock capability states are strings".to_string())
            }
        }

        fn observe(&self) -> Result<Value, BackendError> {
            Ok(self.state())
        }

        fn apply(&self, desired: &Value) -> Result<(), BackendError> {
            self.inner.apply_calls.fetch_add(1, Ordering::SeqCst);
            if self.inner.fail_apply.load(Ordering::SeqCst) {
                return Err(BackendError::new("mock apply failure (scripted)"));
            }
            self.set_state(desired.clone());
            Ok(())
        }

        fn verify(&self, desired: &Value) -> Result<bool, BackendError> {
            if self.inner.verify_false.load(Ordering::SeqCst) {
                return Ok(false);
            }
            Ok(&self.state() == desired)
        }

        fn default_desired(&self) -> Option<Value> {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockCapability;
    use super::*;

    #[test]
    fn descriptor_serializes_to_the_schema_field_set() {
        let mock = MockCapability::new("mock.widget", Value::String("on".into()));
        let d = Descriptor::from_meta(
            &mock.descriptor(),
            Value::String("on".into()),
            Value::String("on".into()),
        );
        let v = serde_json::to_value(&d).unwrap();
        let obj = v.as_object().unwrap();
        for key in [
            "capability",
            "supported",
            "current_state",
            "desired_state",
            "mutable",
            "requires_reboot",
            "risk",
            "managed_by",
            "verification",
            "state_schema",
            "privilege_required",
            "approval_requirement",
            "audit_category",
        ] {
            assert!(obj.contains_key(key), "missing {key}");
        }
        // Optional field absent when None — additionalProperties:false means
        // we must never emit nulls for schema-optional fields.
        assert!(!obj.contains_key("allowed_desired_states"));
        assert_eq!(obj["managed_by"], "local");
        assert_eq!(obj["privilege_required"], "root");
        assert_eq!(obj["approval_requirement"], "allow");
    }

    #[test]
    fn registry_lookup_and_order() {
        let a = MockCapability::new("mock.alpha", Value::String("x".into()));
        let b = MockCapability::new("mock.beta", Value::String("y".into()));
        let reg = Registry::new(vec![Box::new(a), Box::new(b)]);
        assert_eq!(reg.len(), 2);
        assert!(reg.get("mock.alpha").is_some());
        assert!(reg.get("mock.gamma").is_none());
        let ids: Vec<String> = reg
            .iter()
            .map(|c| c.descriptor().capability.to_string())
            .collect();
        assert_eq!(ids, ["mock.alpha", "mock.beta"]);
    }

    #[test]
    fn default_verify_compares_observation() {
        let mock = MockCapability::new("mock.widget", Value::String("on".into()));
        assert!(mock.verify(&Value::String("on".into())).unwrap());
        assert!(!mock.verify(&Value::String("off".into())).unwrap());
    }
}
