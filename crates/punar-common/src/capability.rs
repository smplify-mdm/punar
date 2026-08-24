use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A validated capability identifier: a dotted path such as
/// `security.firewall` or `security.diskEncryption`.
///
/// SPEC sections 10 and 41 address capabilities by dotted path (for example
/// `punarctl policy explain security.firewall`). Validation rules, chosen for
/// Milestone 0 and documented here so later milestones can tighten rather
/// than loosen them:
///
/// - at least two non-empty segments separated by single `.` characters;
/// - each segment starts with an ASCII letter and continues with ASCII
///   letters, digits, or underscores (the SPEC uses both `firewall` and
///   `diskEncryption` spellings, so mixed case is accepted).
///
/// Construct via [`FromStr`] / [`TryFrom<String>`]; both validate. Serde
/// serializes as a plain string and validates on deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CapabilityId(String);

/// Reasons a capability id string fails validation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CapabilityIdError {
    #[error(
        "capability id {0:?} must contain at least two non-empty segments separated by '.' (like \"security.firewall\")"
    )]
    TooFewSegments(String),
    #[error(
        "capability id {id:?} has invalid segment {segment:?}: segments start with an ASCII letter and contain only ASCII letters, digits, or underscores"
    )]
    InvalidSegment { id: String, segment: String },
}

impl CapabilityId {
    /// Validate `input` and construct a `CapabilityId`.
    pub fn new(input: impl Into<String>) -> Result<Self, CapabilityIdError> {
        let input = input.into();
        let segments: Vec<&str> = input.split('.').collect();
        if segments.len() < 2 {
            return Err(CapabilityIdError::TooFewSegments(input));
        }
        for segment in &segments {
            if !segment_is_valid(segment) {
                return Err(CapabilityIdError::InvalidSegment {
                    segment: (*segment).to_string(),
                    id: input,
                });
            }
        }
        Ok(CapabilityId(input))
    }

    /// The capability id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn segment_is_valid(segment: &str) -> bool {
    let mut chars = segment.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for CapabilityId {
    type Err = CapabilityIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        CapabilityId::new(s)
    }
}

impl TryFrom<String> for CapabilityId {
    type Error = CapabilityIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        CapabilityId::new(value)
    }
}

impl From<CapabilityId> for String {
    fn from(id: CapabilityId) -> Self {
        id.0
    }
}

impl AsRef<str> for CapabilityId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_spec_examples() {
        for id in [
            "security.firewall",
            "security.diskEncryption",
            "network.relay.mode",
            "ai.agents.default_policy",
        ] {
            let parsed = CapabilityId::new(id).unwrap();
            assert_eq!(parsed.as_str(), id);
            assert_eq!(parsed.to_string(), id);
        }
    }

    #[test]
    fn rejects_invalid_ids() {
        for id in [
            "",
            "firewall",     // single segment: not a dotted path
            ".firewall",    // empty leading segment
            "security.",    // empty trailing segment
            "security..fw", // empty middle segment
            "security.2fa", // segment starts with a digit
            "_x.firewall",  // segment starts with an underscore
            "security.fire wall",
            "security.fire-wall",
            "security.pare-feu\u{e9}", // non-ASCII
        ] {
            assert!(CapabilityId::new(id).is_err(), "{id:?} should be rejected");
        }
    }

    #[test]
    fn from_str_matches_new() {
        let via_new = CapabilityId::new("security.firewall").unwrap();
        let via_from_str: CapabilityId = "security.firewall".parse().unwrap();
        assert_eq!(via_new, via_from_str);
    }

    #[test]
    fn serde_round_trips_as_plain_string() {
        let id = CapabilityId::new("security.firewall").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"security.firewall\"");
        let back: CapabilityId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn serde_rejects_invalid_strings() {
        assert!(serde_json::from_str::<CapabilityId>("\"not a capability\"").is_err());
        assert!(serde_json::from_str::<CapabilityId>("\"firewall\"").is_err());
    }

    #[test]
    fn errors_are_descriptive() {
        let err = CapabilityId::new("firewall").unwrap_err();
        assert!(err.to_string().contains("firewall"));
        let err = CapabilityId::new("security.2fa").unwrap_err();
        assert!(err.to_string().contains("2fa"));
    }
}
