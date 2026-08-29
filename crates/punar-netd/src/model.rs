//! Closed, validated types at the network enforcement boundary.
//!
//! Raw project files never reach the nft generator. They first become these
//! types, so a zone name cannot become an identifier injection, a cgroup path
//! cannot become a second statement, and an ambiguous CIDR cannot silently
//! widen a set.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ModelError {
    #[error("{0:?} is not a valid snake_case network zone name")]
    InvalidZoneName(String),
    #[error("{0:?} is not a valid project identifier")]
    InvalidProjectId(String),
    #[error("{0:?} is not a valid local user name")]
    InvalidUserName(String),
    #[error("{0:?} is not a valid managed agent session id")]
    InvalidSessionId(String),
    #[error("{0:?} is not a safe absolute cgroup v2 path")]
    InvalidCgroupPath(String),
    #[error("{0:?} is not a canonical IPv4 or IPv6 CIDR")]
    InvalidCidr(String),
    #[error("zone member name key {0:?} is not an IP address")]
    InvalidAddressName(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    ApprovalRequired,
    Deny,
}

impl Decision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::ApprovalRequired => "approval_required",
            Self::Deny => "deny",
        }
    }

    pub const fn blocks(self) -> bool {
        !matches!(self, Self::Allow)
    }

    /// Security order, intentionally opposite to enum declaration order.
    pub const fn strictness(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::ApprovalRequired => 1,
            Self::Deny => 2,
        }
    }

    pub const fn strictest(self, other: Self) -> Self {
        if self.strictness() >= other.strictness() {
            self
        } else {
            other
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoneKind {
    Internet,
    Corporate,
    Production,
    Privileged,
}

impl ZoneKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Internet => "internet",
            Self::Corporate => "corporate",
            Self::Production => "production",
            Self::Privileged => "privileged",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayMode {
    Direct,
    PrivateRelay,
    EnterpriseRoute,
}

impl RelayMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::PrivateRelay => "private_relay",
            Self::EnterpriseRoute => "enterprise_route",
        }
    }

    pub const fn simulated(self) -> bool {
        !matches!(self, Self::Direct)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneDefinition {
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub kind: ZoneKind,
    #[serde(default)]
    pub relay_mode: Option<RelayMode>,
}

impl ZoneDefinition {
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_zone_name(&self.name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Cidr {
    V4(Ipv4Addr, u8),
    V6(Ipv6Addr, u8),
}

impl Cidr {
    pub fn parse(value: &str) -> Result<Self, ModelError> {
        let (address, prefix) = value
            .split_once('/')
            .ok_or_else(|| ModelError::InvalidCidr(value.to_string()))?;
        if prefix.is_empty() || prefix.bytes().any(|b| !b.is_ascii_digit()) {
            return Err(ModelError::InvalidCidr(value.to_string()));
        }
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| ModelError::InvalidCidr(value.to_string()))?;
        match IpAddr::from_str(address) {
            Ok(IpAddr::V4(ip)) if prefix <= 32 => {
                let raw = u32::from(ip);
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                if raw & mask != raw {
                    return Err(ModelError::InvalidCidr(value.to_string()));
                }
                Ok(Self::V4(ip, prefix))
            }
            Ok(IpAddr::V6(ip)) if prefix <= 128 => {
                let raw = u128::from(ip);
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                if raw & mask != raw {
                    return Err(ModelError::InvalidCidr(value.to_string()));
                }
                Ok(Self::V6(ip, prefix))
            }
            _ => Err(ModelError::InvalidCidr(value.to_string())),
        }
    }

    pub const fn is_v4(self) -> bool {
        matches!(self, Self::V4(_, _))
    }

    pub fn contains(self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::V4(network, prefix), IpAddr::V4(address)) => {
                masked_v4(address, prefix) == u32::from(network)
            }
            (Self::V6(network, prefix), IpAddr::V6(address)) => {
                masked_v6(address, prefix) == u128::from(network)
            }
            _ => false,
        }
    }

    pub fn overlaps(self, other: Self) -> bool {
        match (self, other) {
            (Self::V4(left, left_prefix), Self::V4(right, right_prefix)) => {
                let prefix = left_prefix.min(right_prefix);
                masked_v4(left, prefix) == masked_v4(right, prefix)
            }
            (Self::V6(left, left_prefix), Self::V6(right, right_prefix)) => {
                let prefix = left_prefix.min(right_prefix);
                masked_v6(left, prefix) == masked_v6(right, prefix)
            }
            _ => false,
        }
    }
}

fn masked_v4(address: Ipv4Addr, prefix: u8) -> u32 {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(address) & mask
}

fn masked_v6(address: Ipv6Addr, prefix: u8) -> u128 {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    u128::from(address) & mask
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(ip, prefix) => write!(f, "{ip}/{prefix}"),
            Self::V6(ip, prefix) => write!(f, "{ip}/{prefix}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneMembership {
    pub cidrs: Vec<Cidr>,
    pub names: BTreeMap<IpAddr, String>,
}

pub fn validate_zone_name(value: &str) -> Result<(), ModelError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || !bytes[0].is_ascii_lowercase()
        || bytes
            .iter()
            .any(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_'))
    {
        return Err(ModelError::InvalidZoneName(value.to_string()));
    }
    Ok(())
}

pub fn validate_project_id(value: &str) -> Result<(), ModelError> {
    let bytes = value.as_bytes();
    let edge_ok = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let inner_ok = |b: u8| edge_ok(b) || matches!(b, b'_' | b'-' | b'.');
    if bytes.is_empty()
        || bytes.len() > 64
        || !edge_ok(bytes[0])
        || !edge_ok(*bytes.last().expect("not empty"))
        || bytes.iter().copied().any(|b| !inner_ok(b))
    {
        return Err(ModelError::InvalidProjectId(value.to_string()));
    }
    Ok(())
}

pub fn validate_user_name(value: &str) -> Result<(), ModelError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 64
        || !(bytes[0].is_ascii_lowercase() || bytes[0] == b'_')
        || bytes.iter().any(|byte| {
            !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(*byte, b'_' | b'-'))
        })
    {
        Err(ModelError::InvalidUserName(value.to_string()))
    } else {
        Ok(())
    }
}

pub fn validate_session_id(value: &str) -> Result<(), ModelError> {
    if punar_common::agent::session_id_ok(value) {
        Ok(())
    } else {
        Err(ModelError::InvalidSessionId(value.to_string()))
    }
}

pub fn validate_cgroup_path(value: &str) -> Result<(), ModelError> {
    if !value.starts_with('/')
        || value == "/"
        || value.ends_with('/')
        || value.contains("//")
        || value.split('/').any(|part| matches!(part, "." | ".."))
        || value.bytes().any(|b| b.is_ascii_control() || b == b'"')
    {
        return Err(ModelError::InvalidCgroupPath(value.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_order_is_restrictive() {
        assert_eq!(Decision::Allow.strictest(Decision::Deny), Decision::Deny);
        assert_eq!(
            Decision::ApprovalRequired.strictest(Decision::Allow),
            Decision::ApprovalRequired
        );
        assert!(Decision::ApprovalRequired.blocks());
    }

    #[test]
    fn cidrs_must_be_canonical() {
        assert_eq!(
            Cidr::parse("10.20.0.0/16").unwrap().to_string(),
            "10.20.0.0/16"
        );
        assert_eq!(
            Cidr::parse("2001:db8::/32").unwrap().to_string(),
            "2001:db8::/32"
        );
        assert!(Cidr::parse("10.20.1.7/16").is_err());
        assert!(Cidr::parse("2001:db8::1/64").is_err());
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        let broad = Cidr::parse("10.20.0.0/16").unwrap();
        let narrow = Cidr::parse("10.20.9.0/24").unwrap();
        assert!(broad.overlaps(narrow));
        assert!(broad.contains("10.20.1.7".parse().unwrap()));
        assert!(!broad.contains("10.30.1.7".parse().unwrap()));
    }

    #[test]
    fn identifiers_and_cgroups_refuse_statement_material() {
        assert!(validate_zone_name("corp_prod").is_ok());
        assert!(validate_zone_name("corp-prod").is_err());
        assert!(validate_project_id("atlas.dev-2").is_ok());
        assert!(validate_project_id("-atlas").is_err());
        assert!(validate_session_id("agt_4f21c09ab3e1").is_ok());
        assert!(validate_cgroup_path("/user.slice/user-1000.slice/punar-agent.scope").is_ok());
        assert!(validate_cgroup_path("/user.slice/\"; flush ruleset").is_err());
        assert!(validate_cgroup_path("/user.slice/../system.slice").is_err());
    }
}
