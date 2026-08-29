//! Closed IPC contract for the `punar-netd` sibling socket.
//!
//! Like the punard and agentd tables, no method carries a command, program,
//! packet payload, or capture expression. In particular, `network.capture`,
//! `network.inspect`, and `network.export` do not exist.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::ipc::{
    ErrorCode, IpcError, PROTOCOL_VERSION, RequestEnvelope, RequestReject, parse_envelope_line,
};

pub const NETD_SOCKET_PATH: &str = "/run/punar-netd/netd.sock";
pub const CONNECTIONS_PATH: &str = "/run/punar-netd/connections.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkProjectParams {
    pub project: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkExplainParams {
    pub project: String,
    pub zone: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkApplyParams {
    #[serde(default)]
    pub project: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayPreference {
    Direct,
    PrivateRelay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelaySetParams {
    pub mode: RelayPreference,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkMethod {
    Status,
    Connections,
    Zones,
    Policy(NetworkProjectParams),
    Explain(NetworkExplainParams),
    Apply(NetworkApplyParams),
    RelayStatus,
    RelaySet(RelaySetParams),
}

impl NetworkMethod {
    pub const NAMES: [&'static str; 8] = [
        "network.status",
        "network.connections",
        "network.zones",
        "network.policy",
        "network.explain",
        "network.apply",
        "relay.status",
        "relay.set",
    ];

    pub const fn name(&self) -> &'static str {
        match self {
            Self::Status => "network.status",
            Self::Connections => "network.connections",
            Self::Zones => "network.zones",
            Self::Policy(_) => "network.policy",
            Self::Explain(_) => "network.explain",
            Self::Apply(_) => "network.apply",
            Self::RelayStatus => "relay.status",
            Self::RelaySet(_) => "relay.set",
        }
    }

    pub fn params_value(&self) -> Option<Value> {
        let value = match self {
            Self::Status | Self::Connections | Self::Zones | Self::RelayStatus => return None,
            Self::Policy(params) => serde_json::to_value(params),
            Self::Explain(params) => serde_json::to_value(params),
            Self::Apply(params) => serde_json::to_value(params),
            Self::RelaySet(params) => serde_json::to_value(params),
        };
        Some(value.expect("network params serialize infallibly"))
    }

    pub fn from_wire(method: &str, params: Option<Value>) -> Result<Self, IpcError> {
        let parsed = match method {
            "network.status" => Self::expect_no_params(method, params).map(|()| Self::Status),
            "network.connections" => {
                Self::expect_no_params(method, params).map(|()| Self::Connections)
            }
            "network.zones" => Self::expect_no_params(method, params).map(|()| Self::Zones),
            "network.policy" => Self::parse_required(method, params).map(Self::Policy),
            "network.explain" => Self::parse_required(method, params).map(Self::Explain),
            "network.apply" => Self::parse_optional(method, params).map(Self::Apply),
            "relay.status" => Self::expect_no_params(method, params).map(|()| Self::RelayStatus),
            "relay.set" => Self::parse_required(method, params).map(Self::RelaySet),
            unknown
                if matches!(
                    unknown,
                    "network.capture" | "network.inspect" | "network.export"
                ) =>
            {
                return Err(IpcError::with_details(
                    ErrorCode::UnknownMethod,
                    format!(
                        "The method {unknown:?} does not exist. Punar does not capture packets, inspect payloads, or export connection history. Next step: `punarctl privacy connections` shows the bounded local TCP view."
                    ),
                    json!({"method": unknown, "reason": "privacy boundary"}),
                ));
            }
            unknown => {
                return Err(IpcError::with_details(
                    ErrorCode::UnknownMethod,
                    format!(
                        "The method {unknown:?} does not exist. The punar-netd method table is closed and typed; there is no generic execution method. Next step: run `punarctl network --help`."
                    ),
                    json!({"method": unknown}),
                ));
            }
        }?;
        parsed.validate(method)?;
        Ok(parsed)
    }

    fn validate(&self, method: &str) -> Result<(), IpcError> {
        let invalid = |reason: &str| Self::invalid_params(method, reason);
        match self {
            Self::Policy(params) => validate_project(&params.project).map_err(invalid),
            Self::Explain(params) => {
                validate_project(&params.project).map_err(invalid)?;
                validate_zone(&params.zone).map_err(invalid)
            }
            Self::Apply(params) => match params.project.as_deref() {
                Some(project) => validate_project(project).map_err(invalid),
                None => Ok(()),
            },
            _ => Ok(()),
        }
    }

    fn expect_no_params(method: &str, params: Option<Value>) -> Result<(), IpcError> {
        match params {
            None => Ok(()),
            Some(Value::Object(map)) if map.is_empty() => Ok(()),
            Some(_) => Err(Self::invalid_params(
                method,
                "this method takes no parameters",
            )),
        }
    }

    fn parse_required<P: serde::de::DeserializeOwned>(
        method: &str,
        params: Option<Value>,
    ) -> Result<P, IpcError> {
        let value =
            params.ok_or_else(|| Self::invalid_params(method, "params object is required"))?;
        serde_json::from_value(value)
            .map_err(|error| Self::invalid_params(method, &error.to_string()))
    }

    fn parse_optional<P: serde::de::DeserializeOwned + Default>(
        method: &str,
        params: Option<Value>,
    ) -> Result<P, IpcError> {
        match params {
            None => Ok(P::default()),
            Some(value) => serde_json::from_value(value)
                .map_err(|error| Self::invalid_params(method, &error.to_string())),
        }
    }

    fn invalid_params(method: &str, reason: &str) -> IpcError {
        IpcError::with_details(
            ErrorCode::InvalidParams,
            format!(
                "Invalid parameters for {method}: {reason}. Next step: run `punarctl network --help` for the expected arguments."
            ),
            json!({"reason": reason}),
        )
    }
}

fn validate_project(value: &str) -> Result<(), &'static str> {
    let bytes = value.as_bytes();
    let edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    if bytes.is_empty()
        || bytes.len() > 64
        || !edge(bytes[0])
        || !edge(*bytes.last().expect("not empty"))
        || bytes
            .iter()
            .copied()
            .any(|byte| !(edge(byte) || matches!(byte, b'_' | b'-' | b'.')))
    {
        Err("project must be a 1–64 byte lowercase identifier")
    } else {
        Ok(())
    }
}

fn validate_zone(value: &str) -> Result<(), &'static str> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || !bytes[0].is_ascii_lowercase()
        || bytes
            .iter()
            .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_'))
    {
        Err("zone must be a snake_case identifier")
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRequest {
    pub id: String,
    pub method: NetworkMethod,
}

impl NetworkRequest {
    pub fn to_envelope(&self) -> RequestEnvelope {
        RequestEnvelope {
            v: PROTOCOL_VERSION,
            id: self.id.clone(),
            method: self.method.name().to_string(),
            params: self.method.params_value(),
        }
    }

    pub fn to_json_line(&self) -> String {
        self.to_envelope().to_json_line()
    }

    pub fn parse_json_line(line: &str) -> Result<Self, RequestReject> {
        let envelope = parse_envelope_line(line)?;
        let method =
            NetworkMethod::from_wire(&envelope.method, envelope.params).map_err(|error| {
                RequestReject {
                    id: Some(envelope.id.clone()),
                    error,
                }
            })?;
        Ok(Self {
            id: envelope.id,
            method,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_table_is_closed_and_round_trips() {
        let methods = [
            NetworkMethod::Status,
            NetworkMethod::Connections,
            NetworkMethod::Zones,
            NetworkMethod::Policy(NetworkProjectParams {
                project: "atlas".into(),
            }),
            NetworkMethod::Explain(NetworkExplainParams {
                project: "atlas".into(),
                zone: "corp_prod".into(),
            }),
            NetworkMethod::Apply(NetworkApplyParams { project: None }),
            NetworkMethod::RelayStatus,
            NetworkMethod::RelaySet(RelaySetParams {
                mode: RelayPreference::PrivateRelay,
            }),
        ];
        assert_eq!(methods.len(), NetworkMethod::NAMES.len());
        for method in methods {
            let request = NetworkRequest {
                id: "net-1".into(),
                method: method.clone(),
            };
            assert_eq!(
                NetworkRequest::parse_json_line(&request.to_json_line())
                    .unwrap()
                    .method,
                method
            );
        }
    }

    #[test]
    fn privacy_and_execution_probes_are_unknown() {
        for method in [
            "network.capture",
            "network.inspect",
            "network.export",
            "system.exec",
            "shell.run",
        ] {
            let error = NetworkMethod::from_wire(method, None).unwrap_err();
            assert_eq!(error.code, ErrorCode::UnknownMethod);
        }
    }

    #[test]
    fn params_are_strict_and_semantically_validated() {
        for (method, params) in [
            ("network.status", Some(json!({"extra": true}))),
            ("network.policy", Some(json!({"project": "../root"}))),
            (
                "network.explain",
                Some(json!({"project": "atlas", "zone": "Corp Prod"})),
            ),
            ("relay.set", Some(json!({"mode": "enterprise_route"}))),
        ] {
            let error = NetworkMethod::from_wire(method, params).unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidParams);
        }
    }
}
