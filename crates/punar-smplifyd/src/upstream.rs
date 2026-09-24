//! Smplify's Linux device API, the same endpoints its stock agent uses:
//! resolve → enroll (token + CSR) → check-in, then bundle and status over
//! the device certificate. Only the bodies composed here ever leave the
//! device, and every one of them is listed in the visibility manifest
//! (docs/development/smplify-enrollment.md).
use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::{Value, json};

use crate::http::{Client, ClientIdentity, HttpError, Request, Url};

pub const API_PREFIX: &str = "/api/v1/linux/mdm";

/// What the bundle endpoint produces, then JSON for its error bodies.
const BUNDLE_ACCEPT: &str = "application/gzip, application/json;q=0.5";

/// The bundle request, built apart from the send so a test can read exactly
/// what it asks for.
fn bundle_request(url: &Url) -> Request<'_> {
    Request {
        method: "GET",
        url,
        accept: BUNDLE_ACCEPT,
        bearer: None,
        body: None,
    }
}
/// Inside punard's 5 s per-call budget with room for the socket round trip.
pub const CALL_BUDGET: Duration = Duration::from_millis(4000);

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("{0}")]
    Transport(#[from] HttpError),
    #[error("Smplify answered {status}{detail}")]
    Status { status: u16, detail: String },
    #[error("Smplify's answer was not the expected JSON")]
    Shape,
}

impl UpstreamError {
    pub fn status(&self) -> Option<u16> {
        match self {
            UpstreamError::Status { status, .. } => Some(*status),
            _ => None,
        }
    }
}

/// A resolved organisation server plus the client to reach it.
pub struct Api {
    server: Url,
    client: Client,
}

/// A signed bundle as delivered, untouched: this release inspects only its
/// size and delivery id.
pub struct Bundle {
    pub bytes: Vec<u8>,
    pub delivery_id: Option<String>,
}

pub struct Enrolled {
    pub device_id: String,
    pub cert_pem: String,
    pub ca_pem: String,
    pub not_after: Option<String>,
}

impl Api {
    pub fn anonymous(server: &Url) -> Result<Api, UpstreamError> {
        Ok(Api {
            server: server.clone(),
            client: Client::new(None, CALL_BUDGET)?,
        })
    }

    pub fn with_identity(server: &Url, identity: ClientIdentity) -> Result<Api, UpstreamError> {
        Ok(Api {
            server: server.clone(),
            client: Client::new(Some(identity), CALL_BUDGET)?,
        })
    }

    /// `POST /os-identifiers/resolve` with the five os-release keys. `None`
    /// when the registry has no row for this image.
    pub fn resolve_os(
        &self,
        os_release: &BTreeMap<String, String>,
    ) -> Result<Option<String>, UpstreamError> {
        let body = serde_json::to_vec(os_release).map_err(|_| UpstreamError::Shape)?;
        let response = self.post("/os-identifiers/resolve", None, &body)?;
        if response.status != 200 {
            return Ok(None);
        }
        let value = data(&response.body)?;
        if value.get("resolved").and_then(Value::as_bool) != Some(true) {
            return Ok(None);
        }
        Ok(value
            .get("osIdentifier")
            .and_then(|o| o.get("id"))
            .and_then(Value::as_str)
            .map(str::to_string))
    }

    /// `POST /enroll` with the enrollment code as the bearer and the CSR.
    pub fn enroll(
        &self,
        code: &str,
        csr_pem: &str,
        hostname: &str,
        os_identifier: &str,
        machine_id: &str,
    ) -> Result<Enrolled, UpstreamError> {
        let body = json!({
            "csrPem": csr_pem,
            "hostname": hostname,
            "osIdentifier": os_identifier,
            "machineId": machine_id,
        });
        let response = self.post("/enroll", Some(code), body.to_string().as_bytes())?;
        if response.status != 200 && response.status != 201 {
            return Err(status_error(response.status, &response.body));
        }
        let value = data(&response.body)?;
        let device_id = string(&value, "deviceId")?;
        let cert_pem = string(&value, "clientCertPem")?;
        let ca_pem = value
            .get("caCertPem")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let not_after = value
            .get("notAfter")
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok(Enrolled {
            device_id,
            cert_pem,
            ca_pem,
            not_after,
        })
    }

    /// `POST /devices/{id}/checkin`. Returns the tenant signing key Smplify
    /// presents, if any.
    pub fn checkin(
        &self,
        device_id: &str,
        os_identifier: &str,
        os_release: &BTreeMap<String, String>,
    ) -> Result<Option<String>, UpstreamError> {
        let body = json!({
            "deviceId": device_id,
            "osIdentifier": os_identifier,
            "osRelease": os_release,
            "timestamp": crate::clock::now_rfc3339(),
        });
        let response = self.post(
            &format!("/devices/{device_id}/checkin"),
            None,
            body.to_string().as_bytes(),
        )?;
        // Smplify acknowledges a check-in with 202 Accepted, the signing key
        // in its body. Requiring exactly 200 refused every acknowledgement,
        // so the key was never pinned.
        if response.status / 100 != 2 {
            return Err(status_error(response.status, &response.body));
        }
        let value = data(&response.body).unwrap_or(Value::Null);
        Ok(value
            .get("tenantPublicKeyX509Base64")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string))
    }

    /// `GET /devices/{id}/bundle`: `None` on 204 (nothing assigned). The
    /// bundle is a gzip archive (`LinuxDeviceController` declares
    /// `produces = "application/gzip"`), so asking only for JSON is answered
    /// 406; JSON stays acceptable, at lower weight, for error bodies.
    pub fn bundle(&self, device_id: &str) -> Result<Option<Bundle>, UpstreamError> {
        let url = self.url(&format!("/devices/{device_id}/bundle"));
        let response = self.client.send(&bundle_request(&url))?;
        match response.status {
            204 => Ok(None),
            200 => Ok(Some(Bundle {
                delivery_id: response
                    .header("X-Smplify-Linux-Delivery-Id")
                    .map(str::to_string),
                bytes: response.body,
            })),
            status => Err(status_error(status, &response.body)),
        }
    }

    /// `POST /devices/{id}/status` with a body composed by the caller.
    pub fn status(&self, device_id: &str, body: &Value) -> Result<(), UpstreamError> {
        let response = self.post(
            &format!("/devices/{device_id}/status"),
            None,
            body.to_string().as_bytes(),
        )?;
        if response.status / 100 != 2 {
            return Err(status_error(response.status, &response.body));
        }
        Ok(())
    }

    fn url(&self, path: &str) -> Url {
        self.server.with_path(&format!("{API_PREFIX}{path}"))
    }

    fn post(
        &self,
        path: &str,
        bearer: Option<&str>,
        body: &[u8],
    ) -> Result<crate::http::Response, UpstreamError> {
        let url = self.url(path);
        Ok(self.client.send(&Request {
            method: "POST",
            url: &url,
            accept: crate::http::ACCEPT_JSON,
            bearer,
            body: Some(body),
        })?)
    }
}

/// Smplify wraps answers as `{success, data}`; accept that or a bare object.
fn data(body: &[u8]) -> Result<Value, UpstreamError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| UpstreamError::Shape)?;
    match value.get("data") {
        Some(inner) if inner.is_object() => Ok(inner.clone()),
        _ => Ok(value),
    }
}

fn string(value: &Value, key: &str) -> Result<String, UpstreamError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or(UpstreamError::Shape)
}

/// The server's own message when it sent one, trimmed and never echoing a
/// secret (the enrollment code is the only secret in play and it is a
/// request header, not something a body can contain).
fn status_error(status: u16, body: &[u8]) -> UpstreamError {
    let detail = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| {
            v.get("message")
                .or_else(|| v.get("error"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .filter(|m| !m.is_empty())
        .map(|m| format!(": {}", m.chars().take(200).collect::<String>()))
        .unwrap_or_default();
    UpstreamError::Status { status, detail }
}

/// The category-states-only compliance body, flattened into Smplify's
/// `facts` map so it lands in `device_facts` verbatim.
pub fn compliance_status_body(device_id: &str, report: &Value) -> Value {
    let mut facts = serde_json::Map::new();
    if let Some(overall) = report.get("overall").and_then(Value::as_str) {
        facts.insert(
            "punar_compliance_overall".into(),
            Value::String(overall.into()),
        );
    }
    if let Some(categories) = report.get("categories").and_then(Value::as_array) {
        for category in categories {
            if let (Some(name), Some(state)) = (
                category.get("category").and_then(Value::as_str),
                category.get("state").and_then(Value::as_str),
            ) {
                facts.insert(
                    format!("punar_compliance_{}", fact_key(name)),
                    Value::String(state.into()),
                );
            }
        }
    }
    json!({
        "deviceId": device_id,
        "heartbeat": crate::clock::now_rfc3339(),
        "facts": facts,
    })
}

/// The inventory body: the operating system Smplify displays for every
/// Linux device, and nothing else. No hostname, no network, no software list,
/// and no capability VALUES: punard's inventory carries each capability's
/// observed value (`current_state` — the hostname string, the timezone), which
/// is exactly what "category states only" keeps on the device. Per-capability
/// compliance states already travel as `punar_compliance_<capability>` facts
/// in the compliance report.
///
/// On a Punar image the organization manages Punar, not its substrate, so the
/// name is Punar's and the version is the image release (Debian unstable has
/// no VERSION_ID). A value that is absent or the substrate's "unknown"
/// placeholder is sent as `null`: Smplify keeps what it already has for a
/// null, while a placeholder would overwrite a real version.
pub fn inventory_status_body(device_id: &str, inventory: &Value) -> Value {
    let os = inventory.get("os").cloned().unwrap_or(Value::Null);
    let known = |key: &str| -> Option<String> {
        os.get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty() && *v != "unknown")
            .map(str::to_string)
    };
    let punar = known("image_id").is_some_and(|id| id.starts_with("punar"));
    let name = if punar {
        Some("Punar OS".to_string())
    } else {
        known("pretty_name")
    };
    let version = known("image_version").or_else(|| known("version_id"));
    let kernel = inventory
        .get("kernel")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && *v != "unknown");
    json!({
        "deviceId": device_id,
        "heartbeat": crate::clock::now_rfc3339(),
        "systemInfo": {
            "os": {
                "name": name,
                "version": version,
                "kernelRelease": kernel,
            }
        },
        "facts": {},
    })
}

fn fact_key(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bundle endpoint produces application/gzip and answers 406 to a
    /// request that accepts only JSON — the failure a real enrollment hit.
    #[test]
    fn the_bundle_is_asked_for_as_gzip() {
        let url = crate::http::parse_https_url(
            "https://api.smplify.test/api/v1/linux/mdm/devices/d/bundle",
        )
        .unwrap();
        let head = crate::http::request_head(&bundle_request(&url));
        assert!(
            head.contains("\r\nAccept: application/gzip, application/json;q=0.5\r\n"),
            "{head}"
        );
    }

    #[test]
    fn compliance_flattens_to_facts_and_nothing_else() {
        let body = compliance_status_body(
            "dev-1",
            &json!({"overall": "compliant", "categories": [{"category": "security.firewall", "state": "compliant"}]}),
        );
        assert_eq!(body["facts"]["punar_compliance_overall"], "compliant");
        assert_eq!(
            body["facts"]["punar_compliance_security_firewall"],
            "compliant"
        );
        let keys: Vec<&String> = body.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["deviceId", "facts", "heartbeat"]);
    }

    /// The shape punard really sends: a Punar image on Debian unstable, with
    /// capability values that must stay on the device.
    #[test]
    fn inventory_sends_punar_and_its_release_and_no_capability_values() {
        let body = inventory_status_body(
            "dev-1",
            &json!({
                "os": {
                    "id": "debian",
                    "version_id": "unknown",
                    "pretty_name": "Debian GNU/Linux forky/sid",
                    "image_id": "punar-desktop",
                    "image_version": "2026.09.01.1"
                },
                "kernel": "6.12.48-punar",
                "hostname": "atlas",
                "capabilities": [
                    {"capability": "system.hostname", "supported": true, "current_state": "atlas"},
                    {"capability": "time.timezone", "supported": true, "current_state": "Europe/Berlin"}
                ]
            }),
        );
        assert_eq!(body["systemInfo"]["os"]["name"], "Punar OS");
        assert_eq!(body["systemInfo"]["os"]["version"], "2026.09.01.1");
        assert_eq!(body["systemInfo"]["os"]["kernelRelease"], "6.12.48-punar");
        assert_eq!(body["facts"], json!({}));
        let text = body.to_string();
        assert!(
            !text.contains("atlas"),
            "hostname must not travel in status"
        );
        assert!(
            !text.contains("Berlin"),
            "capability values stay on the device"
        );
    }

    /// A value the device does not know is sent as null, never as a
    /// placeholder that would overwrite what Smplify already stores.
    #[test]
    fn an_unknown_version_is_sent_as_null() {
        let body = inventory_status_body(
            "dev-1",
            &json!({
                "os": {"id": "debian", "version_id": "unknown", "pretty_name": "unknown"},
                "kernel": "unknown",
                "capabilities": []
            }),
        );
        assert_eq!(body["systemInfo"]["os"]["name"], Value::Null);
        assert_eq!(body["systemInfo"]["os"]["version"], Value::Null);
        assert_eq!(body["systemInfo"]["os"]["kernelRelease"], Value::Null);
    }

    #[test]
    fn answers_unwrap_data_and_status_errors_carry_the_server_message() {
        let v = data(br#"{"success":true,"data":{"deviceId":"d"}}"#).unwrap();
        assert_eq!(v["deviceId"], "d");
        let v = data(br#"{"deviceId":"d"}"#).unwrap();
        assert_eq!(v["deviceId"], "d");
        let e = status_error(401, br#"{"message":"token revoked"}"#);
        assert_eq!(e.to_string(), "Smplify answered 401: token revoked");
        assert_eq!(e.status(), Some(401));
    }
}
