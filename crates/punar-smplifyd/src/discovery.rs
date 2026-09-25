//! `org.discover {domain}`: what the organisation publishes about itself,
//! read before any secret is spent. Two sources, in order:
//!
//! 1. a root-owned override `<dir>/<domain>.json` — how a lab image or an
//!    organisation without a public web host pins the document;
//! 2. `https://<domain>/.well-known/smplify-management.json`, fetched with
//!    the platform roots.
//!
//! The document keeps the shape punard already reads from the mock's
//! `org.json` (`id`, `name`, `enrollment.display_name`,
//! `enrollment.remote_query_scopes`, `enrollment.removable`,
//! `enrollment.ownership`, `discovery.domain`) and adds the one thing the mock
//! never needed: `enrollment.server`, the Smplify API origin. Enrollment terms
//! such as `removable` and `ownership` are punard's to judge, so they travel
//! in `document` untouched.
use std::path::Path;

use punar_common::ipc::organization_name;
use punar_smplifyd::budget::DISCOVERY_BUDGET;
use serde_json::{Value, json};

use crate::http::{self, Client, Request, parse_https_url};
use crate::protocol::{CallError, ErrorCode};

/// Well-known path (relative to the organisation's domain).
pub const WELL_KNOWN_PATH: &str = "/.well-known/smplify-management.json";

#[derive(Debug, Clone, PartialEq)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub domain: String,
    /// API origin, e.g. `https://api.smplify.example`.
    pub server: http::Url,
    pub methods: Vec<String>,
    pub remote_query_scopes: Vec<String>,
    /// The document as punard receives it.
    pub document: Value,
}

pub fn domain_syntax_ok(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
        && domain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

pub fn discover(override_dir: &Path, domain: &str) -> Result<Organization, CallError> {
    let domain = domain.trim().to_ascii_lowercase();
    if !domain_syntax_ok(&domain) {
        return Err(CallError::new(
            ErrorCode::InvalidParams,
            format!("{domain:?} is not a domain name"),
        ));
    }
    let override_path = override_dir.join(format!("{domain}.json"));
    if let Ok(bytes) = std::fs::read(&override_path) {
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
            CallError::new(
                ErrorCode::Internal,
                format!("the pinned organization document for {domain} is not JSON"),
            )
        })?;
        return parse_document(&domain, value);
    }
    let url = parse_https_url(&format!("https://{domain}{WELL_KNOWN_PATH}"))
        .map_err(|_| CallError::new(ErrorCode::InvalidParams, "domain cannot form a URL"))?;
    let client = Client::new(None, DISCOVERY_BUDGET)
        .map_err(|_| CallError::new(ErrorCode::Internal, "TLS is unavailable"))?;
    let response = client
        .send(&Request {
            method: "GET",
            url: &url,
            accept: crate::http::ACCEPT_JSON,
            bearer: None,
            body: None,
        })
        .map_err(|e| {
            CallError::new(
                ErrorCode::NotFound,
                format!("{domain} publishes no management document ({e})"),
            )
        })?;
    if response.status == 404 {
        return Err(CallError::new(
            ErrorCode::NotFound,
            format!("{domain} publishes no management document"),
        ));
    }
    if response.status != 200 {
        return Err(CallError::new(
            ErrorCode::NotFound,
            format!(
                "{domain} answered {} for its management document",
                response.status
            ),
        ));
    }
    let value: Value = serde_json::from_slice(&response.body).map_err(|_| {
        CallError::new(
            ErrorCode::NotFound,
            format!("{domain}'s management document is not JSON"),
        )
    })?;
    parse_document(&domain, value)
}

/// Validate and normalise a document. Missing `discovery.domain` is filled
/// from the request; a document that names a different domain is refused,
/// because a document is only trusted for the host that served it.
pub fn parse_document(domain: &str, mut value: Value) -> Result<Organization, CallError> {
    let bad = |what: &str| {
        CallError::new(
            ErrorCode::NotFound,
            format!("{domain}'s management document is missing {what}"),
        )
    };
    let id = str_at(&value, &["id"]).ok_or_else(|| bad("id"))?;
    let name = str_at(&value, &["name"]).ok_or_else(|| bad("name"))?;
    let server_raw =
        str_at(&value, &["enrollment", "server"]).ok_or_else(|| bad("enrollment.server"))?;
    let server = parse_https_url(&server_raw).map_err(|_| {
        CallError::new(
            ErrorCode::NotFound,
            format!("{domain}'s management document names a server that is not https://"),
        )
    })?;
    if server.path != "/" {
        return Err(CallError::new(
            ErrorCode::NotFound,
            format!("{domain}'s enrollment.server must be an origin without a path"),
        ));
    }
    let display_name =
        str_at(&value, &["enrollment", "display_name"]).unwrap_or_else(|| name.clone());
    let methods = strings_at(&value, &["enrollment", "methods"]);
    let remote_query_scopes = strings_at(&value, &["enrollment", "remote_query_scopes"]);
    match str_at(&value, &["discovery", "domain"]) {
        // The document names another domain, in text the domain's owner
        // chose and punard repeats to a person: cleaned and bounded like an
        // organization's name before it goes anywhere.
        Some(named) if named != domain => {
            let named = organization_name(&named).unwrap_or_else(|| "another domain".to_string());
            return Err(CallError::new(
                ErrorCode::NotFound,
                format!("{domain}'s management document is for {named}"),
            ));
        }
        Some(_) => {}
        None => {
            let discovery = value
                .as_object_mut()
                .and_then(|o| {
                    o.entry("discovery")
                        .or_insert_with(|| json!({}))
                        .as_object_mut()
                })
                .ok_or_else(|| bad("discovery"))?;
            discovery.insert("domain".into(), Value::String(domain.to_string()));
        }
    }
    if let Some(discovery) = value.get_mut("discovery").and_then(Value::as_object_mut) {
        discovery
            .entry("control_plane")
            .or_insert_with(|| Value::String("smplify".into()));
        discovery
            .entry("endpoint")
            .or_insert_with(|| Value::String(server.origin()));
    }
    Ok(Organization {
        id,
        name,
        display_name,
        domain: domain.to_string(),
        server,
        methods,
        remote_query_scopes,
        document: value,
    })
}

fn str_at(value: &Value, path: &[&str]) -> Option<String> {
    let mut cur = value;
    for key in path {
        cur = cur.get(key)?;
    }
    cur.as_str()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn strings_at(value: &Value, path: &[&str]) -> Vec<String> {
    let mut cur = value;
    for key in path {
        match cur.get(key) {
            Some(next) => cur = next,
            None => return Vec::new(),
        }
    }
    cur.as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> Value {
        json!({
            "id": "acme",
            "name": "Acme",
            "enrollment": {
                "display_name": "Acme Engineering",
                "server": "https://api.acme.example",
                "methods": ["code"],
                "remote_query_scopes": ["inventory"]
            }
        })
    }

    /// Whether a device may later be unenrolled, and whether the organization
    /// owns it, are the organization's terms, and punard decides on them; this
    /// agent must neither drop nor rewrite them, not even one punard will
    /// refuse (docs/development/smplify-enrollment.md sections 3.1 and 3.2).
    #[test]
    fn enrollment_terms_reach_punard_untouched() {
        for (term, values) in [
            ("removable", [json!(false), json!(true), json!("no")]),
            (
                "ownership",
                [json!("organization"), json!("personal"), json!("Corporate")],
            ),
        ] {
            for value in values {
                let mut d = doc();
                d["enrollment"][term] = value.clone();
                let org = parse_document("acme.com", d).unwrap();
                assert_eq!(org.document["enrollment"][term], value);
            }
            let org = parse_document("acme.com", doc()).unwrap();
            assert!(org.document["enrollment"].get(term).is_none(), "{term}");
        }
    }

    #[test]
    fn a_document_is_normalised_for_punard() {
        let org = parse_document("acme.com", doc()).unwrap();
        assert_eq!(org.display_name, "Acme Engineering");
        assert_eq!(org.server.origin(), "https://api.acme.example");
        assert_eq!(org.document["discovery"]["domain"], "acme.com");
        assert_eq!(org.document["discovery"]["control_plane"], "smplify");
        assert_eq!(org.methods, vec!["code".to_string()]);
    }

    #[test]
    fn refuses_plaintext_servers_other_domains_and_missing_fields() {
        let mut d = doc();
        d["enrollment"]["server"] = json!("http://api.acme.example");
        assert!(parse_document("acme.com", d).is_err());
        let mut d = doc();
        d["discovery"] = json!({"domain": "evil.example"});
        assert!(parse_document("acme.com", d).is_err());
        let mut d = doc();
        d["enrollment"]["server"] = json!("https://api.acme.example/v1");
        assert!(parse_document("acme.com", d).is_err());
        let mut d = doc();
        d.as_object_mut().unwrap().remove("name");
        assert!(parse_document("acme.com", d).is_err());
    }

    /// The domain a document says it is for is the domain owner's text, and
    /// the refusal that names it reaches a person's terminal through punard:
    /// cleaned and bounded like an organization's name.
    #[test]
    fn another_domains_name_is_cleaned_before_it_is_repeated() {
        let mut d = doc();
        d["discovery"] = json!({"domain": format!(
            "x\u{1b}]52;c;cm0=\u{7}\nPolicy: forged\u{202e}{}",
            "y".repeat(100_000)
        )});
        let refused = parse_document("acme.com", d).unwrap_err();
        assert!(
            !refused
                .message
                .chars()
                .any(|c| c.is_control() || c == '\u{202e}'),
            "{:?}",
            refused.message
        );
        assert!(
            refused
                .message
                .starts_with("acme.com's management document is for x]52;c;cm0= Policy"),
            "{}",
            refused.message
        );
        assert!(refused.message.chars().count() < 200, "{}", refused.message);
    }

    #[test]
    fn override_files_are_pinned_documents_and_domains_are_validated() {
        let dir = std::env::temp_dir().join(format!("punar-smplifyd-disc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("smplify.lab.json"), doc().to_string()).unwrap();
        let org = discover(&dir, "Smplify.Lab").unwrap();
        assert_eq!(org.domain, "smplify.lab");
        assert_eq!(
            discover(&dir, "../etc/passwd").unwrap_err().code,
            ErrorCode::InvalidParams
        );
        assert_eq!(
            discover(&dir, "").unwrap_err().code,
            ErrorCode::InvalidParams
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
