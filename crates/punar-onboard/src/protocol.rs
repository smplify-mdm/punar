//! First-run wire types and validation shared by the unprivileged client and
//! privileged backend. The password is intentionally absent from every
//! response and error type.

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;
use unicode_segmentation::UnicodeSegmentation;

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_REQUEST_BYTES: usize = 4096;
pub const MAX_RESPONSE_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAccountWire {
    pub v: u32,
    pub username: String,
    pub password: String,
    #[serde(rename = "deviceName")]
    pub device_name: String,
    /// `None` selects the network-provided timezone, with UTC as the offline
    /// fallback. A value is an IANA zoneinfo name such as
    /// `America/Los_Angeles`.
    #[serde(default)]
    pub timezone: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuccessResponse<'a> {
    pub v: u32,
    pub ok: bool,
    pub username: &'a str,
    pub hostname: &'a str,
    pub recovery_code: &'a str,
    pub timezone: Option<&'a str>,
    pub timezone_automatic: bool,
    pub timezone_applied: bool,
    pub timezone_warning: Option<&'a str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse<'a> {
    pub v: u32,
    pub ok: bool,
    pub code: &'a str,
    pub field: Option<&'a str>,
    pub message: &'a str,
    pub changed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAccount {
    pub username: String,
    pub device_name: String,
    pub hostname: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationError {
    pub code: &'static str,
    pub field: &'static str,
    pub message: &'static str,
}

pub fn validate_account(
    username: &str,
    password: &str,
    device_name: &str,
) -> Result<ValidatedAccount, ValidationError> {
    validate_username(username)?;
    let device_name = validate_device_name(device_name)?;
    validate_password(password, username, &device_name)?;
    let hostname = derive_hostname(&device_name).ok_or(ValidationError {
        code: "device_name_no_hostname",
        field: "deviceName",
        message: "Use at least one Latin letter or number so this machine has a network name.",
    })?;

    Ok(ValidatedAccount {
        username: username.to_owned(),
        device_name,
        hostname,
    })
}

pub fn validate_username(username: &str) -> Result<(), ValidationError> {
    let bytes = username.as_bytes();
    let pattern_ok = !bytes.is_empty()
        && bytes.len() <= 32
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
        && !username.ends_with('-');
    if !pattern_ok {
        return Err(ValidationError {
            code: "username_invalid",
            field: "username",
            message: "Start with a lowercase letter; use up to 32 lowercase letters, numbers, _ or -.",
        });
    }

    const RESERVED: &[&str] = &["root", "nobody", "greeter", "punard", "punar"];
    if RESERVED.contains(&username) || username.starts_with("punar-") {
        return Err(ValidationError {
            code: "username_reserved",
            field: "username",
            message: "That name is reserved by the system. Choose another username.",
        });
    }
    Ok(())
}

pub fn validate_device_name(device_name: &str) -> Result<String, ValidationError> {
    let trimmed = device_name.trim();
    let graphemes = trimmed.graphemes(true).count();
    if graphemes == 0 || graphemes > 64 || trimmed.chars().any(char::is_control) {
        return Err(ValidationError {
            code: "device_name_invalid",
            field: "deviceName",
            message: "Use a device name between 1 and 64 visible characters.",
        });
    }
    Ok(trimmed.to_owned())
}

/// Traversal-safe syntax shared by the greeter and its privileged service.
/// Existence under `/usr/share/zoneinfo` is checked by the service before the
/// account transaction starts.
pub fn validate_timezone_name(name: &str) -> Result<(), ValidationError> {
    let valid = !name.is_empty()
        && name.len() <= 128
        && name.split('/').all(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '+' | '-'))
        });
    if !valid {
        return Err(ValidationError {
            code: "timezone_invalid",
            field: "timezone",
            message: "Choose a timezone from the list, or use Automatic (network).",
        });
    }
    Ok(())
}

pub fn validate_password(
    password: &str,
    username: &str,
    device_name: &str,
) -> Result<(), ValidationError> {
    let graphemes = password.graphemes(true).count();
    if graphemes < 10 {
        return Err(ValidationError {
            code: "password_too_short",
            field: "password",
            message: "Use 10 or more characters. There are no symbol or capital-letter rules.",
        });
    }
    if password.len() > 256 || password.chars().any(char::is_control) {
        return Err(ValidationError {
            code: "password_invalid",
            field: "password",
            message: "Use at most 256 bytes and no control characters.",
        });
    }

    let folded = password.to_lowercase();
    let compact: String = folded.chars().filter(|c| c.is_alphanumeric()).collect();
    let user_folded = username.to_lowercase();
    let device_compact: String = device_name
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect();
    if folded.contains("punar")
        || compact.contains(&user_folded)
        || (device_compact.len() >= 4 && compact.contains(&device_compact))
    {
        return Err(ValidationError {
            code: "password_contains_context",
            field: "password",
            message: "Choose a password that does not contain your username, device name, or Punar.",
        });
    }

    if is_common_password(&folded) {
        return Err(ValidationError {
            code: "password_common",
            field: "password",
            message: "That password is commonly guessed. Try three unrelated words instead.",
        });
    }
    Ok(())
}

fn is_common_password(password: &str) -> bool {
    matches!(
        password.trim(),
        "1234567890"
            | "123456789"
            | "qwertyuiop"
            | "qwerty12345"
            | "password"
            | "password1"
            | "password12"
            | "password123"
            | "letmein123"
            | "iloveyou123"
            | "administrator"
            | "welcome123"
            | "changeme123"
            | "correcthorsebatterystaple"
    )
}

/// Derive the RFC-1123 label shown beneath the device display name. Apostrophe
/// marks are elided (`Alice's` → `alices`); other separator runs become one
/// dash. Non-ASCII letters are decomposed before filtering.
pub fn derive_hostname(device_name: &str) -> Option<String> {
    let mut out = String::with_capacity(device_name.len().min(63));
    let mut separator = false;

    for ch in device_name.nfkd() {
        if ch.is_ascii_alphanumeric() {
            if separator && !out.is_empty() && out.len() < 63 {
                out.push('-');
            }
            separator = false;
            if out.len() < 63 {
                out.push(ch.to_ascii_lowercase());
            }
        } else if ch == '\'' || ch == '\u{2019}' || is_combining_mark(ch) {
            continue;
        } else {
            separator = true;
        }
    }

    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() || out.len() > 63 {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_follow_the_binding_contract() {
        for accepted in ["alice", "alice_2", "a", "a-b"] {
            assert!(validate_username(accepted).is_ok(), "{accepted}");
        }
        for refused in ["Alice", "_alice", "alice-", "root", "punar-ci", "a.b", ""] {
            assert!(validate_username(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn display_name_derives_the_documented_hostname() {
        assert_eq!(
            derive_hostname("Alice's ThinkPad").as_deref(),
            Some("alices-thinkpad")
        );
        assert_eq!(
            derive_hostname("  Préetham’s  Pi  ").as_deref(),
            Some("preethams-pi")
        );
        assert_eq!(derive_hostname("李雷"), None);
    }

    #[test]
    fn password_floor_is_explainable_and_offline() {
        assert!(validate_password("short-pass", "alice", "Workstation").is_ok());
        assert!(validate_password("password123", "alice", "Workstation").is_err());
        assert!(validate_password("alice-build-machine", "alice", "Workstation").is_err());
        assert!(validate_password("punar-is-lovely", "alice", "Workstation").is_err());
        assert!(validate_password("three amber rivers", "alice", "Workstation").is_ok());
    }

    #[test]
    fn required_account_values_validate_together() {
        let account = validate_account("alice", "three amber rivers", "Alice's ThinkPad").unwrap();
        assert_eq!(account.hostname, "alices-thinkpad");
        assert_eq!(account.device_name, "Alice's ThinkPad");
    }

    #[test]
    fn timezone_names_are_traversal_safe() {
        for accepted in [
            "UTC",
            "Europe/Berlin",
            "America/Argentina/Ushuaia",
            "Etc/GMT+5",
        ] {
            assert!(validate_timezone_name(accepted).is_ok(), "{accepted}");
        }
        for refused in [
            "",
            "/UTC",
            "UTC/",
            "Europe//Berlin",
            "../etc/shadow",
            "Europe/..",
        ] {
            assert!(validate_timezone_name(refused).is_err(), "{refused}");
        }
    }
}
