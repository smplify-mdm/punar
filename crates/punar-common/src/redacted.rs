use std::fmt;

use serde::{Serialize, Serializer};

/// The only string a [`Redacted`] value ever contributes to output.
pub const REDACTED_PLACEHOLDER: &str = "[redacted]";

/// Wrapper that prevents a secret value from reaching logs or serialized
/// output.
///
/// SPEC section 53: "Never log passwords, secret values, tokens, private
/// keys, prompt contents by default, or source code." SPEC section 1.19
/// requires automated tests for secret redaction. `Redacted<T>` is the type
/// services use to carry secret material so that ordinary formatting and
/// serialization cannot leak it:
///
/// - `Debug` and `Display` always print `[redacted]`, regardless of the
///   inner value, so `format!`, `println!`, panics, and derived `Debug` on
///   containing structs never expose the secret.
/// - **Serialization decision**: `Redacted<T>` implements [`Serialize`], and
///   always serializes as the string `"[redacted]"` for any `T`. Rationale:
///   forbidding `Serialize` entirely would only fail at compile time for
///   direct serialization, while a `Redacted` field inside a larger struct
///   (an audit event, an IPC reply) would then require every container to
///   hand-write serde — an easy place for a leak to slip in later. Always
///   emitting the placeholder makes accidental serialization safe by
///   construction.
/// - `Deserialize` is intentionally **not** implemented: a serialized
///   `Redacted` carries only the placeholder, so no faithful round-trip
///   exists, and silently deserializing `"[redacted]"` into a "secret" would
///   manufacture garbage credentials. Secrets enter the process through the
///   secret broker (SPEC section 29), not through serialized documents.
///
/// The only way to reach the inner value is the explicit
/// [`Redacted::expose_secret`] / [`Redacted::into_inner`] calls, which are
/// easy to audit with `grep`.
///
/// Milestone 0 honesty note: this type controls formatting and serialization
/// only. It does not zeroize memory on drop; that hardening belongs to the
/// secret-broker work (Milestone 9).
#[derive(Clone)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    /// Wrap a secret value.
    pub fn new(secret: T) -> Self {
        Redacted(secret)
    }

    /// Explicitly access the secret. The loud name exists so call sites are
    /// findable in review.
    pub fn expose_secret(&self) -> &T {
        &self.0
    }

    /// Explicitly unwrap the secret, consuming the wrapper.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> From<T> for Redacted<T> {
    fn from(secret: T) -> Self {
        Redacted::new(secret)
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_PLACEHOLDER)
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_PLACEHOLDER)
    }
}

/// Serializes as the literal string `"[redacted]"` for any `T` (see the type
/// docs for why this is implemented rather than forbidden).
impl<T> Serialize for Redacted<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(REDACTED_PLACEHOLDER)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "hunter2-super-secret-token-XYZZY";

    #[test]
    fn debug_never_contains_the_secret() {
        let secret = Redacted::new(SECRET.to_string());
        let debug = format!("{secret:?}");
        let debug_alternate = format!("{secret:#?}");
        assert_eq!(debug, REDACTED_PLACEHOLDER);
        assert_eq!(debug_alternate, REDACTED_PLACEHOLDER);
        assert!(!debug.contains(SECRET));
        assert!(!debug_alternate.contains(SECRET));
    }

    #[test]
    fn display_never_contains_the_secret() {
        let secret = Redacted::new(SECRET.to_string());
        let display = format!("{secret}");
        assert_eq!(display, REDACTED_PLACEHOLDER);
        assert!(!display.contains(SECRET));
    }

    #[test]
    fn derived_debug_on_containing_struct_never_leaks() {
        #[derive(Debug)]
        #[allow(dead_code)] // fields exist to be formatted by derived Debug
        struct CredentialGrant {
            scope: String,
            token: Redacted<String>,
        }

        let grant = CredentialGrant {
            scope: "aws-dev".to_string(),
            token: Redacted::new(SECRET.to_string()),
        };
        let debug = format!("{grant:?}");
        assert!(debug.contains("aws-dev"));
        assert!(debug.contains(REDACTED_PLACEHOLDER));
        assert!(!debug.contains(SECRET));
    }

    #[test]
    fn serializes_to_placeholder_only() {
        let secret = Redacted::new(SECRET.to_string());
        let json = serde_json::to_string(&secret).unwrap();
        assert_eq!(json, format!("\"{REDACTED_PLACEHOLDER}\""));
        assert!(!json.contains(SECRET));
    }

    #[test]
    fn serialization_inside_a_struct_never_leaks() {
        #[derive(Serialize)]
        struct IpcReply {
            status: &'static str,
            token: Redacted<String>,
        }

        let reply = IpcReply {
            status: "issued",
            token: Redacted::new(SECRET.to_string()),
        };
        let json = serde_json::to_string(&reply).unwrap();
        assert_eq!(json, r#"{"status":"issued","token":"[redacted]"}"#);
        assert!(!json.contains(SECRET));
    }

    #[test]
    fn non_string_secrets_also_serialize_to_placeholder() {
        let key_bytes = Redacted::new(vec![0x8f_u8, 0x03, 0x42]);
        assert_eq!(
            serde_json::to_string(&key_bytes).unwrap(),
            format!("\"{REDACTED_PLACEHOLDER}\"")
        );
    }

    #[test]
    fn explicit_access_still_works() {
        let secret = Redacted::new(SECRET.to_string());
        assert_eq!(secret.expose_secret(), SECRET);
        assert_eq!(secret.into_inner(), SECRET);
    }
}
