//! The two bodies punar-smplifyd posts to `POST /devices/{id}/status`: the
//! whole of what an organization's Smplify learns about a device after
//! enrollment. Both are translations of what punard handed over, through a
//! fixed allowlist: a key reaches Smplify only if this file names it, and
//! nothing here reads the device. The agent's own build constants are the one
//! addition, and they describe the agent, not the device. The exact keys per
//! tier, and what is never sent, are the visibility manifest
//! (docs/development/smplify-enrollment.md section 3.3).
//!
//! The receiver is Smplify's `LinuxDeviceStatusIngest`, and four of its rules
//! shape the translation:
//!
//! - It reads a boolean or a number only when the JSON value is one; `"true"`
//!   is silently dropped. Every typed field is coerced here.
//! - `null` means "not reported" and keeps what it already stored, so a value
//!   the device does not know is `null`, never a placeholder that would
//!   overwrite a real one.
//! - `software.installedPackages` is a complete snapshot: rows it does not see
//!   are deleted, and one malformed row discards the whole list. The list is
//!   checked row by row, and anything wrong sends it as `null` ("no change"),
//!   never a shorter list.
//! - It stores every `systemInfo` section it receives verbatim. `network` and
//!   `identity` are therefore never composed: an empty section is still a
//!   section, and the one that is not written cannot grow a field later.
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

/// The application list is a complete snapshot, so it is never cut: longer
/// than this, it is sent as `null`. punard applies the same cap before it
/// hands the inventory over; this one does not trust that it did.
pub const MAX_PACKAGES: usize = 2000;
/// Half of punard's 1 MiB request line to this agent. Over it, the list is
/// sent as `null` and the rest of the body, whose every field is clamped, is
/// far below it.
pub const MAX_INVENTORY_BODY_BYTES: usize = 512 * 1024;
/// The receiving columns' widths, in characters. Smplify writes the typed
/// ones inside the transaction that stores the whole report, so a value one
/// character too long would fail the entire write, not just its own column.
/// Application rows: `name` 255, `version` 100.
const MAX_NAME_CHARS: usize = 255;
const MAX_VERSION_CHARS: usize = 100;
/// `device__model` and `device__model_name` (from `modelName`),
/// `device__os_version`, and `device__version` (from `kernelRelease`).
const MAX_SHORT_TEXT_CHARS: usize = 100;
/// `device__os_name`.
const MAX_OS_NAME_CHARS: usize = 128;
/// `device__cpu_model`, and the width used for text kept only in Smplify's
/// JSON copy of the report.
const MAX_TEXT_CHARS: usize = 255;
const MAX_TOKEN_CHARS: usize = 32;
const MAX_SERIAL_CHARS: usize = 128;

/// The sources punard reports. A row from any other is a row this agent
/// cannot vouch for, and it withholds the list rather than guess.
const PACKAGE_SOURCES: [&str; 3] = ["punar-image", "flatpak", "punar-vendor"];
/// The console's patch vocabulary. `"unknown"` is one of its words, not a
/// placeholder: sending `null` instead would leave an old "up-to-date"
/// standing after the evidence for it expired.
const PATCH_STATUSES: [&str; 3] = ["up-to-date", "updates-available", "unknown"];
const FIREWALLS: [&str; 1] = ["nftables"];
const TPM_VERSIONS: [&str; 2] = ["2.0", "1.2"];

/// Which agent, and which build of it: named, so a console never mistakes it
/// for Smplify's own Linux agent. The revision and build date are stamped in
/// by an image build that sets `PUNAR_BUILD_REVISION` / `PUNAR_BUILD_DATE`,
/// and are `null` when it did not.
pub const AGENT_VERSION: &str = concat!("punar-smplifyd ", env!("CARGO_PKG_VERSION"));
const BUILD_REVISION: Option<&str> = option_env!("PUNAR_BUILD_REVISION");
const BUILD_DATE: Option<&str> = option_env!("PUNAR_BUILD_DATE");

/// The category-states-only compliance body, flattened into Smplify's
/// `facts` map so it lands in `device_facts` verbatim.
pub fn compliance_status_body(device_id: &str, report: &Value) -> Value {
    let mut facts = Map::new();
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

/// The inventory body: punard's inventory, translated key by key into
/// Smplify's `systemInfo` sections. What punard's inventory carries beyond
/// the keys named below never leaves. punard no longer hands over the
/// hostname (sent once, at `/enroll`) or any capability's observed value
/// (`current_state`: the hostname string, the timezone), and were either
/// handed over, it would not be copied: "category states only" keeps them
/// on the device. Per-capability states travel as `punar_compliance_*` facts
/// in the compliance report.
///
/// The tier is punard's to decide, and it decides twice before this is
/// called: `identifiers` is present only for a device its organization owns,
/// and only then does `hardware.serialNumber` exist here; the application
/// list carries only the image's own applications otherwise.
///
/// On a Punar image the organization manages Punar, not its substrate, so the
/// name is Punar's and the version is the image release (Debian unstable has
/// no VERSION_ID).
pub fn inventory_status_body(device_id: &str, inventory: &Value) -> Value {
    let os = &inventory["os"];
    let posture = &inventory["posture"];
    let hardware = &inventory["hardware"];

    let punar = text(&os["image_id"], MAX_TEXT_CHARS).is_some_and(|id| id.starts_with("punar"));
    let name = if punar {
        Some("Punar OS".to_string())
    } else {
        text(&os["pretty_name"], MAX_OS_NAME_CHARS)
    };
    let mut hardware_section = json!({
        "manufacturer": text(&hardware["manufacturer"], MAX_TEXT_CHARS),
        "modelName": text(&hardware["model_name"], MAX_SHORT_TEXT_CHARS),
        "biosVersion": text(&hardware["bios_version"], MAX_TEXT_CHARS),
        "cpuModel": text(&hardware["cpu_model"], MAX_TEXT_CHARS),
        "cpuVendor": text(&hardware["cpu_vendor"], MAX_TEXT_CHARS),
        "cpuCores": count(&hardware["cpu_cores"], i32::MAX as u64),
        "cpuThreads": count(&hardware["cpu_threads"], i32::MAX as u64),
        "memoryTotalBytes": count(&hardware["memory_total_bytes"], i64::MAX as u64),
        "deviceCapacityBytes": count(&hardware["device_capacity_bytes"], i64::MAX as u64),
        "rootFilesystemType": token(&hardware["root_filesystem_type"]),
        "batteryPresent": boolean(&hardware["battery_present"]),
        "secureBoot": boolean(&posture["secure_boot"]),
        "uefi": boolean(&posture["uefi"]),
        "tpmPresent": boolean(&posture["tpm_present"]),
        "tpmVersion": one_of(&posture["tpm_version"], &TPM_VERSIONS),
        "isVirtual": boolean(&posture["is_virtual"]),
        "virtualization": token(&posture["virtualization"]),
    });
    if inventory.get("identifiers").is_some_and(Value::is_object) {
        hardware_section["serialNumber"] =
            json!(serial(&inventory["identifiers"]["serial_number"]));
    }

    let packages = installed_packages(&inventory["applications"]);
    let mut body = json!({
        "deviceId": device_id,
        "heartbeat": crate::clock::now_rfc3339(),
        "systemInfo": {
            "os": {
                "name": name,
                "version": text(&os["image_version"], MAX_SHORT_TEXT_CHARS)
                    .or_else(|| text(&os["version_id"], MAX_SHORT_TEXT_CHARS)),
                "kernelRelease": text(&inventory["kernel"], MAX_SHORT_TEXT_CHARS),
                "arch": token(&os["architecture"]),
            },
            "hardware": hardware_section,
            "security": {
                "diskEncryptionEnabled": boolean(&posture["disk_encryption_enabled"]),
                "firewallEnabled": boolean(&posture["firewall_enabled"]),
                "firewall": one_of(&posture["firewall"], &FIREWALLS),
                "osPatchStatus": one_of(&posture["os_patch_status"], &PATCH_STATUSES),
                "rebootRequired": boolean(&posture["reboot_required"]),
            },
            "software": {
                "smplifydVersion": AGENT_VERSION,
                "smplifydRevision": BUILD_REVISION.filter(|value| is_revision(value)),
                "smplifydBuildDate": BUILD_DATE.filter(|value| is_build_date(value)),
                // Smplify's own change fingerprint leaves the list out and
                // relies on this hash, so a changed list with an unchanged
                // hash would never be written.
                "installedPackagesHash": packages.as_ref().map(|rows| packages_hash(rows)),
                "installedPackagesCount": packages.as_ref().map(Vec::len),
                "installedPackages": packages,
            },
        },
        // This agent honours no remote command (smplify-enrollment.md
        // section 3), and saying so lets Smplify refuse an administrator's
        // action when it is asked for instead of queueing one that fails.
        "supportedActions": [],
        "facts": {},
    });
    let oversized = serde_json::to_vec(&body)
        .map(|bytes| bytes.len() > MAX_INVENTORY_BODY_BYTES)
        .unwrap_or(true);
    if oversized {
        let software = &mut body["systemInfo"]["software"];
        for key in [
            "installedPackages",
            "installedPackagesHash",
            "installedPackagesCount",
        ] {
            software[key] = Value::Null;
        }
    }
    body
}

/// Every row valid, or no list. A row that is not an object, has no name,
/// carries a version or flag of the wrong type, or comes from a source this
/// agent does not know withholds the whole list: sending the others would
/// delete that row's application from the organization's record.
fn installed_packages(applications: &Value) -> Option<Vec<Value>> {
    let rows = applications.as_array()?;
    if rows.len() > MAX_PACKAGES {
        return None;
    }
    rows.iter().map(package).collect()
}

fn package(row: &Value) -> Option<Value> {
    let row = row.as_object()?;
    let name = clamp(row.get("name")?.as_str()?, MAX_NAME_CHARS)?;
    let display_name = match row.get("display_name") {
        None | Some(Value::Null) => name.clone(),
        Some(Value::String(value)) => clamp(value, MAX_NAME_CHARS).unwrap_or_else(|| name.clone()),
        Some(_) => return None,
    };
    let version = match row.get("version") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => clamp(value, MAX_VERSION_CHARS),
        Some(_) => return None,
    };
    let source = row
        .get("source")?
        .as_str()
        .filter(|source| PACKAGE_SOURCES.contains(source))?;
    let managed = match row.get("managed") {
        None | Some(Value::Null) => false,
        Some(value) => boolean(value)?,
    };
    Some(json!({
        "name": name,
        "displayName": display_name,
        "version": version,
        "source": source,
        "managed": managed,
    }))
}

fn packages_hash(rows: &[Value]) -> String {
    let bytes = serde_json::to_vec(rows).unwrap_or_default();
    Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Text a person could read, with control characters made spaces and cut to
/// the receiving column. Empty, or the substrate's "unknown", is `null`.
fn text(value: &Value, max_chars: usize) -> Option<String> {
    clamp(value.as_str()?, max_chars).filter(|text| !text.eq_ignore_ascii_case("unknown"))
}

/// A machine word: an architecture, a filesystem type, a hypervisor name.
/// Anything else is not one of those, and is `null`.
fn token(value: &Value) -> Option<String> {
    let word = value.as_str()?.trim();
    let valid = !word.is_empty()
        && word.len() <= MAX_TOKEN_CHARS
        && !word.eq_ignore_ascii_case("unknown")
        && word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
    valid.then(|| word.to_string())
}

/// One of a closed vocabulary, or `null`.
fn one_of(value: &Value, allowed: &[&str]) -> Option<String> {
    let word = value.as_str()?.trim();
    allowed.contains(&word).then(|| word.to_string())
}

/// A JSON boolean. The exact strings `"true"` and `"false"` are coerced
/// because Smplify would drop them; nothing else is guessed at.
fn boolean(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(flag) => Some(*flag),
        Value::String(text) => match text.trim() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// A non-negative whole number that fits the receiving column. A string of
/// digits is coerced for the same reason as [`boolean`].
fn count(value: &Value, max: u64) -> Option<u64> {
    let number = match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => {
            let digits = text.trim();
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            digits.parse().ok()
        }
        _ => None,
    }?;
    (number <= max).then_some(number)
}

/// A serial number is printable ASCII or it is not sent: it is an identifier
/// Smplify keeps forever once it has one, so it is never repaired into a
/// different one.
fn serial(value: &Value) -> Option<String> {
    let serial = value.as_str()?.trim();
    let valid = !serial.is_empty()
        && serial.len() <= MAX_SERIAL_CHARS
        && serial
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ');
    valid.then(|| serial.to_string())
}

fn clamp(value: &str, max_chars: usize) -> Option<String> {
    let cleaned: String = value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let clamped: String = cleaned.trim().chars().take(max_chars).collect();
    let clamped = clamped.trim_end();
    (!clamped.is_empty()).then(|| clamped.to_string())
}

/// A source revision: 7 to 64 hex digits, optionally marked `-dirty`.
fn is_revision(value: &str) -> bool {
    let hex = value.strip_suffix("-dirty").unwrap_or(value);
    (7..=64).contains(&hex.len()) && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// A build date: an RFC 3339 date or timestamp, nothing longer.
fn is_build_date(value: &str) -> bool {
    (10..=32).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || b"-:TZ+.".contains(&byte))
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

    fn sorted_keys(value: &Value) -> Vec<&str> {
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap_or_else(|| panic!("not an object: {value}"))
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        keys
    }

    const OS_KEYS: [&str; 4] = ["arch", "kernelRelease", "name", "version"];
    const HARDWARE_KEYS: [&str; 17] = [
        "batteryPresent",
        "biosVersion",
        "cpuCores",
        "cpuModel",
        "cpuThreads",
        "cpuVendor",
        "deviceCapacityBytes",
        "isVirtual",
        "manufacturer",
        "memoryTotalBytes",
        "modelName",
        "rootFilesystemType",
        "secureBoot",
        "tpmPresent",
        "tpmVersion",
        "uefi",
        "virtualization",
    ];
    const SECURITY_KEYS: [&str; 5] = [
        "diskEncryptionEnabled",
        "firewall",
        "firewallEnabled",
        "osPatchStatus",
        "rebootRequired",
    ];
    const SOFTWARE_KEYS: [&str; 6] = [
        "installedPackages",
        "installedPackagesCount",
        "installedPackagesHash",
        "smplifydBuildDate",
        "smplifydRevision",
        "smplifydVersion",
    ];

    fn app(name: &str, source: &str) -> Value {
        json!({
            "name": name, "display_name": format!("{name} app"),
            "version": "1.0", "source": source, "managed": false,
        })
    }

    /// punard's inventory in the shape it really sends, plus everything the
    /// organization must not receive, as a punard that got it wrong would
    /// send it: the hostname, capability values, and a key this agent has
    /// never heard of.
    fn inventory() -> Value {
        json!({
            "os": {
                "id": "debian", "version_id": "unknown",
                "pretty_name": "Debian GNU/Linux forky/sid",
                "image_id": "punar-desktop", "image_version": "2026.09.01.1",
                "architecture": "x86_64",
            },
            "kernel": "6.12.48-punar",
            "hostname": "atlas",
            "capabilities": [
                {"capability": "system.hostname", "supported": true, "current_state": "atlas"},
                {"capability": "time.timezone", "supported": true, "current_state": "Europe/Berlin"},
            ],
            "posture": {
                "secure_boot": true, "uefi": true, "tpm_present": true,
                "tpm_version": "2.0", "is_virtual": false, "virtualization": null,
                "disk_encryption_enabled": true, "firewall_enabled": true,
                "firewall": "nftables", "os_patch_status": "up-to-date",
                "reboot_required": false,
            },
            "hardware": {
                "manufacturer": "LENOVO", "model_name": "21K5CTO1WW",
                "bios_version": "R2AET47W (1.22 )", "cpu_model": "AMD Ryzen 7 PRO 7840U",
                "cpu_vendor": "AuthenticAMD", "cpu_cores": 8, "cpu_threads": 16,
                "memory_total_bytes": 34359738368u64,
                "device_capacity_bytes": 1000000000000u64,
                "root_filesystem_type": "erofs", "battery_present": true,
            },
            "applications": [app("org.punar.Mail", "punar-image")],
            "network": {"primary_ip_address": "10.0.2.15"},
        })
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

    /// The allowlist, as exact key sets: every section Smplify receives and
    /// nothing else, whatever punard's inventory carried beside it.
    #[test]
    fn the_inventory_translates_to_exactly_the_allowlisted_keys() {
        let body = inventory_status_body("dev-1", &inventory());
        assert_eq!(
            sorted_keys(&body),
            [
                "deviceId",
                "facts",
                "heartbeat",
                "supportedActions",
                "systemInfo"
            ]
        );
        assert_eq!(
            sorted_keys(&body["systemInfo"]),
            ["hardware", "os", "security", "software"]
        );
        assert_eq!(sorted_keys(&body["systemInfo"]["os"]), OS_KEYS);
        assert_eq!(sorted_keys(&body["systemInfo"]["hardware"]), HARDWARE_KEYS);
        assert_eq!(sorted_keys(&body["systemInfo"]["security"]), SECURITY_KEYS);
        assert_eq!(sorted_keys(&body["systemInfo"]["software"]), SOFTWARE_KEYS);
        assert_eq!(body["supportedActions"], json!([]));
        assert_eq!(body["facts"], json!({}));

        let os = &body["systemInfo"]["os"];
        assert_eq!(os["name"], "Punar OS");
        assert_eq!(os["version"], "2026.09.01.1");
        assert_eq!(os["kernelRelease"], "6.12.48-punar");
        assert_eq!(os["arch"], "x86_64");
        let hardware = &body["systemInfo"]["hardware"];
        assert_eq!(hardware["modelName"], "21K5CTO1WW");
        assert_eq!(hardware["cpuThreads"], 16);
        assert_eq!(hardware["memoryTotalBytes"], 34359738368u64);
        assert_eq!(hardware["secureBoot"], true);
        assert_eq!(hardware["virtualization"], Value::Null);
        let security = &body["systemInfo"]["security"];
        assert_eq!(security["firewall"], "nftables");
        assert_eq!(security["osPatchStatus"], "up-to-date");
        let software = &body["systemInfo"]["software"];
        assert_eq!(software["smplifydVersion"], AGENT_VERSION);
        assert_eq!(
            software["installedPackages"],
            json!([{
                "name": "org.punar.Mail", "displayName": "org.punar.Mail app",
                "version": "1.0", "source": "punar-image", "managed": false,
            }])
        );
        assert_eq!(software["installedPackagesCount"], 1);
        assert_eq!(
            software["installedPackagesHash"].as_str().map(str::len),
            Some(64)
        );
    }

    /// What never leaves, by value: the hostname, capability values, an
    /// address, and any section Smplify would store verbatim.
    #[test]
    fn nothing_outside_the_allowlist_travels() {
        let text = inventory_status_body("dev-1", &inventory()).to_string();
        for forbidden in ["atlas", "Europe/Berlin", "10.0.2.15", "current_state"] {
            assert!(!text.contains(forbidden), "{forbidden} travelled: {text}");
        }
        for section in ["\"network\"", "\"identity\"", "serialNumber"] {
            assert!(!text.contains(section), "{section} travelled");
        }
    }

    /// The serial number exists only when punard says the organization owns
    /// the device, which it says by sending `identifiers` at all.
    #[test]
    fn the_serial_number_travels_only_with_identifiers() {
        let mut owned = inventory();
        owned["identifiers"] = json!({"serial_number": "PF4ABCDE"});
        let body = inventory_status_body("dev-1", &owned);
        let mut keys = HARDWARE_KEYS.to_vec();
        keys.push("serialNumber");
        keys.sort_unstable();
        assert_eq!(sorted_keys(&body["systemInfo"]["hardware"]), keys);
        assert_eq!(body["systemInfo"]["hardware"]["serialNumber"], "PF4ABCDE");

        // Unknown, or not an identifier at all: null, and never repaired.
        owned["identifiers"] = json!({"serial_number": "PF4\u{1b}[2J"});
        let body = inventory_status_body("dev-1", &owned);
        assert_eq!(body["systemInfo"]["hardware"]["serialNumber"], Value::Null);
        owned["identifiers"] = json!({"serial_number": null});
        let body = inventory_status_body("dev-1", &owned);
        assert_eq!(body["systemInfo"]["hardware"]["serialNumber"], Value::Null);
        // A personal device's inventory carries no identifiers, and a stray
        // serial anywhere else in it is not read.
        let mut personal = inventory();
        personal["hardware"]["serial_number"] = json!("PF4ABCDE");
        personal["serial_number"] = json!("PF4ABCDE");
        let text = inventory_status_body("dev-1", &personal).to_string();
        assert!(!text.contains("PF4ABCDE"), "{text}");
    }

    /// Smplify reads typed columns only from typed JSON, so the translation
    /// never sends a string where a boolean or a number belongs.
    #[test]
    fn typed_fields_are_coerced_or_null() {
        let mut coerced = inventory();
        coerced["posture"]["secure_boot"] = json!("true");
        coerced["posture"]["uefi"] = json!("false");
        coerced["posture"]["tpm_present"] = json!("yes");
        coerced["posture"]["is_virtual"] = json!(1);
        coerced["hardware"]["cpu_cores"] = json!("8");
        coerced["hardware"]["cpu_threads"] = json!(-2);
        coerced["hardware"]["memory_total_bytes"] = json!(8.5);
        coerced["hardware"]["device_capacity_bytes"] = json!(u64::MAX);
        coerced["posture"]["os_patch_status"] = json!("patched!");
        coerced["posture"]["firewall"] = json!("ufw");
        coerced["posture"]["tpm_version"] = json!("2");
        coerced["posture"]["virtualization"] = json!("kvm; rm -rf /");
        coerced["os"]["architecture"] = json!("unknown");
        let body = inventory_status_body("dev-1", &coerced);
        let hardware = &body["systemInfo"]["hardware"];
        assert_eq!(hardware["secureBoot"], json!(true));
        assert_eq!(hardware["uefi"], json!(false));
        assert_eq!(hardware["tpmPresent"], Value::Null);
        assert_eq!(hardware["isVirtual"], Value::Null);
        assert_eq!(hardware["cpuCores"], json!(8));
        assert_eq!(hardware["cpuThreads"], Value::Null);
        assert_eq!(hardware["memoryTotalBytes"], Value::Null);
        assert_eq!(hardware["deviceCapacityBytes"], Value::Null, "past bigint");
        assert_eq!(hardware["tpmVersion"], Value::Null);
        assert_eq!(hardware["virtualization"], Value::Null);
        let security = &body["systemInfo"]["security"];
        assert_eq!(security["osPatchStatus"], Value::Null);
        assert_eq!(security["firewall"], Value::Null);
        assert_eq!(body["systemInfo"]["os"]["arch"], Value::Null);
        for section in ["hardware", "security", "os", "software"] {
            for (key, value) in body["systemInfo"][section].as_object().unwrap() {
                assert!(
                    !matches!(value.as_str(), Some("true" | "false")),
                    "{section}.{key} is a string boolean"
                );
            }
        }
        // "unknown" is the patch vocabulary's own word, and it replaces a
        // stale verdict rather than keeping it.
        coerced["posture"]["os_patch_status"] = json!("unknown");
        let body = inventory_status_body("dev-1", &coerced);
        assert_eq!(body["systemInfo"]["security"]["osPatchStatus"], "unknown");
    }

    /// The shape punard really sends: capability values stay on the device.
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
    /// placeholder that would overwrite what Smplify already stores. A
    /// missing section still sends its keys, each `null`.
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
        assert_eq!(sorted_keys(&body["systemInfo"]["hardware"]), HARDWARE_KEYS);
        assert!(
            body["systemInfo"]["hardware"]
                .as_object()
                .unwrap()
                .values()
                .all(Value::is_null)
        );
        let software = &body["systemInfo"]["software"];
        assert_eq!(software["installedPackages"], Value::Null);
        assert_eq!(software["installedPackagesHash"], Value::Null);
        assert_eq!(software["installedPackagesCount"], Value::Null);
    }

    /// Names and versions are cut to the receiving columns, control
    /// characters become spaces, and an entry's unknown keys are not copied.
    #[test]
    fn package_rows_are_clamped_to_the_receiving_columns() {
        let mut long = inventory();
        long["applications"] = json!([{
            "name": format!("org.example.{}", "n".repeat(400)),
            "display_name": format!("Example\u{7}\n{}", "d".repeat(400)),
            "version": "v".repeat(300),
            "source": "flatpak",
            "managed": "true",
            "install_path": "/home/alice/.local/share/flatpak",
        }]);
        let body = inventory_status_body("dev-1", &long);
        let row = &body["systemInfo"]["software"]["installedPackages"][0];
        assert_eq!(
            sorted_keys(row),
            ["displayName", "managed", "name", "source", "version"]
        );
        assert_eq!(row["name"].as_str().unwrap().chars().count(), 255);
        assert_eq!(row["displayName"].as_str().unwrap().chars().count(), 255);
        assert!(
            row["displayName"]
                .as_str()
                .unwrap()
                .starts_with("Example  d")
        );
        assert_eq!(row["version"].as_str().unwrap().chars().count(), 100);
        assert_eq!(row["managed"], json!(true));
        assert!(!body.to_string().contains("/home"));

        // A name that is all control characters or blank names nothing.
        long["applications"] = json!([{"name": " \u{7} ", "source": "flatpak"}]);
        let body = inventory_status_body("dev-1", &long);
        assert_eq!(
            body["systemInfo"]["software"]["installedPackages"],
            Value::Null
        );
    }

    /// One row Smplify would reject discards its whole snapshot, and a
    /// shorter list would delete the rows left out: so any bad row sends
    /// `null` ("no change"), and so does a list over the cap. Never fewer
    /// rows than punard reported.
    #[test]
    fn a_bad_row_or_too_many_rows_withholds_the_list_never_truncates() {
        let good = app("org.punar.Mail", "punar-image");
        let bad_rows = [
            json!("org.punar.Mail"),
            json!({"display_name": "No name", "source": "flatpak"}),
            json!({"name": 42, "source": "flatpak"}),
            json!({"name": "org.x.Y", "version": 3, "source": "flatpak"}),
            json!({"name": "org.x.Y", "display_name": ["x"], "source": "flatpak"}),
            json!({"name": "org.x.Y", "source": "snap"}),
            json!({"name": "org.x.Y"}),
            json!({"name": "org.x.Y", "source": "flatpak", "managed": "maybe"}),
        ];
        for bad in bad_rows {
            let mut withheld = inventory();
            withheld["applications"] = json!([good.clone(), bad.clone()]);
            let software = &inventory_status_body("dev-1", &withheld)["systemInfo"]["software"];
            assert_eq!(software["installedPackages"], Value::Null, "{bad}");
            assert_eq!(software["installedPackagesCount"], Value::Null, "{bad}");
            assert_eq!(software["installedPackagesHash"], Value::Null, "{bad}");
        }

        let rows = |n: usize| -> Value {
            (0..n)
                .map(|i| app(&format!("org.example.App{i}"), "flatpak"))
                .collect()
        };
        let mut at_cap = inventory();
        at_cap["applications"] = rows(MAX_PACKAGES);
        let software = &inventory_status_body("dev-1", &at_cap)["systemInfo"]["software"];
        assert_eq!(software["installedPackagesCount"], MAX_PACKAGES);
        assert_eq!(
            software["installedPackages"].as_array().map(Vec::len),
            Some(MAX_PACKAGES)
        );
        let mut over_cap = inventory();
        over_cap["applications"] = rows(MAX_PACKAGES + 1);
        let software = &inventory_status_body("dev-1", &over_cap)["systemInfo"]["software"];
        assert_eq!(software["installedPackages"], Value::Null);
        assert_eq!(software["installedPackagesCount"], Value::Null);

        // Absent, or not a list: no change, too.
        let mut absent = inventory();
        absent["applications"] = Value::Null;
        let software = &inventory_status_body("dev-1", &absent)["systemInfo"]["software"];
        assert_eq!(software["installedPackages"], Value::Null);
        absent["applications"] = json!({"org.punar.Mail": "1.0"});
        let software = &inventory_status_body("dev-1", &absent)["systemInfo"]["software"];
        assert_eq!(software["installedPackages"], Value::Null);
    }

    /// Under the row cap but over the byte cap: the list goes out as `null`
    /// and the body fits.
    #[test]
    fn an_oversized_body_withholds_the_list() {
        let mut large = inventory();
        large["applications"] = (0..1900)
            .map(|i| {
                json!({
                    "name": format!("org.example.{i}.{}", "x".repeat(200)),
                    "display_name": "y".repeat(255),
                    "version": "z".repeat(100),
                    "source": "flatpak",
                    "managed": false,
                })
            })
            .collect();
        let body = inventory_status_body("dev-1", &large);
        let software = &body["systemInfo"]["software"];
        assert_eq!(software["installedPackages"], Value::Null);
        assert_eq!(software["installedPackagesCount"], Value::Null);
        assert_eq!(software["installedPackagesHash"], Value::Null);
        assert!(serde_json::to_vec(&body).unwrap().len() <= MAX_INVENTORY_BODY_BYTES);
        assert_eq!(sorted_keys(software), SOFTWARE_KEYS);
    }

    /// The hash names the list: the same rows hash the same, a changed row
    /// changes it, and an empty list is a list (count 0), not "no change".
    #[test]
    fn the_package_hash_follows_the_list() {
        let hash = |apps: Value| {
            let mut inventory = inventory();
            inventory["applications"] = apps;
            inventory_status_body("dev-1", &inventory)["systemInfo"]["software"].clone()
        };
        let one = hash(json!([app("org.punar.Mail", "punar-image")]));
        let same = hash(json!([app("org.punar.Mail", "punar-image")]));
        let other = hash(json!([app("org.punar.Calendar", "punar-image")]));
        assert_eq!(one["installedPackagesHash"], same["installedPackagesHash"]);
        assert_ne!(one["installedPackagesHash"], other["installedPackagesHash"]);
        let empty = hash(json!([]));
        assert_eq!(empty["installedPackages"], json!([]));
        assert_eq!(empty["installedPackagesCount"], 0);
    }

    /// Every text field fits the column Smplify writes it to: one character
    /// over would fail the whole report's write, not only that field.
    #[test]
    fn text_fields_fit_their_columns() {
        let mut long = inventory();
        long["os"]["image_id"] = json!("debian");
        long["os"]["pretty_name"] = json!("P".repeat(300));
        long["os"]["image_version"] = json!("9".repeat(300));
        long["kernel"] = json!("6".repeat(300));
        long["hardware"]["model_name"] = json!("M".repeat(300));
        long["hardware"]["cpu_model"] = json!("C".repeat(300));
        long["hardware"]["manufacturer"] = json!("V".repeat(300));
        let body = inventory_status_body("dev-1", &long);
        let chars = |section: &str, key: &str| {
            body["systemInfo"][section][key]
                .as_str()
                .map(|text| text.chars().count())
        };
        assert_eq!(chars("os", "name"), Some(128), "device__os_name");
        assert_eq!(chars("os", "version"), Some(100), "device__os_version");
        assert_eq!(chars("os", "kernelRelease"), Some(100), "device__version");
        assert_eq!(chars("hardware", "modelName"), Some(100), "device__model");
        assert_eq!(
            chars("hardware", "cpuModel"),
            Some(255),
            "device__cpu_model"
        );
        assert_eq!(chars("hardware", "manufacturer"), Some(255));
        assert!(AGENT_VERSION.chars().count() <= 64, "device__agent_version");
    }

    #[test]
    fn build_stamps_are_validated_before_they_are_sent() {
        assert!(is_revision("c5f0e01"));
        assert!(is_revision(
            "c5f0e018700e4672ff34f5ec4a3ef7b0a29d2bdd-dirty"
        ));
        assert!(!is_revision("main"));
        assert!(!is_revision("c5f0e0"));
        assert!(is_build_date("2026-09-24"));
        assert!(is_build_date("2026-09-24T10:00:00Z"));
        assert!(!is_build_date("yesterday"));
        assert!(AGENT_VERSION.starts_with("punar-smplifyd "));
    }
}
