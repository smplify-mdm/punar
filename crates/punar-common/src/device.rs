//! Read-only hardware facts and the small device-class vocabulary.
//!
//! A device class is an observed input to Punar's defaults. It is not a
//! capability: RAM, CPUs, batteries and displays cannot be applied. Keeping
//! these types in `punar-common` gives the daemon, CLI and shell-facing status
//! contract one closed vocabulary without giving any of them a second
//! classifier.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The three experience classes from `docs/design/device-classes.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceClass {
    Workstation,
    Laptop,
    Appliance,
}

impl DeviceClass {
    pub const ALL: [DeviceClass; 3] = [
        DeviceClass::Workstation,
        DeviceClass::Laptop,
        DeviceClass::Appliance,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            DeviceClass::Workstation => "workstation",
            DeviceClass::Laptop => "laptop",
            DeviceClass::Appliance => "appliance",
        }
    }
}

impl fmt::Display for DeviceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parsing is deliberately closed: the force seam used by CI cannot create a
/// fourth, untested class with a free-form string.
impl FromStr for DeviceClass {
    type Err = DeviceClassParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "workstation" => Ok(DeviceClass::Workstation),
            "laptop" => Ok(DeviceClass::Laptop),
            "appliance" => Ok(DeviceClass::Appliance),
            _ => Err(DeviceClassParseError(value.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceClassParseError(String);

impl fmt::Display for DeviceClassParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown device class {:?}; expected workstation, laptop, or appliance",
            self.0
        )
    }
}

impl std::error::Error for DeviceClassParseError {}

/// Facts used by the classifier. Optional booleans distinguish a measured
/// absence from an unreadable hardware interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceFacts {
    pub memory_mib: u64,
    pub logical_cores: u32,
    pub battery_present: Option<bool>,
    pub display_connected: Option<bool>,
}

/// Whether the reported class came from hardware or the typed CI seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceClassSource {
    Observed,
    Forced,
}

/// The daemon's complete, explainable device-class result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceProfile {
    pub class: DeviceClass,
    pub source: DeviceClassSource,
    pub facts: DeviceFacts,
}

// ---------------------------------------------------------------------------
// Posture, hardware and power: one definition for the managed inventory an
// organization receives and the `device.posture` read the person at the device
// makes, so the two can never describe the same machine differently.
// ---------------------------------------------------------------------------

/// Posture: states, never values. `None` is "could not be established" and
/// reaches the organization as `null`, never as a guessed `false`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Posture {
    pub secure_boot: Option<bool>,
    pub uefi: Option<bool>,
    pub tpm_present: Option<bool>,
    pub tpm_version: Option<String>,
    /// SPEC section 1.22: a simulated Secure Boot or TPM must be labelled as
    /// such, and this is the label.
    pub is_virtual: Option<bool>,
    pub virtualization: Option<String>,
    /// Every data path (`/var`, `/home`) proven LUKS2 by
    /// [`crate::storage`]: the one encryption answer on the device.
    pub disk_encryption_enabled: Option<bool>,
    pub firewall_enabled: Option<bool>,
    pub firewall: Option<String>,
    pub os_patch_status: PatchStatus,
    pub reboot_required: Option<bool>,
}

/// The console's closed patch vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PatchStatus {
    UpToDate,
    UpdatesAvailable,
    Unknown,
}

/// Device facts, read once per boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hardware {
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub bios_version: Option<String>,
    pub cpu_model: Option<String>,
    pub cpu_vendor: Option<String>,
    pub cpu_cores: Option<u32>,
    pub cpu_threads: Option<u32>,
    pub memory_total_bytes: Option<u64>,
    /// Rounded to whole gigabytes: a btrfs size moves by a few blocks as
    /// chunks are allocated, and an unrounded size would change the
    /// inventory's hash, and resend it, for no fact anyone needs.
    pub device_capacity_bytes: Option<u64>,
    pub root_filesystem_type: Option<String>,
    pub battery_present: Option<bool>,
}

/// The device's batteries, found by the classifier's rule: a
/// `power_supply` entry named `BAT…`, or one whose `type` is Battery.
/// Local only: the managed inventory carries `battery_present`, never this.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePower {
    pub batteries: Vec<Battery>,
}

/// One battery as the kernel reports it. `None` is "not reported".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Battery {
    /// The `power_supply` entry, like `BAT0`.
    pub name: String,
    /// 0 to 100.
    pub capacity_percent: Option<u8>,
    /// The kernel's word: Charging, Discharging, Full, Not charging, Unknown.
    pub status: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_wire_spellings_are_closed() {
        for class in DeviceClass::ALL {
            let spelling = class.as_str();
            assert_eq!(spelling.parse::<DeviceClass>().unwrap(), class);
            assert_eq!(
                serde_json::to_string(&class).unwrap(),
                format!("\"{spelling}\"")
            );
        }
        assert!("desktop".parse::<DeviceClass>().is_err());
        assert!(serde_json::from_str::<DeviceClass>("\"desktop\"").is_err());
    }

    #[test]
    fn profile_round_trips_with_unknown_observations() {
        let profile = DeviceProfile {
            class: DeviceClass::Appliance,
            source: DeviceClassSource::Observed,
            facts: DeviceFacts {
                memory_mib: 0,
                logical_cores: 0,
                battery_present: None,
                display_connected: None,
            },
        };
        let back: DeviceProfile =
            serde_json::from_str(&serde_json::to_string(&profile).unwrap()).unwrap();
        assert_eq!(back, profile);
    }
}
