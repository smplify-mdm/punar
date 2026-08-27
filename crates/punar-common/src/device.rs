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
