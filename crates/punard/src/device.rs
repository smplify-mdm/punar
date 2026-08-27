//! Linux hardware observation and device classification.
//!
//! The classifier reads facts only. It has no backend `apply()` method and no
//! hardware/model-name table: equal measured machines classify equally on
//! x86_64 and arm64. Missing facts choose the conservative `appliance` class
//! and remain visible as unknowns in the returned profile.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use punar_common::{DeviceClass, DeviceClassSource, DeviceFacts, DeviceProfile};

const MIB_IN_KIB: u64 = 1024;
const LAPTOP_MEMORY_MIB: u64 = 8 * 1024;
const WORKSTATION_MEMORY_MIB: u64 = 16 * 1024;
const WORKSTATION_LOGICAL_CORES: u32 = 8;

/// Injectable Linux observation paths. Production uses procfs/sysfs; tests
/// use ordinary temporary directories containing the same tiny text files.
#[derive(Debug, Clone)]
pub struct DeviceSources {
    pub meminfo: PathBuf,
    pub cpu_online: PathBuf,
    pub power_supply_dir: PathBuf,
    pub drm_dir: PathBuf,
}

impl Default for DeviceSources {
    fn default() -> Self {
        Self {
            meminfo: PathBuf::from("/proc/meminfo"),
            cpu_online: PathBuf::from("/sys/devices/system/cpu/online"),
            power_supply_dir: PathBuf::from("/sys/class/power_supply"),
            drm_dir: PathBuf::from("/sys/class/drm"),
        }
    }
}

/// Observe facts and resolve the class. `forced` is the typed CI seam; facts
/// are still observed and returned so a forced result can never masquerade as
/// hardware detection.
pub fn observe_profile(sources: &DeviceSources, forced: Option<DeviceClass>) -> DeviceProfile {
    let facts = DeviceFacts {
        memory_mib: memory_mib(&sources.meminfo).unwrap_or(0),
        logical_cores: logical_cores(&sources.cpu_online).unwrap_or(0),
        battery_present: directory_has_battery(&sources.power_supply_dir).ok(),
        display_connected: directory_has_connected_display(&sources.drm_dir).ok(),
    };
    DeviceProfile {
        class: forced.unwrap_or_else(|| classify(&facts)),
        source: if forced.is_some() {
            DeviceClassSource::Forced
        } else {
            DeviceClassSource::Observed
        },
        facts,
    }
}

/// The deliberately small decision tree from device-classes.md §3.
pub fn classify(facts: &DeviceFacts) -> DeviceClass {
    if facts.memory_mib < LAPTOP_MEMORY_MIB || facts.display_connected != Some(true) {
        return DeviceClass::Appliance;
    }
    if facts.memory_mib >= WORKSTATION_MEMORY_MIB
        && facts.logical_cores >= WORKSTATION_LOGICAL_CORES
        && facts.battery_present == Some(false)
    {
        return DeviceClass::Workstation;
    }
    DeviceClass::Laptop
}

fn memory_mib(path: &Path) -> io::Result<u64> {
    let text = fs::read_to_string(path)?;
    let kib = text
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|tail| tail.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "MemTotal is absent"))?;
    Ok(kib / MIB_IN_KIB)
}

fn logical_cores(path: &Path) -> io::Result<u32> {
    let text = fs::read_to_string(path)?;
    let mut count = 0u32;
    for segment in text.trim().split(',') {
        let mut bounds = segment.split('-');
        let first = bounds
            .next()
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid CPU range"))?;
        let last = match bounds.next() {
            Some(value) => value
                .parse::<u32>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid CPU range"))?,
            None => first,
        };
        if bounds.next().is_some() || last < first {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid CPU range",
            ));
        }
        count = count
            .checked_add(last - first + 1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "CPU count overflow"))?;
    }
    if count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CPU set is empty",
        ));
    }
    Ok(count)
}

fn directory_has_battery(path: &Path) -> io::Result<bool> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with("BAT") {
            return Ok(true);
        }
        if fs::read_to_string(entry.path().join("type"))
            .is_ok_and(|value| value.trim().eq_ignore_ascii_case("battery"))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn directory_has_connected_display(path: &Path) -> io::Result<bool> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let status = entry.path().join("status");
        if fs::read_to_string(status).is_ok_and(|value| value.trim() == "connected") {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn facts(memory_mib: u64, cores: u32, battery: bool, display: bool) -> DeviceFacts {
        DeviceFacts {
            memory_mib,
            logical_cores: cores,
            battery_present: Some(battery),
            display_connected: Some(display),
        }
    }

    #[test]
    fn every_class_has_a_measured_branch() {
        assert_eq!(
            classify(&facts(32 * 1024, 16, false, true)),
            DeviceClass::Workstation
        );
        assert_eq!(
            classify(&facts(16 * 1024, 4, false, true)),
            DeviceClass::Laptop,
            "a displayed 16 GiB four-core Pi is legitimately laptop-shaped"
        );
        assert_eq!(
            classify(&facts(4 * 1024, 4, false, true)),
            DeviceClass::Appliance
        );
        assert_eq!(
            classify(&facts(32 * 1024, 16, false, false)),
            DeviceClass::Appliance,
            "headless always means appliance"
        );
    }

    #[test]
    fn unknown_safety_relevant_facts_choose_appliance() {
        let mut observed = facts(32 * 1024, 16, false, true);
        observed.display_connected = None;
        assert_eq!(classify(&observed), DeviceClass::Appliance);
        observed.display_connected = Some(true);
        observed.battery_present = None;
        assert_eq!(classify(&observed), DeviceClass::Laptop);
    }

    #[test]
    fn linux_text_interfaces_are_observed_without_model_names() {
        let dir = std::env::temp_dir().join(format!("punard-device-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let meminfo = dir.join("meminfo");
        let cpu_online = dir.join("online");
        let power = dir.join("power");
        let drm = dir.join("drm");
        fs::write(&meminfo, "MemTotal:       16777216 kB\nMemFree: 1 kB\n").unwrap();
        fs::write(&cpu_online, "0-3,8-11\n").unwrap();
        fs::create_dir_all(power.join("AC")).unwrap();
        fs::write(power.join("AC/type"), "Mains\n").unwrap();
        fs::create_dir_all(drm.join("card0-HDMI-A-1")).unwrap();
        fs::write(drm.join("card0-HDMI-A-1/status"), "connected\n").unwrap();

        let profile = observe_profile(
            &DeviceSources {
                meminfo,
                cpu_online,
                power_supply_dir: power,
                drm_dir: drm,
            },
            None,
        );
        assert_eq!(profile.class, DeviceClass::Workstation);
        assert_eq!(profile.source, DeviceClassSource::Observed);
        assert_eq!(profile.facts.memory_mib, 16 * 1024);
        assert_eq!(profile.facts.logical_cores, 8);
        assert_eq!(profile.facts.battery_present, Some(false));
        assert_eq!(profile.facts.display_connected, Some(true));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn forced_class_is_typed_and_cannot_hide_observed_facts() {
        let missing = DeviceSources {
            meminfo: PathBuf::from("/definitely/missing/meminfo"),
            cpu_online: PathBuf::from("/definitely/missing/online"),
            power_supply_dir: PathBuf::from("/definitely/missing/power"),
            drm_dir: PathBuf::from("/definitely/missing/drm"),
        };
        for class in DeviceClass::ALL {
            let profile = observe_profile(&missing, Some(class));
            assert_eq!(profile.class, class);
            assert_eq!(profile.source, DeviceClassSource::Forced);
            assert_eq!(profile.facts.memory_mib, 0);
            assert_eq!(profile.facts.display_connected, None);
        }
    }
}
