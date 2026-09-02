//! Read-only, evidence-backed system update status.
//!
//! This module does not fetch metadata and cannot write a slot. It translates
//! immutable release identity, the kernel/firmware-selected slot, the durable
//! pending record and the health unit's report into `update.status`. Missing or
//! malformed evidence is reported as unknown; it is never replaced with demo
//! data or a guessed version.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use punar_common::update::{
    BrowserUpdateStatus, CurrentReleaseStatus, DesiredReleaseState, DesiredReleaseStatus,
    RollbackState, RollbackStatus, UpdateChannel, UpdateChannelStatus, UpdateHealthSignals,
    UpdateHealthState, UpdateHealthStatus, UpdateSlot, UpdateStatusResult,
};
use serde::Deserialize;

use crate::install::{ROOT_A_PARTUUID, ROOT_B_PARTUUID};
use crate::pi_update::{PendingPiUpdate, PiBootObservation, PiSlot};
use crate::update_transaction::PendingUefiUpdate;

const SMALL_FILE_MAX: u64 = 64 * 1024;
const PACKAGE_DB_MAX: u64 = 32 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct UpdateStatusSources {
    pub os_release: PathBuf,
    pub cmdline: PathBuf,
    pub pi_boot_partition: PathBuf,
    pub pi_tryboot: PathBuf,
    pub health_report: PathBuf,
    pub pending_pi: PathBuf,
    pub pending_uefi: PathBuf,
    pub channel_preference: PathBuf,
    pub dpkg_status: PathBuf,
    pub pacman_local: PathBuf,
}

impl Default for UpdateStatusSources {
    fn default() -> Self {
        Self {
            os_release: PathBuf::from("/etc/os-release"),
            cmdline: PathBuf::from("/proc/cmdline"),
            pi_boot_partition: PathBuf::from("/proc/device-tree/chosen/bootloader/partition"),
            pi_tryboot: PathBuf::from("/proc/device-tree/chosen/bootloader/tryboot"),
            health_report: PathBuf::from("/run/punar/update-health.json"),
            pending_pi: PathBuf::from("/var/lib/punar/update/pending-pi.json"),
            pending_uefi: PathBuf::from("/var/lib/punar/update/pending-uefi.json"),
            channel_preference: PathBuf::from("/var/lib/punar/update/channel"),
            dpkg_status: PathBuf::from("/var/lib/dpkg/status"),
            pacman_local: PathBuf::from("/var/lib/pacman/local"),
        }
    }
}

pub struct UpdateStatusEngine {
    sources: UpdateStatusSources,
}

impl UpdateStatusEngine {
    pub fn new(sources: UpdateStatusSources) -> Self {
        Self { sources }
    }

    pub fn status(&self) -> UpdateStatusResult {
        let release = read_os_release(&self.sources.os_release);
        let (slot, tryboot, slot_reason) = self.observe_slot();
        let current_version = release
            .as_ref()
            .and_then(|fields| {
                fields
                    .get("IMAGE_VERSION")
                    .or_else(|| fields.get("VERSION_ID"))
            })
            .cloned();
        let snapshot_pin = release
            .as_ref()
            .and_then(|fields| fields.get("PUNAR_SNAPSHOT_PIN"))
            .cloned();
        let image_id = release
            .as_ref()
            .and_then(|fields| fields.get("IMAGE_ID").or_else(|| fields.get("ID")))
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let pending = if self.sources.pi_boot_partition.exists() {
            read_pending_pi(&self.sources.pending_pi)
        } else {
            read_pending_uefi(&self.sources.pending_uefi)
        };
        let desired = match &pending {
            PendingRead::Valid {
                version, candidate, ..
            } => DesiredReleaseStatus {
                version: Some(version.to_string()),
                slot: Some(*candidate),
                state: DesiredReleaseState::Staged,
                reason: None,
            },
            PendingRead::Invalid(reason) => DesiredReleaseStatus {
                version: None,
                slot: None,
                state: DesiredReleaseState::Unknown,
                reason: Some(reason.clone()),
            },
            PendingRead::Absent => DesiredReleaseStatus {
                version: None,
                slot: None,
                state: DesiredReleaseState::Unknown,
                reason: Some(
                    "no verified channel check or staged release is recorded on this device"
                        .to_string(),
                ),
            },
        };

        let rollback = match (&pending, slot, tryboot) {
            (
                PendingRead::Valid {
                    previous,
                    candidate,
                    ..
                },
                current,
                Some(true),
            ) if current == *candidate => RollbackStatus {
                state: RollbackState::Available,
                target_version: None,
                target_slot: Some(*previous),
                rollback_unavailable_reason: None,
            },
            (PendingRead::Invalid(reason), _, _) => RollbackStatus {
                state: RollbackState::Unavailable,
                target_version: None,
                target_slot: None,
                rollback_unavailable_reason: Some(reason.clone()),
            },
            (PendingRead::Valid { previous, .. }, _, _) => RollbackStatus {
                state: RollbackState::Available,
                target_version: None,
                target_slot: Some(*previous),
                rollback_unavailable_reason: None,
            },
            _ => RollbackStatus {
                state: RollbackState::None,
                target_version: None,
                target_slot: None,
                rollback_unavailable_reason: Some(
                    "no previously booted and blessed release is recorded".to_string(),
                ),
            },
        };

        let (channel, channel_reason) = read_channel(&self.sources.channel_preference);
        let browser_version =
            chromium_version(&self.sources.dpkg_status, &self.sources.pacman_local);
        let browser_reason = browser_version
            .is_none()
            .then(|| "Chromium is not present in a supported local package database".to_string());

        UpdateStatusResult {
            v: 1,
            image_id,
            current: CurrentReleaseStatus {
                version: current_version.clone(),
                slot,
                blessed: tryboot.map(|value| !value),
                booted_at: None,
                snapshot_pin: snapshot_pin.clone(),
                reason: combine_reasons(
                    current_version
                        .is_none()
                        .then_some("the image does not publish a release version"),
                    slot_reason.as_deref(),
                ),
            },
            desired,
            channel: UpdateChannelStatus {
                name: channel,
                source: if self.sources.channel_preference.is_file() {
                    "personal-preference".to_string()
                } else {
                    "os-default".to_string()
                },
                policy_ids: vec!["personal-defaults".to_string()],
                metadata_age_seconds: None,
                rollout_bps: None,
                in_cohort: None,
                halted: None,
                reachable: false,
                reason: Some(channel_reason.unwrap_or_else(|| {
                    "no verified channel metadata has been checked on this device".to_string()
                })),
            },
            health: read_health(&self.sources.health_report),
            rollback,
            browser: BrowserUpdateStatus {
                engine: "chromium".to_string(),
                version: browser_version,
                channel: "snapshot".to_string(),
                snapshot_pin,
                pin_source: "running image".to_string(),
                security_channel: None,
                reason: browser_reason,
            },
        }
    }

    fn observe_slot(&self) -> (UpdateSlot, Option<bool>, Option<String>) {
        if self.sources.pi_boot_partition.exists() {
            return match PiBootObservation::read(
                &self.sources.pi_boot_partition,
                &self.sources.pi_tryboot,
            ) {
                Ok(observation) => (
                    update_slot(observation.slot),
                    Some(observation.tryboot),
                    None,
                ),
                Err(error) => (
                    UpdateSlot::Unknown,
                    None,
                    Some(format!(
                        "Raspberry Pi firmware slot evidence is invalid: {error}"
                    )),
                ),
            };
        }
        match read_bounded(&self.sources.cmdline, SMALL_FILE_MAX) {
            Ok(bytes) => {
                let cmdline = String::from_utf8_lossy(&bytes);
                if has_root_partuuid(&cmdline, ROOT_A_PARTUUID) {
                    (UpdateSlot::A, None, None)
                } else if has_root_partuuid(&cmdline, ROOT_B_PARTUUID) {
                    (UpdateSlot::B, None, None)
                } else {
                    (
                        UpdateSlot::Unknown,
                        None,
                        Some("the kernel command line does not identify Punar slot A or B".into()),
                    )
                }
            }
            Err(reason) => (UpdateSlot::Unknown, None, Some(reason)),
        }
    }
}

fn update_slot(slot: PiSlot) -> UpdateSlot {
    match slot {
        PiSlot::A => UpdateSlot::A,
        PiSlot::B => UpdateSlot::B,
    }
}

fn has_root_partuuid(cmdline: &str, partuuid: &str) -> bool {
    cmdline.split_ascii_whitespace().any(|token| {
        token
            .strip_prefix("root=PARTUUID=")
            .is_some_and(|value| value.eq_ignore_ascii_case(partuuid))
    })
}

fn combine_reasons(first: Option<&str>, second: Option<&str>) -> Option<String> {
    match (first, second) {
        (None, None) => None,
        (Some(reason), None) | (None, Some(reason)) => Some(reason.to_string()),
        (Some(first), Some(second)) => Some(format!("{first}; {second}")),
    }
}

pub(crate) fn read_os_release(path: &Path) -> Option<BTreeMap<String, String>> {
    let bytes = read_bounded(path, SMALL_FILE_MAX).ok()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        if !key
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
        {
            continue;
        }
        let value = raw_value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .or_else(|| {
                raw_value
                    .strip_prefix('\'')
                    .and_then(|value| value.strip_suffix('\''))
            })
            .unwrap_or(raw_value);
        if !value.contains(['\n', '\r', '\0']) {
            fields.insert(key.to_string(), value.to_string());
        }
    }
    Some(fields)
}

fn read_channel(path: &Path) -> (UpdateChannel, Option<String>) {
    let Ok(bytes) = read_bounded(path, 32) else {
        return (UpdateChannel::Stable, None);
    };
    match String::from_utf8_lossy(&bytes).trim() {
        "stable" => (UpdateChannel::Stable, None),
        "dev" => (UpdateChannel::Dev, None),
        "edge" => (UpdateChannel::Edge, None),
        _ => (
            UpdateChannel::Stable,
            Some("the saved update channel is invalid; no update will be selected".into()),
        ),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthReport {
    schema_version: u8,
    health: HealthSignals,
    waited_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthSignals {
    boot_completed: bool,
    control_plane_answers: bool,
    desktop_ready: bool,
    capabilities_verified: bool,
}

fn read_health(path: &Path) -> UpdateHealthStatus {
    let unknown = |reason: String| UpdateHealthStatus {
        state: UpdateHealthState::Unknown,
        signals: UpdateHealthSignals {
            boot: UpdateHealthState::Unknown,
            services: UpdateHealthState::Unknown,
            session: UpdateHealthState::Unknown,
            capabilities: UpdateHealthState::Unknown,
        },
        evaluated_at: None,
        reason: Some(reason),
    };
    let bytes = match read_bounded(path, SMALL_FILE_MAX) {
        Ok(bytes) => bytes,
        Err(reason) => return unknown(reason),
    };
    let report: HealthReport = match serde_json::from_slice(&bytes) {
        Ok(report) => report,
        Err(error) => return unknown(format!("the update health report is invalid: {error}")),
    };
    if report.schema_version != 1 || report.waited_seconds > 3600 {
        return unknown("the update health report has an unsupported shape".into());
    }
    let signal = |value| {
        if value {
            UpdateHealthState::Pass
        } else {
            UpdateHealthState::Fail
        }
    };
    let signals = UpdateHealthSignals {
        boot: signal(report.health.boot_completed),
        services: signal(report.health.control_plane_answers),
        session: signal(report.health.desktop_ready),
        capabilities: signal(report.health.capabilities_verified),
    };
    let passed = [
        report.health.boot_completed,
        report.health.control_plane_answers,
        report.health.desktop_ready,
        report.health.capabilities_verified,
    ]
    .into_iter()
    .filter(|value| *value)
    .count();
    UpdateHealthStatus {
        state: match passed {
            4 => UpdateHealthState::Pass,
            0 => UpdateHealthState::Fail,
            _ => UpdateHealthState::Partial,
        },
        signals,
        evaluated_at: None,
        reason: None,
    }
}

enum PendingRead {
    Absent,
    Valid {
        version: punar_common::update::ReleaseVersion,
        previous: UpdateSlot,
        candidate: UpdateSlot,
    },
    Invalid(String),
}

fn read_pending_pi(path: &Path) -> PendingRead {
    if !path.exists() {
        return PendingRead::Absent;
    }
    let bytes = match read_bounded(path, SMALL_FILE_MAX) {
        Ok(bytes) => bytes,
        Err(reason) => return PendingRead::Invalid(reason),
    };
    match serde_json::from_slice(&bytes) {
        Ok::<PendingPiUpdate, _>(pending) => PendingRead::Valid {
            version: pending.version,
            previous: update_slot(pending.previous_slot),
            candidate: update_slot(pending.candidate_slot),
        },
        Err(error) => PendingRead::Invalid(format!(
            "the durable Raspberry Pi update record is invalid: {error}"
        )),
    }
}

fn read_pending_uefi(path: &Path) -> PendingRead {
    if !path.exists() {
        return PendingRead::Absent;
    }
    let bytes = match read_bounded(path, SMALL_FILE_MAX) {
        Ok(bytes) => bytes,
        Err(reason) => return PendingRead::Invalid(reason),
    };
    match serde_json::from_slice::<PendingUefiUpdate>(&bytes) {
        Ok(pending)
            if pending.schema_version == 1
                && pending.previous_slot != pending.candidate_slot
                && pending.previous_slot != UpdateSlot::Unknown
                && pending.candidate_slot != UpdateSlot::Unknown =>
        {
            PendingRead::Valid {
                version: pending.version,
                previous: pending.previous_slot,
                candidate: pending.candidate_slot,
            }
        }
        Ok(_) => {
            PendingRead::Invalid("the durable UEFI update record is internally inconsistent".into())
        }
        Err(error) => PendingRead::Invalid(format!(
            "the durable UEFI update record is invalid: {error}"
        )),
    }
}

fn chromium_version(dpkg_status: &Path, pacman_local: &Path) -> Option<String> {
    if let Ok(bytes) = read_bounded(dpkg_status, PACKAGE_DB_MAX) {
        let text = String::from_utf8_lossy(&bytes);
        for paragraph in text.split("\n\n") {
            let mut package = None;
            let mut version = None;
            let mut installed = false;
            for line in paragraph.lines() {
                if let Some(value) = line.strip_prefix("Package: ") {
                    package = Some(value);
                } else if let Some(value) = line.strip_prefix("Version: ") {
                    version = Some(value);
                } else if line == "Status: install ok installed" {
                    installed = true;
                }
            }
            if installed
                && matches!(package, Some("chromium" | "chromium-browser"))
                && let Some(version) = version
            {
                return Some(version.to_string());
            }
        }
    }
    let entries = fs::read_dir(pacman_local).ok()?;
    for entry in entries.flatten() {
        let desc = entry.path().join("desc");
        let Ok(bytes) = read_bounded(&desc, SMALL_FILE_MAX) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        if pacman_field(&text, "NAME") == Some("chromium") {
            return pacman_field(&text, "VERSION").map(str::to_string);
        }
    }
    None
}

fn pacman_field<'a>(text: &'a str, field: &str) -> Option<&'a str> {
    let marker = format!("%{field}%");
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if line == marker {
            return lines.next().filter(|value| !value.is_empty());
        }
    }
    None
}

pub(crate) fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("{} is unavailable: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(format!("{} is not a bounded regular file", path.display()));
    }
    fs::read(path).map_err(|error| format!("{} could not be read: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "punar-update-status-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn sources(root: &Path) -> UpdateStatusSources {
        UpdateStatusSources {
            os_release: root.join("os-release"),
            cmdline: root.join("cmdline"),
            pi_boot_partition: root.join("pi-partition"),
            pi_tryboot: root.join("pi-tryboot"),
            health_report: root.join("health.json"),
            pending_pi: root.join("pending-pi.json"),
            pending_uefi: root.join("pending-uefi.json"),
            channel_preference: root.join("channel"),
            dpkg_status: root.join("dpkg-status"),
            pacman_local: root.join("pacman-local"),
        }
    }

    #[test]
    fn status_reports_only_local_evidence_and_explicit_unknowns() {
        let root = fixture_root("known");
        let paths = sources(&root);
        fs::write(
            &paths.os_release,
            "ID=punar\nIMAGE_ID=punar-desktop\nVERSION_ID=2026.08.30.1\nPUNAR_SNAPSHOT_PIN=20260820T000000Z\n",
        )
        .unwrap();
        fs::write(
            &paths.cmdline,
            format!("quiet root=PARTUUID={ROOT_A_PARTUUID} rw\n"),
        )
        .unwrap();
        fs::write(
            &paths.health_report,
            r#"{"schema_version":1,"health":{"boot_completed":true,"control_plane_answers":true,"desktop_ready":true,"capabilities_verified":true},"waited_seconds":4}"#,
        )
        .unwrap();
        fs::write(
            &paths.dpkg_status,
            "Package: chromium\nStatus: install ok installed\nVersion: 151.0.1-1\n\n",
        )
        .unwrap();

        let status = UpdateStatusEngine::new(paths).status();
        assert_eq!(status.image_id, "punar-desktop");
        assert_eq!(status.current.version.as_deref(), Some("2026.08.30.1"));
        assert_eq!(status.current.slot, UpdateSlot::A);
        assert_eq!(status.health.state, UpdateHealthState::Pass);
        assert_eq!(status.browser.version.as_deref(), Some("151.0.1-1"));
        assert_eq!(status.desired.state, DesiredReleaseState::Unknown);
        assert!(!status.channel.reachable);
        assert_eq!(status.rollback.state, RollbackState::None);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_local_state_never_becomes_a_plausible_update() {
        let root = fixture_root("malformed");
        let paths = sources(&root);
        fs::write(&paths.os_release, "ID=punar\n").unwrap();
        fs::write(&paths.cmdline, "root=/dev/vda2 rw\n").unwrap();
        fs::write(&paths.pending_uefi, b"not-json").unwrap();
        fs::write(&paths.channel_preference, "nightly\n").unwrap();

        let status = UpdateStatusEngine::new(paths).status();
        assert!(status.current.version.is_none());
        assert_eq!(status.current.slot, UpdateSlot::Unknown);
        assert_eq!(status.desired.state, DesiredReleaseState::Unknown);
        assert!(
            status
                .desired
                .reason
                .as_deref()
                .unwrap()
                .contains("invalid")
        );
        assert_eq!(status.rollback.state, RollbackState::Unavailable);
        assert_eq!(status.channel.name, UpdateChannel::Stable);
        assert!(!status.channel.reachable);
        fs::remove_dir_all(root).unwrap();
    }
}
