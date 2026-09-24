//! The managed-device inventory's collectors: security posture, device
//! hardware, the applications built into the image and, only for a device its
//! organization owns, the serial number and every system-wide application
//! (docs/development/smplify-enrollment.md section 3; SPEC sections 24, 50,
//! 54).
//!
//! punard collects; `punar-smplifyd` translates through a fixed allowlist and
//! gathers nothing itself. This module is therefore the whole of what an
//! organization can learn from a device's inventory, and every reader in it is
//! here because the owner decided an organization may have that fact:
//!
//! - **Every managed device.** Posture states, hardware facts, and the
//!   applications the image ships. The image's applications are identical on
//!   every device of a release, so they say nothing about the person using it.
//! - **Organization-owned** — the organization declared it at enrollment and
//!   the person accepted it. Additionally the serial number and every
//!   system-wide application. The caller passes the tier; on a personal
//!   enrollment the applications a person chose are never even read.
//!
//! Never, in any tier, and there is no reader for any of it in this file:
//! anything under `/home` or per user, user Flatpaks, browser or AI data,
//! addresses, network names, Bluetooth, USB history, timezone or location,
//! user and session facts, uptime or usage samples, `/etc/machine-id`, base OS
//! packages, audit contents, processes, secrets.
//!
//! Cost (SPEC section 6.3): hardware and virtualization are read once per
//! daemon, which is once per boot; posture is a handful of sysfs reads per
//! pass; the system Flatpak list is re-read only when the installation
//! changed. Every path is injectable ([`CollectorSources`]), so no test reads
//! the host it runs on.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use punar_common::storage::{self, StorageSources};
use serde::Serialize;
use serde_json::Value;

use crate::device::{DeviceSources, directory_has_battery, logical_cores, memory_kib};
use crate::update_status::StagedRelease;
use crate::util::run_with_timeout;

/// `source` of an application built into the signed image.
pub const SOURCE_IMAGE: &str = "punar-image";
/// `source` of a system-wide Flatpak (organization-owned devices only).
pub const SOURCE_FLATPAK: &str = "flatpak";
/// `source` of a catalog vendor package (organization-owned devices only).
pub const SOURCE_VENDOR: &str = "punar-vendor";

/// The application list is a complete snapshot: the receiving side deletes
/// every row it does not see. It is therefore never truncated. A list longer
/// than this, or one that would push the inventory past
/// [`MAX_INVENTORY_BYTES`], is sent as `null` ("no change") instead.
pub const MAX_APPLICATIONS: usize = 2000;
/// Half the agent's 1 MiB request line, leaving room for its own envelope.
pub const MAX_INVENTORY_BYTES: usize = 512 * 1024;
/// The receiving columns' widths, in characters.
const MAX_NAME_CHARS: usize = 255;
const MAX_VERSION_CHARS: usize = 100;

/// A verified channel check older than this no longer says "up to date".
pub const PATCH_EVIDENCE_MAX_AGE_SECONDS: u64 = 24 * 60 * 60;

const SECURE_BOOT_VARIABLE: &str = "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
const SMALL_FILE_MAX: u64 = 64 * 1024;
const DETECT_VIRT_TIMEOUT: Duration = Duration::from_secs(2);
const FLATPAK_LIST_TIMEOUT: Duration = Duration::from_secs(30);
const BYTES_PER_GB: u64 = 1_000_000_000;

/// Where every fact is read from. Production uses [`Default`]; tests point
/// each field at a fixture tree.
#[derive(Debug, Clone)]
pub struct CollectorSources {
    /// Memory, logical CPUs and batteries: the classifier's own readers.
    pub device: DeviceSources,
    /// `/proc/cpuinfo`, for the CPU's vendor and model strings only.
    pub cpuinfo: PathBuf,
    /// `/sys/devices/system/cpu`, for the physical-core topology.
    pub cpu_dir: PathBuf,
    /// `/sys/class/dmi/id` on firmware with SMBIOS.
    pub dmi_dir: PathBuf,
    /// `/proc/device-tree` on firmware without it (Raspberry Pi).
    pub device_tree_dir: PathBuf,
    /// `/sys/firmware/efi`: present only when the kernel booted through UEFI.
    pub efi_dir: PathBuf,
    /// `/sys/class/tpm`.
    pub tpm_dir: PathBuf,
    /// sysfs and the mount table, for encryption and the root filesystem.
    pub storage: StorageSources,
    /// Every path whose filesystem must be LUKS2 for the disk to count as
    /// encrypted: `/var` and `/home`, the data partition's two subvolumes.
    pub encrypted_paths: Vec<PathBuf>,
    /// The filesystem whose size is the device's storage capacity.
    pub capacity_path: PathBuf,
    /// XDG application directories of the image, highest precedence first.
    pub desktop_entry_dirs: Vec<PathBuf>,
    /// The system Flatpak installation.
    pub flatpak_installation: PathBuf,
    /// `systemd-detect-virt`, fixed argv.
    pub detect_virt_bin: PathBuf,
}

impl Default for CollectorSources {
    fn default() -> Self {
        Self {
            device: DeviceSources::default(),
            cpuinfo: PathBuf::from("/proc/cpuinfo"),
            cpu_dir: PathBuf::from("/sys/devices/system/cpu"),
            dmi_dir: PathBuf::from("/sys/class/dmi/id"),
            device_tree_dir: PathBuf::from("/proc/device-tree"),
            efi_dir: PathBuf::from("/sys/firmware/efi"),
            tpm_dir: PathBuf::from("/sys/class/tpm"),
            storage: StorageSources::default(),
            encrypted_paths: vec![PathBuf::from("/var"), PathBuf::from("/home")],
            capacity_path: PathBuf::from("/var"),
            desktop_entry_dirs: vec![
                PathBuf::from("/usr/local/share/applications"),
                PathBuf::from("/usr/share/applications"),
            ],
            flatpak_installation: PathBuf::from("/var/lib/flatpak"),
            detect_virt_bin: PathBuf::from("/usr/bin/systemd-detect-virt"),
        }
    }
}

/// Posture: states, never values. `None` is "could not be established" and
/// reaches the organization as `null`, never as a guessed `false`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Posture {
    pub secure_boot: Option<bool>,
    pub uefi: Option<bool>,
    pub tpm_present: Option<bool>,
    pub tpm_version: Option<String>,
    /// SPEC section 1.22: a simulated Secure Boot or TPM must be labelled as
    /// such, and this is the label.
    pub is_virtual: Option<bool>,
    pub virtualization: Option<String>,
    pub disk_encryption_enabled: Option<bool>,
    pub firewall_enabled: Option<bool>,
    pub firewall: Option<String>,
    pub os_patch_status: PatchStatus,
    pub reboot_required: Option<bool>,
}

/// The console's closed patch vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PatchStatus {
    UpToDate,
    UpdatesAvailable,
    Unknown,
}

/// What the update engines say about this device's release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatchPosture {
    pub status: PatchStatus,
    pub reboot_required: Option<bool>,
}

/// Device facts, read once per boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

/// One application row, already clamped to the receiving columns.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Application {
    /// A stable identifier: desktop-file id, Flatpak app id or catalog id.
    pub name: String,
    pub display_name: String,
    pub version: Option<String>,
    pub source: &'static str,
    /// Required by the organization's application policy. No policy can
    /// require an application yet, so nothing is managed.
    pub managed: bool,
}

impl Application {
    /// `None` when nothing identifying is left after cleaning — a row the
    /// receiving side would reject, and with it the whole snapshot.
    fn new(
        name: &str,
        display_name: &str,
        version: Option<&str>,
        source: &'static str,
    ) -> Option<Application> {
        let name = clean_text(name, MAX_NAME_CHARS)?;
        let display_name = clean_text(display_name, MAX_NAME_CHARS).unwrap_or_else(|| name.clone());
        Some(Application {
            name,
            display_name,
            version: version.and_then(|value| clean_text(value, MAX_VERSION_CHARS)),
            source,
            managed: false,
        })
    }
}

/// Why the application list went out as `null`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Withheld {
    /// More than [`MAX_APPLICATIONS`] rows.
    TooMany,
    /// The inventory would exceed [`MAX_INVENTORY_BYTES`] with the list.
    TooLarge,
    /// A row could not be represented: sending the rest would delete it.
    Malformed,
    /// The installation could not be read this pass.
    Unreadable,
}

impl Withheld {
    pub fn as_str(self) -> &'static str {
        match self {
            Withheld::TooMany => "too_many_applications",
            Withheld::TooLarge => "inventory_too_large",
            Withheld::Malformed => "malformed_application",
            Withheld::Unreadable => "applications_unreadable",
        }
    }
}

/// Everything one pass collected. The body builder
/// ([`crate::enroll::inventory_body`]) applies the tier again before anything
/// leaves: the collector's gate and the builder's are independent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collected {
    pub architecture: String,
    pub posture: Posture,
    pub hardware: Hardware,
    /// Sorted, deduplicated; `Err` when the list must go out as `null`.
    pub applications: Result<Vec<Application>, Withheld>,
    /// Read only for an organization-owned device.
    pub serial_number: Option<String>,
}

impl Collected {
    /// The rows this tier may send. A personal enrollment carries only what
    /// the image built in, whatever the collector was handed.
    pub fn applications_for(&self, organization_owned: bool) -> Result<Vec<Application>, Withheld> {
        let rows: Vec<Application> = self
            .applications
            .clone()?
            .into_iter()
            .filter(|app| organization_owned || app.source == SOURCE_IMAGE)
            .collect();
        if rows.len() > MAX_APPLICATIONS {
            return Err(Withheld::TooMany);
        }
        Ok(rows)
    }
}

/// Per-pass inputs the daemon already holds.
#[derive(Debug, Clone)]
pub struct PassInputs {
    /// The tier. Only `true` reads the serial number and system-wide apps.
    pub organization_owned: bool,
    pub architecture: String,
    /// This pass's `security.firewall` observation; `None` when no firewall
    /// capability is registered.
    pub firewall_state: Option<Value>,
    pub patch: PatchPosture,
}

/// The running image's identity, asked for once per boot.
#[derive(Debug, Clone, Default)]
pub struct ImageRelease {
    /// `IMAGE_VERSION`: every built-in application's version.
    pub version: Option<String>,
    /// The image browser's package version.
    pub browser_version: Option<String>,
}

struct BootFacts {
    hardware: Hardware,
    is_virtual: Option<bool>,
    virtualization: Option<String>,
    image_applications: Result<Vec<Application>, Withheld>,
}

type InstallationStamp = (Option<FileStamp>, Option<FileStamp>);

/// The last system Flatpak list, and the installation state it was read at.
type FlatpakSnapshot = (InstallationStamp, Result<Vec<Application>, Withheld>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    modified: Option<SystemTime>,
    inode: u64,
    len: u64,
}

/// Holds the per-boot caches. One per daemon.
pub struct InventoryCollector {
    sources: CollectorSources,
    flatpak_bin: PathBuf,
    boot: OnceLock<BootFacts>,
    serial_number: OnceLock<Option<String>>,
    system_flatpaks: Mutex<Option<FlatpakSnapshot>>,
}

impl InventoryCollector {
    pub fn new(sources: CollectorSources, flatpak_bin: PathBuf) -> Self {
        Self {
            sources,
            flatpak_bin,
            boot: OnceLock::new(),
            serial_number: OnceLock::new(),
            system_flatpaks: Mutex::new(None),
        }
    }

    /// Collect one pass. `image` is called at most once per daemon;
    /// `vendor_apps` only for an organization-owned device.
    pub fn collect(
        &self,
        pass: &PassInputs,
        image: impl FnOnce() -> ImageRelease,
        vendor_apps: impl FnOnce() -> Vec<(String, String, Option<String>)>,
    ) -> Collected {
        let boot = self.boot.get_or_init(|| {
            let (is_virtual, virtualization) = virtualization(&self.sources);
            BootFacts {
                hardware: hardware(&self.sources),
                is_virtual,
                virtualization,
                image_applications: image_applications(&self.sources, &image()),
            }
        });

        let firewall_enabled = match pass.firewall_state.as_ref().and_then(Value::as_str) {
            Some("enabled") => Some(true),
            Some("disabled") => Some(false),
            _ => None,
        };
        let uefi = self.sources.efi_dir.is_dir();
        let (tpm_present, tpm_version) = tpm(&self.sources.tpm_dir);
        let posture = Posture {
            secure_boot: secure_boot(&self.sources.efi_dir),
            uefi: Some(uefi),
            tpm_present,
            tpm_version,
            is_virtual: boot.is_virtual,
            virtualization: boot.virtualization.clone(),
            disk_encryption_enabled: disk_encryption(&self.sources),
            firewall_enabled,
            firewall: pass.firewall_state.as_ref().map(|_| "nftables".to_string()),
            os_patch_status: pass.patch.status,
            reboot_required: pass.patch.reboot_required,
        };

        let (applications, serial_number) = if pass.organization_owned {
            let serial = self
                .serial_number
                .get_or_init(|| serial_number(&self.sources))
                .clone();
            let vendor: Vec<Application> = vendor_apps()
                .iter()
                .filter_map(|(id, name, version)| {
                    Application::new(id, name, version.as_deref(), SOURCE_VENDOR)
                })
                .collect();
            let applications = boot.image_applications.clone().and_then(|mut rows| {
                rows.extend(self.system_flatpaks()?);
                rows.extend(vendor);
                Ok(rows)
            });
            (applications, serial)
        } else {
            (boot.image_applications.clone(), None)
        };

        Collected {
            architecture: pass.architecture.clone(),
            posture,
            hardware: boot.hardware.clone(),
            applications: applications.map(|mut rows| {
                // Sorted so an unchanged device hashes the same every pass;
                // one row per identifier and source.
                rows.sort();
                let mut seen = BTreeSet::new();
                rows.retain(|row| seen.insert((row.name.clone(), row.source)));
                rows
            }),
            serial_number,
        }
    }

    /// Every system-wide Flatpak application. The list is re-read only when
    /// Flatpak marked its installation changed (it rewrites `.changed` on
    /// every deploy and removal) or its `app/` directory changed; a pass on
    /// an unchanged installation spawns nothing.
    fn system_flatpaks(&self) -> Result<Vec<Application>, Withheld> {
        let root = &self.sources.flatpak_installation;
        if !root.is_dir() {
            return Ok(Vec::new());
        }
        let stamp = (
            file_stamp(&root.join(".changed")),
            file_stamp(&root.join("app")),
        );
        let mut cache = self.system_flatpaks.lock().unwrap();
        if let Some((cached, rows)) = cache.as_ref() {
            if *cached == stamp {
                return rows.clone();
            }
        }
        let result = run_with_timeout(
            &self.flatpak_bin,
            &[
                "list",
                "--system",
                "--app",
                "--columns=application,name,version,active",
            ],
            FLATPAK_LIST_TIMEOUT,
        );
        let rows = match result {
            Ok(result) if result.success => parse_flatpak_list(&result.stdout),
            // A failed read is retried next pass, not remembered.
            _ => return Err(Withheld::Unreadable),
        };
        *cache = Some((stamp, rows.clone()));
        rows
    }
}

/// Map the update engines' evidence to the console's vocabulary. A staged
/// release waiting for a restart is an update available and a reboot
/// required. Otherwise "up to date" needs a verified channel check
/// ([`crate::update_check::UpdateCheckEngine::verified_update_available`]);
/// without one the status is unknown, never assumed current.
pub fn patch_posture(
    staged: StagedRelease,
    verified_update_available: impl FnOnce() -> Option<bool>,
) -> PatchPosture {
    match staged {
        StagedRelease::AwaitingRestart => PatchPosture {
            status: PatchStatus::UpdatesAvailable,
            reboot_required: Some(true),
        },
        StagedRelease::Unknown => PatchPosture {
            status: PatchStatus::Unknown,
            reboot_required: None,
        },
        StagedRelease::None | StagedRelease::Running => PatchPosture {
            status: match verified_update_available() {
                Some(true) => PatchStatus::UpdatesAvailable,
                Some(false) => PatchStatus::UpToDate,
                None => PatchStatus::Unknown,
            },
            reboot_required: Some(false),
        },
    }
}

// ---------------------------------------------------------------------------
// Posture
// ---------------------------------------------------------------------------

/// The EFI `SecureBoot` variable: four attribute bytes, then one value byte.
/// A machine that did not boot through UEFI did not boot with UEFI Secure
/// Boot; firmware that does not implement it publishes no variable at all.
fn secure_boot(efi_dir: &Path) -> Option<bool> {
    if !efi_dir.is_dir() {
        return Some(false);
    }
    let efivars = efi_dir.join("efivars");
    match read_small(&efivars.join(SECURE_BOOT_VARIABLE)) {
        Ok(bytes) if bytes.len() >= 5 => Some(bytes[4] == 1),
        Ok(_) => None,
        // Absent from a readable efivarfs: the firmware has no Secure Boot.
        // Absent because efivarfs is not mounted: nothing is known.
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::read_dir(&efivars).ok().map(|_| false)
        }
        Err(_) => None,
    }
}

/// `tpm0` and its interface version. The kernel's TPM drivers speak the 1.2
/// and 2.0 interfaces; `tpm_version_major` names which.
fn tpm(tpm_dir: &Path) -> (Option<bool>, Option<String>) {
    let tpm0 = tpm_dir.join("tpm0");
    if !tpm0.exists() {
        return (Some(false), None);
    }
    let version = match read_text(&tpm0.join("tpm_version_major")).as_deref() {
        Some("2") => Some("2.0".to_string()),
        Some("1") => Some("1.2".to_string()),
        _ => None,
    };
    (Some(true), version)
}

/// Encrypted only when every data path is proven LUKS2
/// ([`punar_common::storage`], the check the PIM vault also relies on). One
/// unproven path is `false`; an unreadable one, with none disproven, is
/// unknown.
fn disk_encryption(sources: &CollectorSources) -> Option<bool> {
    if sources.encrypted_paths.is_empty() {
        return None;
    }
    let mut unknown = false;
    for path in &sources.encrypted_paths {
        match storage::luks2_backing(path, &sources.storage) {
            Ok(Some(_)) => {}
            Ok(None) => return Some(false),
            Err(_) => unknown = true,
        }
    }
    (!unknown).then_some(true)
}

/// `systemd-detect-virt --vm`, the system's own answer; without it, the CPUID
/// hypervisor bit every mainstream hypervisor sets, which names no product.
fn virtualization(sources: &CollectorSources) -> (Option<bool>, Option<String>) {
    if let Ok(result) = run_with_timeout(&sources.detect_virt_bin, &["--vm"], DETECT_VIRT_TIMEOUT) {
        let answer = result.stdout.trim();
        let token = !answer.is_empty()
            && answer.len() <= 32
            && answer.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_".contains(&byte)
            });
        if token && answer == "none" {
            return (Some(false), None);
        }
        if token && result.success {
            return (Some(true), Some(answer.to_string()));
        }
    }
    let cpuinfo = read_small(&sources.cpuinfo).unwrap_or_default();
    let flags = cpuinfo_field(&String::from_utf8_lossy(&cpuinfo), "flags");
    (
        flags.map(|flags| flags.split_whitespace().any(|flag| flag == "hypervisor")),
        None,
    )
}

// ---------------------------------------------------------------------------
// Hardware
// ---------------------------------------------------------------------------

fn hardware(sources: &CollectorSources) -> Hardware {
    let dmi = |name: &str| meaningful(read_text(&sources.dmi_dir.join(name)));
    let tree = |name: &str| {
        read_small(&sources.device_tree_dir.join(name))
            .ok()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    };
    // The device tree's first `compatible` entry is `vendor,board`.
    let tree_vendor = tree("compatible").and_then(|compatible| {
        let first = compatible.split('\0').next()?;
        meaningful(first.split_once(',').map(|(vendor, _)| vendor.to_string()))
    });
    let tree_model = tree("model").and_then(|model| meaningful(Some(model)));
    let cpuinfo = read_small(&sources.cpuinfo)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    let root_filesystem_type =
        storage::mount_containing(Path::new("/"), &sources.storage.mountinfo)
            .ok()
            .flatten()
            .and_then(|mount| clean_text(&mount.fstype, 32));

    Hardware {
        manufacturer: dmi("sys_vendor").or(tree_vendor),
        model_name: dmi("product_name").or(tree_model),
        bios_version: dmi("bios_version"),
        // Only these two named fields: a Raspberry Pi's cpuinfo also carries
        // the board's serial number, which is an identifier.
        cpu_model: cpuinfo_field(&cpuinfo, "model name")
            .and_then(|value| clean_text(&value, MAX_NAME_CHARS)),
        cpu_vendor: cpuinfo_field(&cpuinfo, "vendor_id")
            .and_then(|value| clean_text(&value, MAX_NAME_CHARS)),
        cpu_cores: physical_cores(&sources.cpu_dir),
        cpu_threads: logical_cores(&sources.device.cpu_online).ok(),
        memory_total_bytes: memory_kib(&sources.device.meminfo)
            .ok()
            .and_then(|kib| kib.checked_mul(1024)),
        device_capacity_bytes: rustix::fs::statvfs(&sources.capacity_path)
            .ok()
            .and_then(|stat| stat.f_blocks.checked_mul(stat.f_frsize))
            .and_then(round_to_whole_gb),
        root_filesystem_type,
        battery_present: directory_has_battery(&sources.device.power_supply_dir).ok(),
    }
}

/// The first `key : value` line of `/proc/cpuinfo` with this exact key.
fn cpuinfo_field(cpuinfo: &str, key: &str) -> Option<String> {
    cpuinfo.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        (name.trim() == key).then(|| value.trim().to_string())
    })
}

/// Physical cores: one per distinct set of hardware threads that share a
/// core, which counts correctly with SMT, without it, and across big.LITTLE
/// clusters that reuse core ids.
fn physical_cores(cpu_dir: &Path) -> Option<u32> {
    let mut cores = BTreeSet::new();
    for entry in fs::read_dir(cpu_dir).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_cpu = name
            .strip_prefix("cpu")
            .is_some_and(|index| !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()));
        if !is_cpu {
            continue;
        }
        let topology = entry.path().join("topology");
        if let Some(siblings) = read_text(&topology.join("core_cpus_list"))
            .or_else(|| read_text(&topology.join("thread_siblings_list")))
        {
            cores.insert(siblings);
        }
    }
    u32::try_from(cores.len()).ok().filter(|count| *count > 0)
}

fn round_to_whole_gb(bytes: u64) -> Option<u64> {
    let rounded = bytes.saturating_add(BYTES_PER_GB / 2) / BYTES_PER_GB * BYTES_PER_GB;
    (rounded > 0).then_some(rounded)
}

// ---------------------------------------------------------------------------
// Organization-owned extras
// ---------------------------------------------------------------------------

/// SMBIOS's system serial, else the device tree's (Raspberry Pi). Placeholder
/// text is not a serial: the receiving side keeps the first serial it sees
/// forever, and two devices sharing "To Be Filled By O.E.M." would collide.
fn serial_number(sources: &CollectorSources) -> Option<String> {
    // Checked before cleaning: a serial carrying control bytes is not
    // repaired into a different serial.
    let valid = |value: Option<String>| {
        let serial = value.filter(|serial| {
            serial.len() <= 128 && serial.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
        });
        meaningful(serial)
    };
    valid(read_text(&sources.dmi_dir.join("product_serial")))
        .or_else(|| valid(read_text(&sources.device_tree_dir.join("serial-number"))))
}

/// `flatpak list --columns=application,name,version,active` rows. One row the
/// receiving side could not store would discard the whole snapshot, so a
/// single malformed row withholds the list rather than being skipped.
fn parse_flatpak_list(stdout: &str) -> Result<Vec<Application>, Withheld> {
    let mut rows = Vec::new();
    for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split('\t').collect();
        let [id, name, version, active] = fields[..] else {
            return Err(Withheld::Malformed);
        };
        if !is_flatpak_app_id(id) {
            return Err(Withheld::Malformed);
        }
        // Flatpak prints the active commit abbreviated; it stands in for an
        // application that publishes no version.
        let commit = active.trim();
        let version = if version.trim().is_empty()
            && !commit.is_empty()
            && commit.bytes().all(|b| b.is_ascii_hexdigit())
        {
            Some(commit)
        } else {
            Some(version)
        };
        rows.push(Application::new(id, name, version, SOURCE_FLATPAK).ok_or(Withheld::Malformed)?);
    }
    Ok(rows)
}

fn is_flatpak_app_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_NAME_CHARS
        && id.contains('.')
        && !id.starts_with('.')
        && !id.ends_with('.')
        && !id.contains("..")
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

// ---------------------------------------------------------------------------
// The image's own applications
// ---------------------------------------------------------------------------

/// Punar's first-party applications, as the image's desktop entries declare
/// them (`X-Punar-FirstParty=true`, shown in the launcher), plus the image
/// browser. Every one is part of the signed release, so its version is the
/// release's. Debian's own entries (an editor, a file manager) are base OS
/// packages, which are never sent, and carry no marker.
fn image_applications(
    sources: &CollectorSources,
    image: &ImageRelease,
) -> Result<Vec<Application>, Withheld> {
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    for dir in &sources.desktop_entry_dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        let mut files: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
        files.sort();
        for path in files {
            let Some(id) = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix(".desktop"))
                .filter(|id| is_desktop_id(id))
            else {
                continue;
            };
            // XDG precedence: the first directory to define an id owns it,
            // including when that definition hides the application.
            if !seen.insert(id.to_string()) {
                continue;
            }
            let Some(entry) = read_desktop_entry(&path) else {
                continue;
            };
            let listed =
                entry.first_party && entry.application && !entry.no_display && !entry.hidden;
            if listed {
                rows.push(
                    Application::new(id, &entry.name, image.version.as_deref(), SOURCE_IMAGE)
                        .ok_or(Withheld::Malformed)?,
                );
            }
        }
    }
    if let Some(version) = image.browser_version.as_deref() {
        rows.extend(Application::new(
            "chromium",
            "Chromium",
            Some(version),
            SOURCE_IMAGE,
        ));
    }
    Ok(rows)
}

struct DesktopEntry {
    name: String,
    application: bool,
    first_party: bool,
    no_display: bool,
    hidden: bool,
}

fn read_desktop_entry(path: &Path) -> Option<DesktopEntry> {
    let bytes = read_small(path).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    let mut in_group = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_group = line == "[Desktop Entry]";
        } else if in_group && !line.starts_with('#') {
            if let Some((key, value)) = line.split_once('=') {
                fields.entry(key.trim()).or_insert(value.trim());
            }
        }
    }
    let is_true = |key: &str| fields.get(key) == Some(&"true");
    Some(DesktopEntry {
        name: fields.get("Name")?.to_string(),
        application: fields.get("Type") == Some(&"Application"),
        first_party: is_true("X-Punar-FirstParty"),
        no_display: is_true("NoDisplay"),
        hidden: is_true("Hidden"),
    })
}

fn is_desktop_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_NAME_CHARS
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

// ---------------------------------------------------------------------------
// Small readers
// ---------------------------------------------------------------------------

/// A bounded regular file: sysfs attributes, efivars, desktop entries.
fn read_small(path: &Path) -> io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(SMALL_FILE_MAX + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > SMALL_FILE_MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "oversized"));
    }
    Ok(bytes)
}

/// A text attribute, trimmed of whitespace and the device tree's NULs.
fn read_text(path: &Path) -> Option<String> {
    let bytes = read_small(path).ok()?;
    let text = String::from_utf8_lossy(&bytes)
        .trim_matches(|c: char| c.is_whitespace() || c == '\0')
        .to_string();
    (!text.is_empty()).then_some(text)
}

/// Firmware fills unused SMBIOS strings with vendor boilerplate. Those are
/// not facts, and a repeated single character is not one either.
fn meaningful(value: Option<String>) -> Option<String> {
    const PLACEHOLDERS: &[&str] = &[
        "to be filled by o.e.m.",
        "to be filled by oem",
        "default string",
        "system manufacturer",
        "system product name",
        "system serial number",
        "system version",
        "chassis serial number",
        "serial number",
        "not specified",
        "not applicable",
        "not available",
        "none",
        "n/a",
        "na",
        "oem",
        "o.e.m.",
        "unknown",
        "undefined",
        "invalid",
        "empty",
        "0123456789",
        "123456789",
        "1234567890",
    ];
    let value = clean_text(&value?, MAX_NAME_CHARS)?;
    let lowered = value.to_ascii_lowercase();
    let mut chars = value.chars();
    let first = chars.next()?;
    if PLACEHOLDERS.contains(&lowered.as_str()) || chars.all(|c| c == first) {
        return None;
    }
    Some(value)
}

/// Control characters become spaces, surrounding space goes, and the result
/// is cut to `max_chars` characters. `None` when nothing is left.
fn clean_text(value: &str, max_chars: usize) -> Option<String> {
    let cleaned: String = value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let clamped: String = cleaned.trim().chars().take(max_chars).collect();
    let clamped = clamped.trim_end().to_string();
    (!clamped.is_empty()).then_some(clamped)
}

fn file_stamp(path: &Path) -> Option<FileStamp> {
    let metadata = fs::metadata(path).ok()?;
    Some(FileStamp {
        modified: metadata.modified().ok(),
        inode: metadata.ino(),
        len: metadata.len(),
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde_json::json;

    use super::*;

    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// A fixture tree shaped like the procfs/sysfs/image paths the collector
    /// reads in production. Nothing in these tests reads the host's own.
    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Fixture {
            let root = std::env::temp_dir().join(format!(
                "punard-inventory-{tag}-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            Fixture { root }
        }

        fn write(&self, relative: &str, contents: impl AsRef<[u8]>) {
            let path = self.root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }

        fn sources(&self) -> CollectorSources {
            let at = |relative: &str| self.root.join(relative);
            CollectorSources {
                device: DeviceSources {
                    meminfo: at("proc/meminfo"),
                    cpu_online: at("sys/devices/system/cpu/online"),
                    power_supply_dir: at("sys/class/power_supply"),
                    drm_dir: at("sys/class/drm"),
                },
                cpuinfo: at("proc/cpuinfo"),
                cpu_dir: at("sys/devices/system/cpu"),
                dmi_dir: at("sys/class/dmi/id"),
                device_tree_dir: at("proc/device-tree"),
                efi_dir: at("sys/firmware/efi"),
                tpm_dir: at("sys/class/tpm"),
                storage: StorageSources {
                    sys_dev_block: at("sys/dev/block"),
                    sys_class_block: at("sys/class/block"),
                    sys_fs_btrfs: at("sys/fs/btrfs"),
                    mountinfo: at("proc/self/mountinfo"),
                },
                encrypted_paths: vec![at("var"), at("home")],
                capacity_path: self.root.clone(),
                desktop_entry_dirs: vec![
                    at("usr/local/share/applications"),
                    at("usr/share/applications"),
                ],
                flatpak_installation: at("var/lib/flatpak"),
                detect_virt_bin: at("bin/systemd-detect-virt"),
            }
        }

        /// A QEMU x86_64 guest with SMBIOS, UEFI, Secure Boot on, a TPM
        /// 2.0, four cores / eight threads, and Punar's desktop entries.
        fn uefi_vm(tag: &str) -> Fixture {
            let fixture = Fixture::new(tag);
            fixture.write("proc/meminfo", "MemTotal:       16384000 kB\n");
            fixture.write("sys/devices/system/cpu/online", "0-7\n");
            for cpu in 0..8 {
                fixture.write(
                    &format!("sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list"),
                    format!("{},{}\n", cpu % 4, cpu % 4 + 4),
                );
            }
            fixture.write("sys/devices/system/cpu/cpufreq/policy0/x", "");
            fixture.write(
                "proc/cpuinfo",
                "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: QEMU Virtual CPU version 2.5+\n\
                 flags\t\t: fpu vme hypervisor\n\nprocessor\t: 1\nvendor_id\t: GenuineIntel\n",
            );
            fixture.write("sys/class/dmi/id/sys_vendor", "QEMU\n");
            fixture.write(
                "sys/class/dmi/id/product_name",
                "Standard PC (Q35 + ICH9, 2009)\n",
            );
            fixture.write("sys/class/dmi/id/bios_version", "1.16.3-debian-1.16.3-2\n");
            fixture.write("sys/class/dmi/id/product_serial", "PNR-0042-XYZ\n");
            fixture.write(
                format!("sys/firmware/efi/efivars/{SECURE_BOOT_VARIABLE}").as_str(),
                [0x06, 0x00, 0x00, 0x00, 0x01],
            );
            fixture.write("sys/class/tpm/tpm0/tpm_version_major", "2\n");
            fixture.write("sys/class/power_supply/AC/type", "Mains\n");
            fixture.write(
                "proc/self/mountinfo",
                "22 1 253:1 / / ro,relatime - erofs /dev/mapper/usr ro\n",
            );
            fixture.write(
                "usr/local/share/applications/org.punar.Mail.desktop",
                "[Desktop Entry]\nType=Application\nName=Mail\nName[de]=Post\n\
                 Exec=punarctl mail open\nX-Punar-FirstParty=true\n",
            );
            fixture.write(
                "usr/local/share/applications/org.punar.MailPrototype.desktop",
                "[Desktop Entry]\nType=Application\nName=Prototype\nNoDisplay=true\n\
                 X-Punar-FirstParty=true\n",
            );
            fixture.write(
                "usr/local/share/applications/punar-browser.desktop",
                "[Desktop Entry]\nType=Application\nName=Browser\n",
            );
            fixture.write(
                "usr/share/applications/thunar.desktop",
                "[Desktop Entry]\nType=Application\nName=Thunar File Manager\n",
            );
            fixture
        }

        fn luks(&self) {
            fs::create_dir_all(self.root.join("var")).unwrap();
            fs::create_dir_all(self.root.join("home")).unwrap();
            let dev = fs::metadata(self.root.join("var")).unwrap().dev();
            self.write(
                &format!(
                    "sys/dev/block/{}:{}/dm/uuid",
                    rustix::fs::major(dev),
                    rustix::fs::minor(dev)
                ),
                "CRYPT-LUKS2-0123456789abcdef-punar-data\n",
            );
        }

        fn script(&self, relative: &str, body: &str) -> PathBuf {
            let path = self.root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn pass(organization_owned: bool) -> PassInputs {
        PassInputs {
            organization_owned,
            architecture: "x86_64".into(),
            firewall_state: Some(json!("enabled")),
            patch: PatchPosture {
                status: PatchStatus::UpToDate,
                reboot_required: Some(false),
            },
        }
    }

    fn release() -> ImageRelease {
        ImageRelease {
            version: Some("2026.09.01.1".into()),
            browser_version: Some("151.0.7922.173-1".into()),
        }
    }

    fn keys(value: &Value) -> Vec<String> {
        value.as_object().unwrap().keys().cloned().collect()
    }

    #[test]
    fn hardware_is_read_from_smbios_procfs_and_sysfs() {
        let fixture = Fixture::uefi_vm("hardware");
        let collector = InventoryCollector::new(fixture.sources(), PathBuf::from("/bin/false"));
        let collected = collector.collect(&pass(false), release, Vec::new);
        let hardware = &collected.hardware;
        assert_eq!(hardware.manufacturer.as_deref(), Some("QEMU"));
        assert_eq!(
            hardware.model_name.as_deref(),
            Some("Standard PC (Q35 + ICH9, 2009)")
        );
        assert_eq!(
            hardware.bios_version.as_deref(),
            Some("1.16.3-debian-1.16.3-2")
        );
        assert_eq!(hardware.cpu_vendor.as_deref(), Some("GenuineIntel"));
        assert_eq!(
            hardware.cpu_model.as_deref(),
            Some("QEMU Virtual CPU version 2.5+")
        );
        assert_eq!(hardware.cpu_cores, Some(4), "four cores, two threads each");
        assert_eq!(hardware.cpu_threads, Some(8));
        assert_eq!(hardware.memory_total_bytes, Some(16_384_000 * 1024));
        assert_eq!(hardware.battery_present, Some(false));
        assert_eq!(hardware.root_filesystem_type.as_deref(), Some("erofs"));
        let capacity = hardware.device_capacity_bytes.expect("statvfs of the tree");
        assert_eq!(capacity % BYTES_PER_GB, 0);

        // The exact key set: hardware facts, and no identifier among them.
        let value = serde_json::to_value(hardware).unwrap();
        assert_eq!(
            keys(&value),
            [
                "battery_present",
                "bios_version",
                "cpu_cores",
                "cpu_model",
                "cpu_threads",
                "cpu_vendor",
                "device_capacity_bytes",
                "manufacturer",
                "memory_total_bytes",
                "model_name",
                "root_filesystem_type",
            ]
        );
        assert!(!value.to_string().contains("PNR-0042-XYZ"));
    }

    /// A Raspberry Pi has no SMBIOS: the device tree names the board, and
    /// cpuinfo's `Serial` line is never read into a hardware field.
    #[test]
    fn a_device_tree_board_is_named_without_its_serial() {
        let fixture = Fixture::new("pi");
        fixture.write(
            "proc/device-tree/model",
            b"Raspberry Pi 5 Model B Rev 1.0\0",
        );
        fixture.write(
            "proc/device-tree/compatible",
            b"raspberrypi,5-model-b\0brcm,bcm2712\0",
        );
        fixture.write("proc/device-tree/serial-number", b"10000000abcdef01\0");
        fixture.write(
            "proc/cpuinfo",
            "processor\t: 0\nBogoMIPS\t: 108.00\nCPU implementer\t: 0x41\n\n\
             Revision\t: d04170\nSerial\t\t: 10000000abcdef01\nModel\t\t: Raspberry Pi 5 Model B Rev 1.0\n",
        );
        for cpu in 0..4 {
            fixture.write(
                &format!("sys/devices/system/cpu/cpu{cpu}/topology/core_cpus_list"),
                format!("{cpu}\n"),
            );
        }
        let sources = fixture.sources();
        let hardware = hardware(&sources);
        assert_eq!(hardware.manufacturer.as_deref(), Some("raspberrypi"));
        assert_eq!(
            hardware.model_name.as_deref(),
            Some("Raspberry Pi 5 Model B Rev 1.0")
        );
        assert_eq!(hardware.bios_version, None);
        assert_eq!(hardware.cpu_cores, Some(4));
        assert_eq!(hardware.cpu_vendor, None);
        assert!(
            !serde_json::to_string(&hardware)
                .unwrap()
                .contains("10000000abcdef01")
        );
        // The same board's serial, for the organization-owned tier only.
        assert_eq!(serial_number(&sources).as_deref(), Some("10000000abcdef01"));
    }

    #[test]
    fn firmware_placeholders_are_not_facts_and_never_serials() {
        let fixture = Fixture::new("placeholders");
        for (vendor, serial) in [
            ("To Be Filled By O.E.M.", "To Be Filled By O.E.M."),
            ("Default string", "Default string"),
            ("System manufacturer", "System Serial Number"),
            ("QEMU", "0000000000"),
            ("QEMU", "0123456789"),
            ("QEMU", " "),
            ("QEMU", "serial\u{7}bell"),
        ] {
            fixture.write("sys/class/dmi/id/sys_vendor", vendor);
            fixture.write("sys/class/dmi/id/product_serial", serial);
            let sources = fixture.sources();
            assert_eq!(serial_number(&sources), None, "{serial:?}");
            if vendor != "QEMU" {
                assert_eq!(hardware(&sources).manufacturer, None, "{vendor:?}");
            }
        }
        fixture.write("sys/class/dmi/id/product_serial", "PF2ABCDE\n");
        assert_eq!(
            serial_number(&fixture.sources()).as_deref(),
            Some("PF2ABCDE")
        );
    }

    #[test]
    fn posture_is_read_from_efi_tpm_and_the_storage_proof() {
        let fixture = Fixture::uefi_vm("posture");
        fixture.luks();
        fixture.script("bin/systemd-detect-virt", "echo kvm");
        let collector = InventoryCollector::new(fixture.sources(), PathBuf::from("/bin/false"));
        let posture = collector.collect(&pass(false), release, Vec::new).posture;
        assert_eq!(
            posture,
            Posture {
                secure_boot: Some(true),
                uefi: Some(true),
                tpm_present: Some(true),
                tpm_version: Some("2.0".into()),
                is_virtual: Some(true),
                virtualization: Some("kvm".into()),
                disk_encryption_enabled: Some(true),
                firewall_enabled: Some(true),
                firewall: Some("nftables".into()),
                os_patch_status: PatchStatus::UpToDate,
                reboot_required: Some(false),
            }
        );
        assert_eq!(
            keys(&serde_json::to_value(&posture).unwrap()),
            [
                "disk_encryption_enabled",
                "firewall",
                "firewall_enabled",
                "is_virtual",
                "os_patch_status",
                "reboot_required",
                "secure_boot",
                "tpm_present",
                "tpm_version",
                "uefi",
                "virtualization",
            ]
        );
        assert_eq!(
            serde_json::to_value(&posture).unwrap()["os_patch_status"],
            "up-to-date"
        );
    }

    #[test]
    fn posture_says_false_only_on_evidence_and_unknown_otherwise() {
        let fixture = Fixture::uefi_vm("posture-off");
        let sources = fixture.sources();
        // Secure Boot variable says off; then absent from a mounted efivarfs
        // (no Secure Boot in firmware); then efivarfs not mounted at all.
        fixture.write(
            format!("sys/firmware/efi/efivars/{SECURE_BOOT_VARIABLE}").as_str(),
            [0x06, 0x00, 0x00, 0x00, 0x00],
        );
        assert_eq!(secure_boot(&sources.efi_dir), Some(false));
        fs::remove_file(sources.efi_dir.join("efivars").join(SECURE_BOOT_VARIABLE)).unwrap();
        assert_eq!(secure_boot(&sources.efi_dir), Some(false));
        fs::remove_dir(sources.efi_dir.join("efivars")).unwrap();
        assert_eq!(secure_boot(&sources.efi_dir), None);
        // No UEFI boot: no UEFI Secure Boot.
        fs::remove_dir_all(&sources.efi_dir).unwrap();
        assert_eq!(secure_boot(&sources.efi_dir), Some(false));

        fs::remove_dir_all(&sources.tpm_dir).unwrap();
        assert_eq!(tpm(&sources.tpm_dir), (Some(false), None));

        // /var and /home exist but nothing proves them encrypted.
        fs::create_dir_all(fixture.root.join("var")).unwrap();
        fs::create_dir_all(fixture.root.join("home")).unwrap();
        assert_eq!(disk_encryption(&sources), Some(false));
        let none = CollectorSources {
            encrypted_paths: Vec::new(),
            ..sources.clone()
        };
        assert_eq!(disk_encryption(&none), None);

        // No detect-virt binary and no CPUID flags line: unknown. With the
        // flags line, the hypervisor bit decides, and names no product.
        fixture.write("proc/cpuinfo", "processor\t: 0\n");
        assert_eq!(virtualization(&sources), (None, None));
        fixture.write("proc/cpuinfo", "flags\t\t: fpu vme sse2\n");
        assert_eq!(virtualization(&sources), (Some(false), None));
        fixture.script("bin/systemd-detect-virt", "echo none; exit 1");
        assert_eq!(virtualization(&sources), (Some(false), None));
        fixture.script("bin/systemd-detect-virt", "echo 'Not A Token'");
        assert_eq!(virtualization(&sources), (Some(false), None));

        // A firewall capability that could not be observed is unknown.
        let collector = InventoryCollector::new(sources, PathBuf::from("/bin/false"));
        let mut inputs = pass(false);
        inputs.firewall_state = Some(json!("unknown"));
        let posture = collector.collect(&inputs, release, Vec::new).posture;
        assert_eq!(posture.firewall_enabled, None);
        assert_eq!(posture.firewall.as_deref(), Some("nftables"));
        inputs.firewall_state = None;
        let posture = collector.collect(&inputs, release, Vec::new).posture;
        assert_eq!((posture.firewall_enabled, posture.firewall), (None, None));
    }

    #[test]
    fn patch_posture_needs_verified_evidence_to_say_up_to_date() {
        let never = || -> Option<bool> { panic!("a staged release decides without the channel") };
        assert_eq!(
            patch_posture(StagedRelease::AwaitingRestart, never),
            PatchPosture {
                status: PatchStatus::UpdatesAvailable,
                reboot_required: Some(true)
            }
        );
        assert_eq!(
            patch_posture(StagedRelease::Unknown, never),
            PatchPosture {
                status: PatchStatus::Unknown,
                reboot_required: None
            }
        );
        for staged in [StagedRelease::None, StagedRelease::Running] {
            assert_eq!(
                patch_posture(staged, || Some(false)).status,
                PatchStatus::UpToDate
            );
            assert_eq!(
                patch_posture(staged, || Some(true)).status,
                PatchStatus::UpdatesAvailable
            );
            assert_eq!(
                patch_posture(staged, || None),
                PatchPosture {
                    status: PatchStatus::Unknown,
                    reboot_required: Some(false)
                }
            );
        }
    }

    /// Only first-party entries the launcher shows, at the release's version,
    /// plus the image browser. XDG precedence decides a shadowed id.
    #[test]
    fn image_applications_are_the_releases_first_party_entries() {
        let fixture = Fixture::uefi_vm("image-apps");
        // The dev profile shadows a product id with a hidden entry: hidden.
        fixture.write(
            "usr/local/share/applications/org.punar.MailAccount.desktop",
            "[Desktop Entry]\nType=Application\nName=Add Mail Account\nHidden=true\n\
             X-Punar-FirstParty=true\n",
        );
        fixture.write(
            "usr/share/applications/org.punar.MailAccount.desktop",
            "[Desktop Entry]\nType=Application\nName=Add Mail Account\nX-Punar-FirstParty=true\n",
        );
        fixture.write(
            "usr/share/applications/org.punar.Link.desktop",
            "[Desktop Entry]\nType=Link\nName=Docs\nX-Punar-FirstParty=true\n",
        );
        fixture.write(
            "usr/share/applications/org.punar.Notes.desktop",
            "[Other Group]\nName=Wrong group\n[Desktop Entry]\nType=Application\n\
             Name=Notes\nX-Punar-FirstParty=true\n",
        );
        let rows = image_applications(&fixture.sources(), &release()).unwrap();
        let rows: Vec<(&str, &str, Option<&str>)> = rows
            .iter()
            .map(|a| {
                (
                    a.name.as_str(),
                    a.display_name.as_str(),
                    a.version.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                ("org.punar.Mail", "Mail", Some("2026.09.01.1")),
                ("org.punar.Notes", "Notes", Some("2026.09.01.1")),
                ("chromium", "Chromium", Some("151.0.7922.173-1")),
            ]
        );
        let none = image_applications(&fixture.sources(), &ImageRelease::default()).unwrap();
        assert_eq!(none.len(), 2, "no browser without a browser version");
        assert!(none.iter().all(|app| app.version.is_none()));
    }

    /// Tier gating at the collector: a personal enrollment never runs
    /// flatpak, never asks for vendor apps and never reads the serial.
    #[test]
    fn a_personal_enrollment_reads_no_system_apps_and_no_serial() {
        let fixture = Fixture::uefi_vm("tier-personal");
        let flatpak = fixture.script("bin/flatpak", "echo called >> \"$0.log\"; exit 1");
        fixture.write("var/lib/flatpak/.changed", "");
        let collector = InventoryCollector::new(fixture.sources(), flatpak.clone());
        let collected = collector.collect(&pass(false), release, || {
            panic!("vendor apps are read only for an organization-owned device")
        });
        assert_eq!(collected.serial_number, None);
        assert!(
            collected
                .applications
                .as_ref()
                .unwrap()
                .iter()
                .all(|app| app.source == SOURCE_IMAGE)
        );
        assert!(!flatpak.with_extension("log").exists(), "flatpak never ran");
    }

    #[test]
    fn an_organization_owned_device_adds_serial_system_flatpaks_and_vendor_apps() {
        let fixture = Fixture::uefi_vm("tier-org");
        let log = fixture.root.join("flatpak.log");
        let flatpak = fixture.script(
            "bin/flatpak",
            &format!(
                "printf '%s\\n' \"$*\" >> '{}'\n\
                 printf 'org.mozilla.firefox\\tFirefox\\t131.0\\t0123456789ab\\n'\n\
                 printf 'com.example.NoVersion\\t\\t\\tfedcba987654\\n'",
                log.display()
            ),
        );
        fixture.write("var/lib/flatpak/.changed", "");
        let collector = InventoryCollector::new(fixture.sources(), flatpak);
        let vendor = || {
            vec![(
                "chatgpt-desktop".to_string(),
                "ChatGPT Desktop (preview)".to_string(),
                Some("26.825.32147".to_string()),
            )]
        };
        let collected = collector.collect(&pass(true), release, vendor);
        assert_eq!(collected.serial_number.as_deref(), Some("PNR-0042-XYZ"));
        let rows = collected.applications.clone().unwrap();
        let named: Vec<(&str, &str, Option<&str>, &str)> = rows
            .iter()
            .map(|a| {
                (
                    a.name.as_str(),
                    a.display_name.as_str(),
                    a.version.as_deref(),
                    a.source,
                )
            })
            .collect();
        assert_eq!(
            named,
            [
                (
                    "chatgpt-desktop",
                    "ChatGPT Desktop (preview)",
                    Some("26.825.32147"),
                    SOURCE_VENDOR
                ),
                (
                    "chromium",
                    "Chromium",
                    Some("151.0.7922.173-1"),
                    SOURCE_IMAGE
                ),
                (
                    "com.example.NoVersion",
                    "com.example.NoVersion",
                    Some("fedcba987654"),
                    SOURCE_FLATPAK
                ),
                (
                    "org.mozilla.firefox",
                    "Firefox",
                    Some("131.0"),
                    SOURCE_FLATPAK
                ),
                ("org.punar.Mail", "Mail", Some("2026.09.01.1"), SOURCE_IMAGE),
            ]
        );
        assert_eq!(
            fs::read_to_string(&log).unwrap(),
            "list --system --app --columns=application,name,version,active\n",
            "system installation only, fixed argv"
        );
        // Every row carries the same five keys.
        for row in &rows {
            assert_eq!(
                keys(&serde_json::to_value(row).unwrap()),
                ["display_name", "managed", "name", "source", "version"]
            );
            assert!(!row.managed);
        }

        // An unchanged installation is not listed again; a changed one is.
        collector.collect(&pass(true), release, vendor);
        assert_eq!(fs::read_to_string(&log).unwrap().lines().count(), 1);
        std::thread::sleep(Duration::from_millis(20));
        fs::remove_file(fixture.root.join("var/lib/flatpak/.changed")).unwrap();
        fixture.write("var/lib/flatpak/.changed", "x");
        collector.collect(&pass(true), release, vendor);
        assert_eq!(fs::read_to_string(&log).unwrap().lines().count(), 2);

        // The tier is the caller's: the same collector, asked for a personal
        // pass, drops everything the organization-owned pass added.
        let personal = collector.collect(&pass(false), release, Vec::new);
        assert_eq!(personal.serial_number, None);
        assert_eq!(personal.applications.unwrap().len(), 2);
    }

    #[test]
    fn a_malformed_or_unreadable_flatpak_list_is_withheld_never_truncated() {
        assert_eq!(
            parse_flatpak_list("org.a.B\tB\t1\tabc\norg.c.D\tD\n"),
            Err(Withheld::Malformed)
        );
        assert_eq!(
            parse_flatpak_list("../escape\tX\t1\tabc\n"),
            Err(Withheld::Malformed)
        );
        assert!(parse_flatpak_list("\n").unwrap().is_empty());

        let fixture = Fixture::uefi_vm("flatpak-fails");
        let flatpak = fixture.script("bin/flatpak", "exit 1");
        fixture.write("var/lib/flatpak/.changed", "");
        let collector = InventoryCollector::new(fixture.sources(), flatpak);
        assert_eq!(
            collector
                .collect(&pass(true), release, Vec::new)
                .applications,
            Err(Withheld::Unreadable)
        );
        // No system installation at all: nothing to list, nothing spawned.
        fs::remove_dir_all(fixture.root.join("var/lib/flatpak")).unwrap();
        assert!(
            collector
                .collect(&pass(true), release, Vec::new)
                .applications
                .is_ok()
        );
    }

    #[test]
    fn rows_are_clamped_to_the_receiving_columns() {
        let long = "x".repeat(400);
        let app = Application::new(
            &long,
            "  Name\twith\ncontrols ",
            Some(&long),
            SOURCE_FLATPAK,
        )
        .unwrap();
        assert_eq!(app.name.chars().count(), MAX_NAME_CHARS);
        assert_eq!(
            app.version.as_deref().unwrap().chars().count(),
            MAX_VERSION_CHARS
        );
        assert_eq!(app.display_name, "Name with controls");
        assert_eq!(Application::new(" \u{7} ", "x", None, SOURCE_FLATPAK), None);
        let unicode = "é".repeat(300);
        let app = Application::new("org.a.B", &unicode, Some(""), SOURCE_FLATPAK).unwrap();
        assert_eq!(app.display_name.chars().count(), MAX_NAME_CHARS);
        assert_eq!(app.version, None);
    }

    #[test]
    fn the_count_cap_withholds_instead_of_truncating() {
        let fixture = Fixture::uefi_vm("cap");
        let collector = InventoryCollector::new(fixture.sources(), PathBuf::from("/bin/false"));
        let mut collected = collector.collect(&pass(true), release, Vec::new);
        let many: Vec<Application> = (0..=MAX_APPLICATIONS)
            .map(|i| {
                Application::new(&format!("org.example.App{i}"), "App", None, SOURCE_FLATPAK)
                    .unwrap()
            })
            .collect();
        collected.applications = Ok(many);
        assert_eq!(collected.applications_for(true), Err(Withheld::TooMany));
        // The personal tier filters first: the image's rows remain.
        assert!(collected.applications_for(false).unwrap().is_empty());
    }

    #[test]
    fn whole_gigabytes_round_to_nearest() {
        assert_eq!(round_to_whole_gb(0), None);
        assert_eq!(round_to_whole_gb(499_999_999), None);
        assert_eq!(round_to_whole_gb(500_000_000), Some(BYTES_PER_GB));
        assert_eq!(round_to_whole_gb(255_869_321_216), Some(256 * BYTES_PER_GB));
        assert_eq!(
            round_to_whole_gb(u64::MAX),
            Some(u64::MAX / BYTES_PER_GB * BYTES_PER_GB)
        );
    }
}
