//! Offline installer hardware observation.
//!
//! This is evidence about the running kernel, not a hardware-support claim.
//! Device serials, MAC addresses and user data are deliberately absent. The
//! only subprocess is fixed-argv `modinfo`, used to read module firmware
//! metadata from the already-installed kernel tree.

use crate::util::SpawnBusyRetry;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use punar_common::install::{
    InstallHardwareBus, InstallHardwareCoverage, InstallHardwareDevice, InstallHardwareFunction,
    InstallHardwareReason, InstallHardwareReport,
};

const MODULE_ALIASES_MAX_BYTES: u64 = 32 * 1024 * 1024;
const MODINFO_MAX_BYTES: u64 = 256 * 1024;
#[cfg(not(test))]
const MODINFO_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(test)]
const MODINFO_TIMEOUT: Duration = Duration::from_millis(100);
const DEVICE_LIMIT: usize = 1024;
const MODULE_ALIAS_LIMIT: usize = 250_000;
const MODULE_CLAIM_LIMIT: usize = 32;
const FIRMWARE_REQUEST_LIMIT: usize = 256;
const FIRMWARE_FILE_LIMIT: usize = 250_000;
const FIRMWARE_DEPTH_LIMIT: usize = 16;

#[derive(Clone, Debug)]
pub struct HardwareSources {
    pub pci_devices: PathBuf,
    pub usb_devices: PathBuf,
    pub platform_devices: PathBuf,
    pub modules_root: PathBuf,
    pub kernel_release_path: PathBuf,
    pub firmware_roots: Vec<PathBuf>,
    pub modinfo_path: PathBuf,
}

impl Default for HardwareSources {
    fn default() -> Self {
        Self {
            pci_devices: PathBuf::from("/sys/bus/pci/devices"),
            usb_devices: PathBuf::from("/sys/bus/usb/devices"),
            platform_devices: PathBuf::from("/sys/bus/platform/devices"),
            modules_root: PathBuf::from("/lib/modules"),
            kernel_release_path: PathBuf::from("/proc/sys/kernel/osrelease"),
            firmware_roots: vec![PathBuf::from("/usr/lib/firmware")],
            modinfo_path: PathBuf::from("/usr/bin/modinfo"),
        }
    }
}

#[derive(Clone, Debug)]
struct ModuleAlias {
    pattern: String,
    module: String,
}

#[derive(Clone, Debug)]
struct ObservedDevice {
    bus: InstallHardwareBus,
    address: String,
    path: PathBuf,
}

pub fn observe_install_hardware(
    sources: &HardwareSources,
    architecture: &str,
    disk_below_minimum_target: bool,
) -> io::Result<InstallHardwareReport> {
    if !matches!(architecture, "x86_64" | "aarch64") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hardware report architecture is unsupported",
        ));
    }
    let kernel_release = read_attribute(&sources.kernel_release_path, 256)?.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "kernel release is unavailable")
    })?;
    if !valid_kernel_release(&kernel_release) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel release contains invalid characters",
        ));
    }
    let aliases_path = sources
        .modules_root
        .join(&kernel_release)
        .join("modules.alias");
    let aliases = load_module_aliases(&aliases_path)?;
    let firmware = inventory_firmware(&sources.firmware_roots)?;

    let mut observed = Vec::new();
    observe_bus(&sources.pci_devices, InstallHardwareBus::Pci, &mut observed)?;
    observe_bus(&sources.usb_devices, InstallHardwareBus::Usb, &mut observed)?;
    observe_bus(
        &sources.platform_devices,
        InstallHardwareBus::Platform,
        &mut observed,
    )?;
    observed.sort_by(|left, right| {
        bus_name(left.bus)
            .cmp(bus_name(right.bus))
            .then_with(|| left.address.cmp(&right.address))
    });
    if observed.len() > DEVICE_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hardware report exceeds its fixed device limit",
        ));
    }

    let mut metadata = BTreeMap::<String, Option<Vec<String>>>::new();
    let mut devices = Vec::with_capacity(observed.len());
    for device in observed {
        devices.push(classify_device(
            &device,
            &aliases,
            &firmware,
            sources,
            &kernel_release,
            &mut metadata,
        )?);
    }
    let graphics_usable = devices.iter().any(|device| {
        device.function == InstallHardwareFunction::Graphics
            && device.driver.is_some()
            && device.coverage != InstallHardwareCoverage::Unsupported
    });
    let overall = devices
        .iter()
        .map(|device| device.coverage)
        .max()
        .unwrap_or(InstallHardwareCoverage::Unsupported);

    Ok(InstallHardwareReport {
        v: 1,
        generated_at: punar_common::time::utc_now_rfc3339(),
        architecture: architecture.to_string(),
        kernel_release,
        overall,
        graphics_usable,
        disk_below_minimum_target,
        bare_hardware_qualified: false,
        devices,
    })
}

fn observe_bus(
    root: &Path,
    bus: InstallHardwareBus,
    devices: &mut Vec<ObservedDevice>,
) -> io::Result<()> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_dir() && !file_type.is_symlink() {
            continue;
        }
        let address = entry.file_name().to_string_lossy().into_owned();
        if address.is_empty() || address.len() > 128 || address.chars().any(char::is_control) {
            continue;
        }
        devices.push(ObservedDevice {
            bus,
            address,
            path: entry.path(),
        });
        if devices.len() > DEVICE_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "hardware report exceeds its fixed device limit",
            ));
        }
    }
    Ok(())
}

fn classify_device(
    observed: &ObservedDevice,
    aliases: &[ModuleAlias],
    firmware_files: &BTreeSet<String>,
    sources: &HardwareSources,
    kernel_release: &str,
    metadata_cache: &mut BTreeMap<String, Option<Vec<String>>>,
) -> io::Result<InstallHardwareDevice> {
    let modalias = read_attribute(&observed.path.join("modalias"), 4096)?;
    let vendor_id = read_identifier(
        &observed.path,
        match observed.bus {
            InstallHardwareBus::Pci => "vendor",
            InstallHardwareBus::Usb => "idVendor",
            InstallHardwareBus::Platform => "vendor",
        },
    )?;
    let device_id = read_identifier(
        &observed.path,
        match observed.bus {
            InstallHardwareBus::Pci => "device",
            InstallHardwareBus::Usb => "idProduct",
            InstallHardwareBus::Platform => "device",
        },
    )?;
    let class_id = read_class_id(observed)?;
    let function = classify_function(observed.bus, class_id.as_deref(), modalias.as_deref());
    let display_name = display_name(observed, vendor_id.as_deref(), device_id.as_deref())?;
    let (driver, bound_module) = bound_driver(&observed.path)?;

    let all_claiming_modules = modalias
        .as_deref()
        .map(|value| {
            aliases
                .iter()
                .filter(|entry| wildcard_matches(&entry.pattern, value))
                .map(|entry| entry.module.clone())
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let claiming_modules = bounded_claiming_modules(
        &all_claiming_modules,
        bound_module.as_deref().or(driver.as_deref()),
    );

    let mut requested_firmware = Vec::new();
    let mut missing_firmware = Vec::new();
    let (coverage, reason) = if modalias.is_none() {
        (
            InstallHardwareCoverage::Unsupported,
            InstallHardwareReason::ModaliasUnavailable,
        )
    } else if claiming_modules.is_empty() {
        (
            InstallHardwareCoverage::Unsupported,
            InstallHardwareReason::NoModuleClaim,
        )
    } else if driver.is_none() {
        (
            InstallHardwareCoverage::Partial,
            InstallHardwareReason::DriverUnbound,
        )
    } else {
        let module = bound_module
            .as_deref()
            .or(driver.as_deref())
            .expect("driver checked above");
        let claimed = claiming_modules
            .iter()
            .any(|claim| module_names_equal(claim, module));
        if !claimed {
            (
                InstallHardwareCoverage::Partial,
                InstallHardwareReason::DriverUnbound,
            )
        } else {
            let module_metadata = if let Some(cached) = metadata_cache.get(module) {
                cached.clone()
            } else {
                let read = read_module_firmware(&sources.modinfo_path, kernel_release, module)?;
                metadata_cache.insert(module.to_string(), read.clone());
                read
            };
            match module_metadata {
                None => (
                    InstallHardwareCoverage::Partial,
                    InstallHardwareReason::ModuleMetadataUnavailable,
                ),
                Some(entries) => {
                    requested_firmware = entries;
                    missing_firmware = requested_firmware
                        .iter()
                        .filter(|request| !firmware_request_present(request, firmware_files))
                        .cloned()
                        .collect();
                    if missing_firmware.is_empty() {
                        (
                            InstallHardwareCoverage::Full,
                            InstallHardwareReason::DriverBound,
                        )
                    } else {
                        (
                            InstallHardwareCoverage::Partial,
                            InstallHardwareReason::FirmwareMissing,
                        )
                    }
                }
            }
        }
    };

    Ok(InstallHardwareDevice {
        bus: observed.bus,
        address: observed.address.clone(),
        function,
        display_name,
        modalias,
        vendor_id,
        device_id,
        class_id,
        driver,
        claiming_modules,
        requested_firmware,
        missing_firmware,
        coverage,
        reason,
    })
}

fn bounded_claiming_modules(
    all_claiming_modules: &BTreeSet<String>,
    bound_module: Option<&str>,
) -> Vec<String> {
    let mut claiming_modules = all_claiming_modules
        .iter()
        .take(MODULE_CLAIM_LIMIT)
        .cloned()
        .collect::<Vec<_>>();
    if let Some(bound) = bound_module
        && let Some(claim) = all_claiming_modules
            .iter()
            .find(|claim| module_names_equal(claim, bound))
        && !claiming_modules
            .iter()
            .any(|included| module_names_equal(included, claim))
    {
        if claiming_modules.len() == MODULE_CLAIM_LIMIT {
            claiming_modules.pop();
        }
        claiming_modules.push(claim.clone());
    }
    claiming_modules.sort();
    claiming_modules
}

fn load_module_aliases(path: &Path) -> io::Result<Vec<ModuleAlias>> {
    let bytes = read_bounded_file(path, MODULE_ALIASES_MAX_BYTES)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "modules.alias is not UTF-8"))?;
    let mut aliases = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("alias ") else {
            continue;
        };
        let mut fields = rest.split_ascii_whitespace();
        let (Some(pattern), Some(module), None) = (fields.next(), fields.next(), fields.next())
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "modules.alias contains a malformed alias line",
            ));
        };
        if pattern.len() > 4096 || !valid_module_name(module) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "modules.alias contains an invalid pattern or module",
            ));
        }
        aliases.push(ModuleAlias {
            pattern: pattern.to_string(),
            module: module.to_string(),
        });
        if aliases.len() > MODULE_ALIAS_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "modules.alias exceeds its fixed entry limit",
            ));
        }
    }
    Ok(aliases)
}

fn read_module_firmware(
    binary: &Path,
    kernel_release: &str,
    module: &str,
) -> io::Result<Option<Vec<String>>> {
    if !valid_kernel_release(kernel_release) || !valid_module_name(module) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "module metadata request is invalid",
        ));
    }
    let mut child = match Command::new(binary)
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("LC_ALL", "C")
        .args(["-k", kernel_release, "-F", "firmware", module])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn_busy_retry()
    {
        Ok(child) => child,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("modinfo did not provide its fixed output pipe"))?;
    let mut reader = Some(thread::spawn(move || {
        let mut bytes = Vec::new();
        Read::by_ref(&mut stdout)
            .take(MODINFO_MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        Ok::<_, io::Error>(bytes)
    }));
    let mut bytes = None;
    let started = Instant::now();
    let status = loop {
        if reader.as_ref().is_some_and(thread::JoinHandle::is_finished) {
            let completed = reader
                .take()
                .expect("reader checked above")
                .join()
                .map_err(|_| io::Error::other("modinfo output reader failed"))??;
            if completed.len() as u64 > MODINFO_MAX_BYTES {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "module firmware metadata exceeds its fixed limit",
                ));
            }
            bytes = Some(completed);
        }
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= MODINFO_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            if let Some(reader) = reader.take() {
                let _ = reader.join();
            }
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "modinfo exceeded its fixed two-second deadline",
            ));
        }
        thread::sleep(Duration::from_millis(5));
    };
    let bytes = match bytes {
        Some(bytes) => bytes,
        None => reader
            .take()
            .expect("reader is active when no bytes were collected")
            .join()
            .map_err(|_| io::Error::other("modinfo output reader failed"))??,
    };
    if bytes.len() as u64 > MODINFO_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "module firmware metadata exceeds its fixed limit",
        ));
    }
    if !status.success() {
        return Ok(None);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "module firmware metadata is not UTF-8",
        )
    })?;
    let mut entries = BTreeSet::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if !valid_firmware_request(line) {
            return Ok(None);
        }
        entries.insert(line.to_string());
        if entries.len() > FIRMWARE_REQUEST_LIMIT {
            return Ok(None);
        }
    }
    Ok(Some(entries.into_iter().collect()))
}

fn inventory_firmware(roots: &[PathBuf]) -> io::Result<BTreeSet<String>> {
    let mut files = BTreeSet::new();
    for root in roots {
        let canonical_root = match fs::canonicalize(root) {
            Ok(path) => path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        inventory_firmware_directory(&canonical_root, &canonical_root, 0, &mut files)?;
    }
    Ok(files)
}

fn inventory_firmware_directory(
    root: &Path,
    directory: &Path,
    depth: usize,
    files: &mut BTreeSet<String>,
) -> io::Result<()> {
    if depth > FIRMWARE_DEPTH_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "firmware tree exceeds its fixed depth limit",
        ));
    }
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() {
            inventory_firmware_directory(root, &path, depth + 1, files)?;
            continue;
        }
        let accepted = if file_type.is_file() {
            true
        } else if file_type.is_symlink() {
            fs::canonicalize(&path).is_ok_and(|target| target.starts_with(root))
        } else {
            false
        };
        if !accepted {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| io::Error::other("firmware path escaped its root"))?
            .to_string_lossy()
            .replace('\\', "/");
        if !relative.is_empty() {
            files.insert(relative);
        }
        if files.len() > FIRMWARE_FILE_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "firmware inventory exceeds its fixed file limit",
            ));
        }
    }
    Ok(())
}

fn firmware_request_present(request: &str, files: &BTreeSet<String>) -> bool {
    files.iter().any(|path| {
        let uncompressed = path
            .strip_suffix(".zst")
            .or_else(|| path.strip_suffix(".xz"))
            .unwrap_or(path);
        wildcard_matches(request, path) || wildcard_matches(request, uncompressed)
    })
}

fn bound_driver(path: &Path) -> io::Result<(Option<String>, Option<String>)> {
    let driver_link = path.join("driver");
    let driver = match fs::read_link(&driver_link) {
        Ok(target) => target
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| valid_module_name(name))
            .map(str::to_string),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let module = match fs::read_link(driver_link.join("module")) {
        Ok(target) => target
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| valid_module_name(name))
            .map(str::to_string),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    Ok((driver, module))
}

fn read_class_id(device: &ObservedDevice) -> io::Result<Option<String>> {
    let candidates: &[&str] = match device.bus {
        InstallHardwareBus::Pci => &["class"],
        InstallHardwareBus::Usb => &["bInterfaceClass", "bDeviceClass"],
        InstallHardwareBus::Platform => &["class"],
    };
    for candidate in candidates {
        if let Some(value) = read_identifier(&device.path, candidate)? {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn read_identifier(path: &Path, name: &str) -> io::Result<Option<String>> {
    let Some(value) = read_attribute(&path.join(name), 32)? else {
        return Ok(None);
    };
    let value = value
        .strip_prefix("0x")
        .unwrap_or(&value)
        .to_ascii_lowercase();
    if value.is_empty() || value.len() > 8 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(None);
    }
    Ok(Some(value))
}

fn classify_function(
    bus: InstallHardwareBus,
    class_id: Option<&str>,
    modalias: Option<&str>,
) -> InstallHardwareFunction {
    let class = class_id.unwrap_or_default().to_ascii_lowercase();
    let prefix = class.get(..2).unwrap_or_default();
    match bus {
        InstallHardwareBus::Pci => match prefix {
            "03" => InstallHardwareFunction::Graphics,
            "02" => InstallHardwareFunction::Network,
            "01" => InstallHardwareFunction::Storage,
            "04" => InstallHardwareFunction::Audio,
            "09" => InstallHardwareFunction::Input,
            _ => InstallHardwareFunction::Other,
        },
        InstallHardwareBus::Usb => match prefix {
            "03" => InstallHardwareFunction::Input,
            "01" => InstallHardwareFunction::Audio,
            "02" | "0a" => InstallHardwareFunction::Network,
            "08" => InstallHardwareFunction::Storage,
            "e0" => InstallHardwareFunction::Bluetooth,
            _ => InstallHardwareFunction::Other,
        },
        InstallHardwareBus::Platform => {
            let alias = modalias.unwrap_or_default().to_ascii_lowercase();
            if ["vc4", "v3d", "gpu", "display", "drm"]
                .iter()
                .any(|needle| alias.contains(needle))
            {
                InstallHardwareFunction::Graphics
            } else if ["ethernet", "wifi", "wlan", "network"]
                .iter()
                .any(|needle| alias.contains(needle))
            {
                InstallHardwareFunction::Network
            } else if ["mmc", "nvme", "storage", "sata"]
                .iter()
                .any(|needle| alias.contains(needle))
            {
                InstallHardwareFunction::Storage
            } else if alias.contains("audio") || alias.contains("sound") {
                InstallHardwareFunction::Audio
            } else if alias.contains("bluetooth") {
                InstallHardwareFunction::Bluetooth
            } else if alias.contains("input") || alias.contains("keyboard") {
                InstallHardwareFunction::Input
            } else {
                InstallHardwareFunction::Other
            }
        }
    }
}

fn display_name(
    device: &ObservedDevice,
    vendor_id: Option<&str>,
    device_id: Option<&str>,
) -> io::Result<String> {
    for candidate in ["product", "label", "name"] {
        if let Some(value) = read_attribute(&device.path.join(candidate), 256)? {
            if value.len() <= 128 && !value.chars().any(char::is_control) {
                return Ok(value);
            }
        }
    }
    Ok(match (vendor_id, device_id) {
        (Some(vendor), Some(product)) => format!(
            "{} {}:{}",
            bus_name(device.bus).to_ascii_uppercase(),
            vendor,
            product
        ),
        _ => format!(
            "{} {}",
            bus_name(device.bus).to_ascii_uppercase(),
            device.address
        ),
    })
}

fn read_attribute(path: &Path, maximum: u64) -> io::Result<Option<String>> {
    let bytes = match read_bounded_file(path, maximum) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "sysfs value is not UTF-8"))?
        .trim()
        .to_string();
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

fn read_bounded_file(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hardware source is not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hardware source exceeds its fixed size limit",
        ));
    }
    Ok(bytes)
}

fn valid_kernel_release(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
}

fn valid_module_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_firmware_request(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.starts_with('/')
        && !value.split('/').any(|component| component == "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
}

fn module_names_equal(left: &str, right: &str) -> bool {
    left.bytes()
        .map(|byte| if byte == b'-' { b'_' } else { byte })
        .eq(right
            .bytes()
            .map(|byte| if byte == b'-' { b'_' } else { byte }))
}

fn bus_name(bus: InstallHardwareBus) -> &'static str {
    match bus {
        InstallHardwareBus::Pci => "pci",
        InstallHardwareBus::Usb => "usb",
        InstallHardwareBus::Platform => "platform",
    }
}

/// ASCII wildcard matcher for the `*` and `?` grammar used by
/// `modules.alias` and module firmware metadata. No bracket, escape or shell
/// expansion exists.
fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut p, mut v, mut star, mut checkpoint) = (0, 0, None, 0);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            checkpoint = v;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            checkpoint += 1;
            v = checkpoint;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    static SEQUENCE: AtomicU32 = AtomicU32::new(0);

    fn fixture() -> (PathBuf, HardwareSources) {
        let root = std::env::temp_dir().join(format!(
            "punar-hardware-test-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&root);
        for directory in ["pci", "usb", "platform", "modules/test-kernel", "firmware"] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        fs::write(root.join("kernel-release"), "test-kernel\n").unwrap();
        fs::write(
            root.join("modules/test-kernel/modules.alias"),
            "alias pci:v00001AF4d00001050* virtio_gpu\n\
             alias pci:v00008086d00001234* test_net\n",
        )
        .unwrap();
        let modinfo = root.join("modinfo");
        fs::write(
            &modinfo,
            "#!/bin/sh\nset -eu\nmodule=$5\n\
             case \"${module}\" in\n\
               virtio_gpu) exit 0 ;;\n\
               test_net) printf '%s\\n' 'test/net.bin' ;;\n\
               *) exit 1 ;;\n\
             esac\n",
        )
        .unwrap();
        fs::set_permissions(&modinfo, fs::Permissions::from_mode(0o755)).unwrap();
        let sources = HardwareSources {
            pci_devices: root.join("pci"),
            usb_devices: root.join("usb"),
            platform_devices: root.join("platform"),
            modules_root: root.join("modules"),
            kernel_release_path: root.join("kernel-release"),
            firmware_roots: vec![root.join("firmware")],
            modinfo_path: modinfo,
        };
        (root, sources)
    }

    fn add_bound_pci(root: &Path, address: &str, modalias: &str, class: &str, module: &str) {
        let device = root.join("pci").join(address);
        let driver = root.join("drivers").join(module);
        let module_path = root.join("loaded-modules").join(module);
        fs::create_dir_all(&device).unwrap();
        fs::create_dir_all(&driver).unwrap();
        fs::create_dir_all(&module_path).unwrap();
        fs::write(device.join("modalias"), format!("{modalias}\n")).unwrap();
        fs::write(device.join("class"), format!("{class}\n")).unwrap();
        fs::write(device.join("vendor"), "0x1af4\n").unwrap();
        fs::write(device.join("device"), "0x1050\n").unwrap();
        symlink(&driver, device.join("driver")).unwrap();
        symlink(&module_path, driver.join("module")).unwrap();
    }

    #[test]
    fn report_is_offline_bounded_and_keeps_qualification_false() {
        let (root, sources) = fixture();
        add_bound_pci(
            &root,
            "0000:00:01.0",
            "pci:v00001AF4d00001050sv00000000",
            "0x030000",
            "virtio_gpu",
        );
        add_bound_pci(
            &root,
            "0000:00:02.0",
            "pci:v00008086d00001234sv00000000",
            "0x020000",
            "test_net",
        );
        let usb = root.join("usb/1-1");
        fs::create_dir(&usb).unwrap();
        fs::write(usb.join("modalias"), "usb:vFFFFpFFFFd0001\n").unwrap();
        fs::write(usb.join("bDeviceClass"), "03\n").unwrap();
        fs::write(usb.join("product"), "Fixture keyboard\n").unwrap();

        let report = observe_install_hardware(&sources, "x86_64", true).unwrap();
        assert_eq!(report.v, 1);
        assert_eq!(report.kernel_release, "test-kernel");
        assert!(report.graphics_usable);
        assert!(report.disk_below_minimum_target);
        assert!(!report.bare_hardware_qualified);
        assert_eq!(report.overall, InstallHardwareCoverage::Unsupported);
        assert_eq!(report.devices.len(), 3);
        let graphics = report
            .devices
            .iter()
            .find(|device| device.function == InstallHardwareFunction::Graphics)
            .unwrap();
        assert_eq!(graphics.coverage, InstallHardwareCoverage::Full);
        assert_eq!(graphics.reason, InstallHardwareReason::DriverBound);
        let network = report
            .devices
            .iter()
            .find(|device| device.function == InstallHardwareFunction::Network)
            .unwrap();
        assert_eq!(network.coverage, InstallHardwareCoverage::Partial);
        assert_eq!(network.reason, InstallHardwareReason::FirmwareMissing);
        assert_eq!(network.missing_firmware, ["test/net.bin"]);
        let input = report
            .devices
            .iter()
            .find(|device| device.bus == InstallHardwareBus::Usb)
            .unwrap();
        assert_eq!(input.display_name, "Fixture keyboard");
        assert_eq!(input.coverage, InstallHardwareCoverage::Unsupported);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("serial"));
        assert!(!json.contains("mac"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wildcard_grammar_matches_kernel_aliases_without_shell_expansion() {
        assert!(wildcard_matches(
            "pci:v00008086d*sv*",
            "pci:v00008086d1234sv0000"
        ));
        assert!(wildcard_matches(
            "brcm/?cm*-firmware.bin",
            "brcm/bcm43-firmware.bin"
        ));
        assert!(!wildcard_matches("usb:v1234p*", "pci:v1234p5678"));
        assert!(!wildcard_matches("foo", "foobar"));
    }

    #[test]
    fn compressed_firmware_satisfies_the_uncompressed_module_request() {
        let files = BTreeSet::from(["intel/ipu.bin.zst".to_string()]);
        assert!(firmware_request_present("intel/ipu.bin", &files));
        assert!(firmware_request_present("intel/*.bin", &files));
        assert!(!firmware_request_present("intel/missing.bin", &files));
    }

    #[test]
    fn a_bound_module_is_never_truncated_out_of_the_claim_evidence() {
        let mut all = (0..40)
            .map(|index| format!("module_{index:02}"))
            .collect::<BTreeSet<_>>();
        all.insert("zz_bound_driver".into());
        let bounded = bounded_claiming_modules(&all, Some("zz-bound-driver"));
        assert_eq!(bounded.len(), MODULE_CLAIM_LIMIT);
        assert!(bounded.iter().any(|module| module == "zz_bound_driver"));
        assert_eq!(bounded.iter().collect::<BTreeSet<_>>().len(), bounded.len());
    }

    #[test]
    fn modinfo_has_a_real_wall_clock_deadline() {
        let (root, sources) = fixture();
        fs::write(&sources.modinfo_path, "#!/bin/sh\nexec sleep 5\n").unwrap();
        fs::set_permissions(&sources.modinfo_path, fs::Permissions::from_mode(0o755)).unwrap();
        let started = Instant::now();
        let error =
            read_module_firmware(&sources.modinfo_path, "test-kernel", "virtio_gpu").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
        fs::remove_dir_all(root).unwrap();
    }
}
