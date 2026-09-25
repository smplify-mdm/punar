//! `device.posture`: the person at the device reads the posture and hardware
//! their organization would receive, from the same collector, plus the
//! batteries. An open read, like `status`.
//!
//! Every fact comes from a fixture machine, so no assertion depends on the
//! host running the test.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use punar_common::storage::StorageSources;
use punard::authz::{Peer, PeerSource};
use punard::capability::Registry;
use punard::capability::mock::MockCapability;
use punard::device::DeviceSources;
use punard::inventory::CollectorSources;
use punard::server::{Daemon, DaemonConfig, DaemonHandle};
use punard::update_status::UpdateStatusSources;
use serde_json::{Value, json};

static SEQ: AtomicU32 = AtomicU32::new(0);

fn write_file(path: &Path, contents: impl AsRef<[u8]>) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

/// A QEMU x86_64 guest under UEFI with Secure Boot on, a TPM 2.0, a battery
/// beside mains power, and `/var` and `/home` on one btrfs over the mapping
/// `punar-data`, whose UUID is `dm_uuid`.
fn machine(root: &Path, dm_uuid: &str) -> (CollectorSources, UpdateStatusSources) {
    let at = |relative: &str| root.join(relative);
    write_file(&at("proc/meminfo"), "MemTotal:        8192000 kB\n");
    write_file(&at("sys/devices/system/cpu/online"), "0-3\n");
    write_file(
        &at("proc/cpuinfo"),
        "processor\t: 0\nvendor_id\t: AuthenticAMD\nmodel name\t: QEMU Virtual CPU\n\
         flags\t\t: fpu hypervisor\n",
    );
    write_file(&at("sys/class/dmi/id/sys_vendor"), "QEMU\n");
    write_file(
        &at("sys/class/dmi/id/product_name"),
        "Standard PC (Q35 + ICH9, 2009)\n",
    );
    write_file(
        &at("sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
        [6u8, 0, 0, 0, 1],
    );
    write_file(&at("sys/class/tpm/tpm0/tpm_version_major"), "2\n");
    write_file(&at("sys/class/power_supply/AC/type"), "Mains\n");
    write_file(&at("sys/class/power_supply/BAT0/capacity"), "64\n");
    write_file(&at("sys/class/power_supply/BAT0/status"), "Charging\n");
    fs::create_dir_all(at("var")).unwrap();
    fs::create_dir_all(at("home")).unwrap();
    let mounts = format!(
        "22 1 253:1 / / ro,relatime - erofs /dev/mapper/usr ro\n\
         40 22 0:44 /@var {} rw - btrfs /dev/mapper/punar-data rw,subvol=/@var\n\
         41 22 0:44 /@home {} rw - btrfs /dev/mapper/punar-data rw,subvol=/@home\n",
        at("var").display(),
        at("home").display()
    );
    write_file(&at("proc/1/mountinfo"), &mounts);
    write_file(&at("proc/self/mountinfo"), &mounts);
    write_file(&at("sys/class/block/dm-0/dm/name"), "punar-data\n");
    write_file(&at("sys/class/block/dm-0/dev"), "253:0\n");
    write_file(&at("sys/class/block/dm-0/dm/uuid"), format!("{dm_uuid}\n"));
    fs::create_dir_all(at("sys/fs/btrfs/9f1c/devices/dm-0")).unwrap();
    write_file(&at("proc/cmdline"), "quiet rw\n");
    write_file(
        &root.join("os-release"),
        "ID=punar\nIMAGE_VERSION=2026.09.01.1\n",
    );

    let collector = CollectorSources {
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
        system_mountinfo: at("proc/1/mountinfo"),
        encrypted_paths: vec![at("var"), at("home")],
        capacity_path: root.to_path_buf(),
        desktop_entry_dirs: vec![at("usr/share/applications")],
        flatpak_installation: at("var/lib/flatpak"),
        detect_virt_bin: at("bin/systemd-detect-virt"),
    };
    let update_status = UpdateStatusSources {
        os_release: root.join("os-release"),
        cmdline: at("proc/cmdline"),
        pi_boot_partition: at("proc/device-tree/chosen/bootloader/partition"),
        pi_tryboot: at("proc/device-tree/chosen/bootloader/tryboot"),
        health_report: at("run/punar/update-health.json"),
        pending_pi: at("var/lib/punar/update/pending-pi.json"),
        pending_uefi: at("var/lib/punar/update/pending-uefi.json"),
        channel_preference: at("var/lib/punar/update/channel"),
        dpkg_status: at("var/lib/dpkg/status"),
        pacman_local: at("var/lib/pacman/local"),
    };
    (collector, update_status)
}

struct TestDaemon {
    dir: PathBuf,
    handle: Option<DaemonHandle>,
}

impl TestDaemon {
    /// A daemon on the fixture machine, answering an ordinary person (uid
    /// 1000): the read is open, as `status` is.
    fn start(dm_uuid: &str) -> TestDaemon {
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("punard-posture-{}-{seq}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let group_file = dir.join("group");
        fs::write(&group_file, "root:x:0:\npunar:x:970:\n").unwrap();
        let passwd_file = dir.join("passwd");
        fs::write(
            &passwd_file,
            "root:x:0:0::/root:/bin/bash\npunar:x:1000:1000::/home/punar:/bin/nologin\n",
        )
        .unwrap();
        let state_dir = dir.join("state");
        fs::create_dir_all(&state_dir).unwrap();
        let (inventory_sources, update_status_sources) = machine(&dir.join("machine"), dm_uuid);
        let firewall = MockCapability::new("security.firewall", json!("enabled"));
        let registry = Registry::new(vec![Box::new(firewall)]);
        let cfg = DaemonConfig {
            group_file,
            passwd_file,
            peer_source: PeerSource::Fixed(Peer {
                uid: 1000,
                gid: 1000,
                pid: None,
            }),
            io_timeout: Duration::from_secs(5),
            inventory_sources,
            update_status_sources,
            ..DaemonConfig::new(dir.join("punard.sock"), state_dir, dir.join("audit.jsonl"))
        };
        let daemon = Daemon::new(cfg, registry).unwrap();
        daemon.boot_reconcile();
        let handle = daemon.spawn().unwrap();
        TestDaemon {
            dir,
            handle: Some(handle),
        }
    }

    fn call(&self, method: &str, params: Option<Value>) -> Value {
        let mut request = json!({ "v": 1, "id": "t-1", "method": method });
        if let Some(params) = params {
            request["params"] = params;
        }
        let mut stream = UnixStream::connect(self.handle.as_ref().unwrap().socket_path()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(format!("{request}\n").as_bytes()).unwrap();
        let mut response = String::new();
        BufReader::new(stream).read_line(&mut response).unwrap();
        serde_json::from_str(&response).unwrap()
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.stop();
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// The whole answer on a fixture machine: posture, hardware and power, to an
/// ordinary person.
#[test]
fn device_posture_answers_a_person_with_posture_hardware_and_power() {
    let daemon = TestDaemon::start("CRYPT-LUKS2-0123456789abcdef-punar-data");
    let response = daemon.call("device.posture", None);
    let result = &response["result"];
    assert!(response.get("error").is_none(), "{response}");

    let posture = &result["posture"];
    assert_eq!(posture["uefi"], true, "{posture}");
    assert_eq!(posture["secure_boot"], true, "{posture}");
    assert_eq!(posture["tpm_present"], true, "{posture}");
    assert_eq!(posture["tpm_version"], "2.0", "{posture}");
    assert_eq!(posture["is_virtual"], true, "{posture}");
    assert_eq!(posture["disk_encryption_enabled"], true, "{posture}");
    assert_eq!(posture["firewall_enabled"], true, "{posture}");
    assert_eq!(posture["firewall"], "nftables", "{posture}");
    assert_eq!(posture["os_patch_status"], "unknown", "{posture}");

    let hardware = &result["hardware"];
    assert_eq!(hardware["manufacturer"], "QEMU", "{hardware}");
    assert_eq!(hardware["cpu_threads"], 4, "{hardware}");
    assert_eq!(
        hardware["memory_total_bytes"],
        8192000u64 * 1024,
        "{hardware}"
    );
    assert_eq!(hardware["battery_present"], true, "{hardware}");

    assert_eq!(
        result["power"],
        json!({"batteries": [{"name": "BAT0", "capacity_percent": 64, "status": "Charging"}]})
    );
    assert!(
        result["checked_at"]
            .as_str()
            .is_some_and(|at| at.ends_with('Z'))
    );
    // Nothing a person reads here is what only an organization-owned device
    // sends: there is no serial number and no application list.
    assert!(result.get("identifiers").is_none() && result.get("applications").is_none());
}

/// One LUKS2 answer: a data path whose mapping is not LUKS2 makes the disk
/// "not encrypted", by the same proof the managed inventory uses.
#[test]
fn device_posture_reports_a_plaintext_mapping_as_not_encrypted() {
    let daemon = TestDaemon::start("LVM-0123456789abcdef");
    let response = daemon.call("device.posture", None);
    assert_eq!(
        response["result"]["posture"]["disk_encryption_enabled"], false,
        "{response}"
    );
}

/// The method takes no params, like every closed read.
#[test]
fn device_posture_refuses_params() {
    let daemon = TestDaemon::start("CRYPT-LUKS2-0123456789abcdef-punar-data");
    let response = daemon.call("device.posture", Some(json!({"path": "/etc/shadow"})));
    assert_eq!(response["error"]["code"], "invalid_params", "{response}");
}
