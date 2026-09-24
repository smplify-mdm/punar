//! Kernel-observed storage encryption: is the filesystem a path lives on
//! backed only by LUKS2 device-mapper mappings?
//!
//! One implementation, shared by the PIM credential vault, which refuses to
//! open without it, and punard's managed-device posture, which reports it to
//! an organization. Two copies of an encryption check are two answers that can
//! disagree about the same disk.
//!
//! The answer is read from the kernel, never from a claim: sysfs names the
//! device-mapper target, and cryptsetup's `CRYPT-LUKS2-` UUID prefix names the
//! LUKS version. File permissions, mount options and configuration files are
//! not evidence. Anything that cannot be proven reads as "not encrypted"; only
//! an I/O error on evidence that exists is an error.
//!
//! Two shapes are proven:
//!
//! - A filesystem whose `st_dev` is the block device itself (ext4 or xfs on a
//!   mapping): that device's `dm/uuid`.
//! - A btrfs subvolume. Every btrfs subvolume reports its own anonymous
//!   `st_dev` — it is how `find -xdev` stops at one — which is not a block
//!   device and has no `/sys/dev/block` entry. Read the first way, Punar's
//!   `/var` and `/home`, subvolumes of one LUKS2 partition
//!   (docs/design/installer.md section 4.3), would be reported as plaintext.
//!   For btrfs, EVERY member device of the filesystem must carry the prefix:
//!   a plaintext device added to the pool would receive data too.
//!
//! The btrfs path never opens anything under `/dev`: the PIM service runs
//! with a private `/dev`, so the member is named from the mount table and
//! sysfs alone.
//!
//! A caller may also be unable to see the path it asks about. punard runs
//! with `ProtectHome=yes`, so its own `/home` is an empty directory systemd
//! mounted over the real one, and asking the path would judge the mask.
//! [`luks2_backing_of_mount`] judges the mount another namespace made (PID
//! 1's, the system's) from that namespace's mount table and sysfs, without
//! opening the path at all.

use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use zeroize::Zeroize;

const MAX_DM_UUID_BYTES: u64 = 256;
const MAX_SYSFS_TEXT_BYTES: u64 = 256;
const MAX_MOUNTINFO_BYTES: u64 = 4 * 1024 * 1024;
const LUKS2_UUID_PREFIX: &[u8] = b"CRYPT-LUKS2-";

/// Where the kernel publishes the evidence. Production uses the fixed paths
/// in [`StorageSources::default`]; tests point every field at a fixture tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageSources {
    /// `/sys/dev/block`: one entry per block device, named `major:minor`.
    pub sys_dev_block: PathBuf,
    /// `/sys/class/block`: the same devices, by kernel name (`dm-0`).
    pub sys_class_block: PathBuf,
    /// `/sys/fs/btrfs`: one directory per mounted btrfs, listing its members.
    pub sys_fs_btrfs: PathBuf,
    /// `/proc/self/mountinfo`, read in the caller's own mount namespace.
    pub mountinfo: PathBuf,
}

impl Default for StorageSources {
    fn default() -> Self {
        Self {
            sys_dev_block: PathBuf::from("/sys/dev/block"),
            sys_class_block: PathBuf::from("/sys/class/block"),
            sys_fs_btrfs: PathBuf::from("/sys/fs/btrfs"),
            mountinfo: PathBuf::from("/proc/self/mountinfo"),
        }
    }
}

/// Proof that a path's filesystem is backed only by LUKS2 mappings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Luks2Backing {
    /// `st_dev` of the nearest existing ancestor of the path that was asked
    /// about, so a caller can bind later use to the same filesystem.
    pub dev: u64,
    /// The proven block devices, `major:minor`, sorted. One for a plain
    /// filesystem; every member for btrfs.
    pub devices: Vec<String>,
}

/// One `/proc/self/mountinfo` line, the fields anything here needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    /// `major:minor` of the filesystem: its block device when it sits on
    /// one, an anonymous `0:N` otherwise (btrfs, tmpfs, overlay).
    pub device: String,
    pub mount_point: PathBuf,
    pub fstype: String,
    pub source: String,
}

/// `st_dev` of the nearest existing ancestor of `path` (the path itself when
/// it exists), or `None` when nothing on the way up exists.
pub fn nearest_existing_device(path: &Path) -> io::Result<Option<u64>> {
    match nearest_existing(path) {
        Some(existing) => Ok(Some(fs::metadata(existing)?.dev())),
        None => Ok(None),
    }
}

/// Prove that `path`'s filesystem is backed only by LUKS2 mappings. `None`
/// is "not proven", which every caller treats as "not encrypted".
pub fn luks2_backing(path: &Path, sources: &StorageSources) -> io::Result<Option<Luks2Backing>> {
    let Some(existing) = nearest_existing(path) else {
        return Ok(None);
    };
    let dev = fs::metadata(existing)?.dev();
    let device = format!("{}:{}", rustix::fs::major(dev), rustix::fs::minor(dev));

    // The filesystem sits directly on a block device: that device decides.
    let direct = sources.sys_dev_block.join(&device);
    if direct.exists() {
        return Ok(
            dm_uuid_is_luks2(&direct.join("dm/uuid"))?.then(|| Luks2Backing {
                dev,
                devices: vec![device],
            }),
        );
    }

    // An anonymous st_dev. Only btrfs is proven this way; tmpfs, overlay and
    // FUSE have no backing device to prove, and a FUSE mount chooses its own
    // source text, so the filesystem type is checked before the source is
    // believed.
    let canonical = fs::canonicalize(existing)?;
    let mount = match mount_containing(&canonical, &sources.mountinfo) {
        Ok(Some(mount)) => mount,
        Ok(None) => return Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if mount.fstype != "btrfs" {
        return Ok(None);
    }
    Ok(match btrfs_members_luks2(&mount.source, sources)? {
        Members::Luks2(devices) => Some(Luks2Backing { dev, devices }),
        Members::NotLuks2 | Members::Unseen => None,
    })
}

/// Prove that the filesystem mounted where `path` lives, as the mount table
/// at `sources.mountinfo` records it, is backed only by LUKS2 mappings —
/// without opening `path`. This is for a caller whose own view of the path is
/// not the system's: punard runs with `ProtectHome=yes`, so its `/home` is an
/// empty mask, and reading PID 1's table (`/proc/1/mountinfo`) judges the
/// mount the system actually made. `path` is taken as the table names it:
/// absolute, with no symbolic link to resolve.
///
/// Three answers, because only one of them may be reported as "not
/// encrypted":
///
/// - `Ok(Some(devices))`: proven, the `major:minor` of every backing device.
/// - `Ok(None)`: the evidence says otherwise. The filesystem sits on a block
///   device that is not a LUKS2 mapping, is btrfs with a member that is not
///   one, or has no backing device at all.
/// - `Err`: the evidence cannot be seen. The table is unreadable or names no
///   mount for the path, or it names a btrfs device that sysfs does not
///   publish as a member of a mounted btrfs.
pub fn luks2_backing_of_mount(
    path: &Path,
    sources: &StorageSources,
) -> io::Result<Option<Vec<String>>> {
    let Some(mount) = mount_containing(path, &sources.mountinfo)? else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the mount table names no mount for the path",
        ));
    };
    let direct = sources.sys_dev_block.join(&mount.device);
    if direct.exists() {
        return Ok(dm_uuid_is_luks2(&direct.join("dm/uuid"))?.then(|| vec![mount.device]));
    }
    if mount.fstype != "btrfs" {
        return Ok(None);
    }
    match btrfs_members_luks2(&mount.source, sources)? {
        Members::Luks2(devices) => Ok(Some(devices)),
        Members::NotLuks2 => Ok(None),
        Members::Unseen => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "sysfs publishes no mounted btrfs with this member",
        )),
    }
}

/// What sysfs says about the members of the btrfs a mount source names.
enum Members {
    /// Every member is a LUKS2 mapping: their `major:minor`, sorted.
    Luks2(Vec<String>),
    /// At least one member is not.
    NotLuks2,
    /// The source names no device sysfs knows as a mounted btrfs member.
    Unseen,
}

/// For btrfs, EVERY member device of the filesystem must carry the prefix: a
/// plaintext device added to the pool would receive data too.
fn btrfs_members_luks2(source: &str, sources: &StorageSources) -> io::Result<Members> {
    let Some(name) = block_device_name(source, &sources.sys_class_block)? else {
        return Ok(Members::Unseen);
    };
    let Some(members) = btrfs_members(&name, &sources.sys_fs_btrfs)? else {
        return Ok(Members::Unseen);
    };
    let mut devices = Vec::with_capacity(members.len());
    for member in members {
        let block = sources.sys_class_block.join(&member);
        if !dm_uuid_is_luks2(&block.join("dm/uuid"))? {
            return Ok(Members::NotLuks2);
        }
        let Some(number) = read_sysfs_text(&block.join("dev"))? else {
            return Ok(Members::NotLuks2);
        };
        devices.push(number);
    }
    devices.sort();
    Ok(Members::Luks2(devices))
}

/// The mount `path` lives on: the longest mount point that contains it, and
/// the LAST such line when several share it, because a later mount on the
/// same point shadows the earlier one. `path` must already be canonical.
pub fn mount_containing(path: &Path, mountinfo: &Path) -> io::Result<Option<MountEntry>> {
    let mut input = Vec::new();
    File::open(mountinfo)?
        .take(MAX_MOUNTINFO_BYTES + 1)
        .read_to_end(&mut input)?;
    if input.len() as u64 > MAX_MOUNTINFO_BYTES {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&input);
    let mut best: Option<MountEntry> = None;
    for entry in text.lines().filter_map(parse_mountinfo_line) {
        if !path.starts_with(&entry.mount_point) {
            continue;
        }
        let deeper = best.as_ref().is_none_or(|current| {
            entry.mount_point.components().count() >= current.mount_point.components().count()
        });
        if deeper {
            best = Some(entry);
        }
    }
    Ok(best)
}

fn nearest_existing(path: &Path) -> Option<&Path> {
    let mut existing = path;
    while !existing.exists() {
        existing = existing.parent()?;
    }
    Some(existing)
}

/// `36 35 98:0 /root /mnt rw,noatime master:1 - ext3 /dev/root rw` → the
/// device, mount point, type and source. The optional fields end at a lone
/// `-`.
fn parse_mountinfo_line(line: &str) -> Option<MountEntry> {
    let mut fields = line.split(' ');
    let device = fields.nth(2)?;
    let mount_point = fields.nth(1)?;
    let mut rest = fields.skip_while(|field| *field != "-");
    rest.next()?;
    let fstype = rest.next()?;
    let source = rest.next()?;
    Some(MountEntry {
        device: device.to_string(),
        mount_point: PathBuf::from(unescape_mount_field(mount_point)),
        fstype: unescape_mount_field(fstype),
        source: unescape_mount_field(source),
    })
}

/// The kernel writes space, tab, newline and backslash in mount fields as
/// three-digit octal escapes (`\040`).
fn unescape_mount_field(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let digits = &bytes[i + 1..i + 4];
            if digits.iter().all(|d| (b'0'..=b'7').contains(d)) {
                let value = digits
                    .iter()
                    .fold(0u32, |acc, d| acc * 8 + u32::from(d - b'0'));
                if let Ok(byte) = u8::try_from(value) {
                    out.push(byte);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The kernel name (`dm-0`, `nvme0n1p4`) of a btrfs mount source. btrfs
/// reports the path its member was opened by; a `/dev/mapper/<name>` path is
/// matched against the names device-mapper publishes in sysfs, anything else
/// under `/dev` must already be a kernel name. Nothing under `/dev` is read.
fn block_device_name(source: &str, sys_class_block: &Path) -> io::Result<Option<String>> {
    if let Some(mapped) = source.strip_prefix("/dev/mapper/") {
        if mapped.is_empty() || mapped.contains('/') {
            return Ok(None);
        }
        let entries = match fs::read_dir(sys_class_block) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry = entry?;
            if read_sysfs_text(&entry.path().join("dm/name"))?.as_deref() == Some(mapped) {
                return Ok(Some(entry.file_name().to_string_lossy().into_owned()));
            }
        }
        return Ok(None);
    }
    let Some(name) = source.strip_prefix("/dev/") else {
        return Ok(None);
    };
    if name.is_empty() || name.contains('/') || !sys_class_block.join(name).exists() {
        return Ok(None);
    }
    Ok(Some(name.to_string()))
}

/// Every member of the mounted btrfs that `member` belongs to, by kernel
/// name, or `None` when no mounted btrfs lists it.
fn btrfs_members(member: &str, sys_fs_btrfs: &Path) -> io::Result<Option<Vec<String>>> {
    let filesystems = match fs::read_dir(sys_fs_btrfs) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    for filesystem in filesystems {
        let devices = filesystem?.path().join("devices");
        if !devices.join(member).exists() {
            continue;
        }
        let mut members = Vec::new();
        for entry in fs::read_dir(&devices)? {
            members.push(entry?.file_name().to_string_lossy().into_owned());
        }
        members.sort();
        return Ok(Some(members));
    }
    Ok(None)
}

/// Whether a `dm/uuid` file names a LUKS2 crypt target. Absent is `false`
/// (not a mapping, or not readable as one). The UUID is wiped after the
/// comparison: it identifies the disk, and nothing here needs to keep it.
fn dm_uuid_is_luks2(path: &Path) -> io::Result<bool> {
    let Ok(input) = File::open(path) else {
        return Ok(false);
    };
    let mut uuid = Vec::new();
    input.take(MAX_DM_UUID_BYTES + 1).read_to_end(&mut uuid)?;
    if uuid.len() as u64 > MAX_DM_UUID_BYTES {
        uuid.zeroize();
        return Ok(false);
    }
    while uuid.last().is_some_and(u8::is_ascii_whitespace) {
        uuid.pop();
    }
    let verified = uuid.starts_with(LUKS2_UUID_PREFIX)
        && uuid.len() > LUKS2_UUID_PREFIX.len()
        && uuid
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(byte));
    uuid.zeroize();
    Ok(verified)
}

/// A short sysfs attribute, trimmed; `None` when absent, oversized or blank.
fn read_sysfs_text(path: &Path) -> io::Result<Option<String>> {
    let input = match File::open(path) {
        Ok(input) => input,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    input
        .take(MAX_SYSFS_TEXT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SYSFS_TEXT_BYTES {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&bytes).trim().to_string();
    Ok((!text.is_empty()).then_some(text))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static SEQ: AtomicU64 = AtomicU64::new(0);

    struct Tree(PathBuf);

    impl Tree {
        fn new(tag: &str) -> Tree {
            let root = std::env::temp_dir().join(format!(
                "punar-storage-{tag}-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            Tree(root)
        }

        fn sources(&self) -> StorageSources {
            StorageSources {
                sys_dev_block: self.0.join("sys/dev/block"),
                sys_class_block: self.0.join("sys/class/block"),
                sys_fs_btrfs: self.0.join("sys/fs/btrfs"),
                mountinfo: self.0.join("mountinfo"),
            }
        }

        fn data(&self) -> PathBuf {
            let data = self.0.join("data");
            fs::create_dir_all(&data).unwrap();
            data
        }

        fn write(&self, relative: &str, contents: &str) {
            let path = self.0.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }

        /// A btrfs mount of `data` whose one member is `dm-0` (LUKS2 when
        /// `luks` is true) — the Punar data partition, in miniature.
        fn btrfs(&self, luks: bool) -> PathBuf {
            let data = self.data();
            let canonical = fs::canonicalize(&data).unwrap();
            self.write(
                "mountinfo",
                &format!(
                    "22 1 253:1 / / ro,relatime - erofs /dev/mapper/root ro\n\
                     40 22 0:44 /@var {} rw,noatime - btrfs /dev/mapper/punar-data rw,subvol=/@var\n",
                    canonical.display()
                ),
            );
            self.write("sys/class/block/dm-0/dm/name", "punar-data\n");
            self.write("sys/class/block/dm-0/dev", "253:0\n");
            self.write(
                "sys/class/block/dm-0/dm/uuid",
                if luks {
                    "CRYPT-LUKS2-0123456789abcdef-punar-data\n"
                } else {
                    "LVM-plain\n"
                },
            );
            self.write("sys/class/block/dm-1/dm/name", "root\n");
            fs::create_dir_all(self.0.join("sys/fs/btrfs/9f1c/devices/dm-0")).unwrap();
            fs::create_dir_all(self.0.join("sys/fs/btrfs/features")).unwrap();
            data
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn device_of(path: &Path) -> String {
        let dev = fs::metadata(path).unwrap().dev();
        format!("{}:{}", rustix::fs::major(dev), rustix::fs::minor(dev))
    }

    /// The direct shape: the device st_dev names decides, by its dm UUID.
    #[test]
    fn a_filesystem_on_a_luks2_mapping_is_proven_and_nothing_else_is() {
        let tree = Tree::new("direct");
        let data = tree.data();
        let sources = tree.sources();
        let device = device_of(&data);

        assert_eq!(luks2_backing(&data, &sources).unwrap(), None, "no evidence");

        let dm = sources.sys_dev_block.join(&device).join("dm");
        fs::create_dir_all(&dm).unwrap();
        for plaintext in [
            "LVM-0123",
            "CRYPT-LUKS1-0123-old",
            "CRYPT-LUKS2-",
            "CRYPT-LUKS2-0123 space",
        ] {
            fs::write(dm.join("uuid"), plaintext).unwrap();
            assert_eq!(luks2_backing(&data, &sources).unwrap(), None, "{plaintext}");
        }
        fs::write(dm.join("uuid"), "x".repeat(300)).unwrap();
        assert_eq!(luks2_backing(&data, &sources).unwrap(), None, "oversized");

        fs::write(dm.join("uuid"), "CRYPT-LUKS2-0123456789abcdef-punar-data\n").unwrap();
        let proven = luks2_backing(&data.join("not/yet/created"), &sources)
            .unwrap()
            .expect("a path that does not exist yet is judged by its ancestor");
        assert_eq!(proven.devices, [device.as_str()]);
        assert_eq!(proven.dev, fs::metadata(&data).unwrap().dev());
        assert_eq!(
            nearest_existing_device(&data.join("not/yet")).unwrap(),
            Some(proven.dev)
        );
    }

    /// Punar's layout: /var and /home are btrfs subvolumes with anonymous
    /// st_dev numbers. The member behind the mount is proven instead.
    #[test]
    fn a_btrfs_subvolume_is_proven_through_every_member_device() {
        let tree = Tree::new("btrfs");
        let data = tree.btrfs(true);
        let sources = tree.sources();
        let proven = luks2_backing(&data.join("lib/punar"), &sources)
            .unwrap()
            .expect("the subvolume's one member is LUKS2");
        assert_eq!(proven.devices, ["253:0"]);

        // A plaintext device added to the pool receives data too.
        tree.write("sys/class/block/sda1/dev", "8:1\n");
        fs::create_dir_all(tree.0.join("sys/fs/btrfs/9f1c/devices/sda1")).unwrap();
        assert_eq!(luks2_backing(&data, &sources).unwrap(), None);
    }

    #[test]
    fn a_btrfs_member_without_a_luks2_uuid_is_not_proven() {
        let tree = Tree::new("btrfs-plain");
        let data = tree.btrfs(false);
        assert_eq!(luks2_backing(&data, &tree.sources()).unwrap(), None);
    }

    /// A FUSE filesystem chooses its own source text. Naming the encrypted
    /// device there proves nothing, and neither does any non-btrfs type.
    #[test]
    fn only_btrfs_may_name_its_member_through_the_mount_source() {
        let tree = Tree::new("fuse");
        let data = tree.btrfs(true);
        let canonical = fs::canonicalize(&data).unwrap();
        for fstype in ["fuse.sshfs", "overlay", "tmpfs"] {
            tree.write(
                "mountinfo",
                &format!(
                    "40 22 0:44 / {} rw - {fstype} /dev/mapper/punar-data rw\n",
                    canonical.display()
                ),
            );
            assert_eq!(
                luks2_backing(&data, &tree.sources()).unwrap(),
                None,
                "{fstype}"
            );
        }
        // A source that is not a device path names nothing.
        tree.write(
            "mountinfo",
            &format!(
                "40 22 0:44 / {} rw - btrfs UUID=9f1c rw\n",
                canonical.display()
            ),
        );
        assert_eq!(luks2_backing(&data, &tree.sources()).unwrap(), None);
    }

    /// Longest prefix wins, by path component; a later mount on the same
    /// point shadows the earlier one; escaped mount points are unescaped.
    #[test]
    fn the_mount_table_resolves_the_mount_a_path_lives_on() {
        let tree = Tree::new("mountinfo");
        tree.write(
            "mountinfo",
            "22 1 253:1 / / ro - erofs /dev/mapper/root ro\n\
             30 22 0:40 / /var rw shared:1 master:2 - btrfs /dev/mapper/punar-data rw\n\
             31 22 0:41 / /variable rw - ext4 /dev/sdb1 rw\n\
             32 30 0:42 / /var rw - tmpfs tmpfs rw\n\
             33 22 0:43 / /mnt/a\\040b rw - ext4 /dev/sdc1 rw\n\
             malformed line\n",
        );
        let info = tree.0.join("mountinfo");
        let at = |path: &str| mount_containing(Path::new(path), &info).unwrap().unwrap();
        assert_eq!(at("/").fstype, "erofs");
        assert_eq!(at("/usr/bin").mount_point, PathBuf::from("/"));
        assert_eq!(at("/var/lib").fstype, "tmpfs", "the later mount shadows");
        assert_eq!(at("/var/lib").device, "0:42");
        assert_eq!(at("/variable/x").source, "/dev/sdb1");
        assert_eq!(at("/mnt/a b/c").source, "/dev/sdc1");
        assert_eq!(at("/mnt/ab").fstype, "erofs");
        assert!(mount_containing(Path::new("/"), &tree.0.join("absent")).is_err());
    }

    /// punard's own `/home` is systemd's `ProtectHome=yes` mask: an empty
    /// tmpfs directory. The system's table (PID 1's) still records the btrfs
    /// subvolume the person's files live on, and that is what is proven —
    /// without opening the path, which the caller could not see.
    #[test]
    fn a_hidden_path_is_proven_from_the_systems_mount_table() {
        let tree = Tree::new("hidden");
        tree.btrfs(true);
        // One table per case: each is a different system.
        let system = |name: &str, lines: &str| {
            tree.write(name, lines);
            StorageSources {
                mountinfo: tree.0.join(name),
                ..tree.sources()
            }
        };
        let punar = "22 1 253:1 / / ro - erofs /dev/mapper/root ro\n\
                     40 22 0:44 /@var /var rw - btrfs /dev/mapper/punar-data rw,subvol=/@var\n\
                     41 22 0:44 /@home /home rw - btrfs /dev/mapper/punar-data rw,subvol=/@home\n";
        let sources = system("punar", punar);
        for path in ["/home", "/home/ada/notes", "/var"] {
            assert_eq!(
                luks2_backing_of_mount(Path::new(path), &sources).unwrap(),
                Some(vec!["253:0".to_string()]),
                "{path}"
            );
        }
        // A mask stacked in the SAME table would win, as it does for the
        // path itself: the table is trusted only as the namespace it names.
        let masked = system(
            "masked",
            &format!("{punar}90 41 0:25 /systemd/inaccessible/dir /home ro - tmpfs tmpfs rw\n"),
        );
        assert_eq!(
            luks2_backing_of_mount(Path::new("/home"), &masked).unwrap(),
            None
        );

        // Evidence of plaintext: a block device that is not a LUKS2 mapping,
        // or a btrfs member that is not one.
        tree.write("sys/dev/block/8:2/dev", "8:2\n");
        let plain = system(
            "plain",
            &format!("{punar}50 22 8:2 / /home rw - ext4 /dev/sda2 rw\n"),
        );
        assert_eq!(
            luks2_backing_of_mount(Path::new("/home"), &plain).unwrap(),
            None
        );
        tree.write("sys/dev/block/8:2/dm/uuid", "CRYPT-LUKS2-00ff-home\n");
        assert_eq!(
            luks2_backing_of_mount(Path::new("/home"), &plain).unwrap(),
            Some(vec!["8:2".to_string()])
        );
        tree.write("sys/class/block/sda1/dev", "8:1\n");
        fs::create_dir_all(tree.0.join("sys/fs/btrfs/9f1c/devices/sda1")).unwrap();
        assert_eq!(
            luks2_backing_of_mount(Path::new("/home"), &sources).unwrap(),
            None
        );

        // No evidence at all is not evidence of plaintext.
        let unseen = system(
            "unseen",
            "41 1 0:44 /@home /home rw - btrfs /dev/mapper/other rw\n",
        );
        assert!(luks2_backing_of_mount(Path::new("/home"), &unseen).is_err());
        let empty = system("empty", "");
        assert!(luks2_backing_of_mount(Path::new("/home"), &empty).is_err());
        let absent = StorageSources {
            mountinfo: tree.0.join("absent"),
            ..tree.sources()
        };
        assert!(luks2_backing_of_mount(Path::new("/home"), &absent).is_err());
    }
}
