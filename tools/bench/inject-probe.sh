#!/usr/bin/env bash
# Inject the benchmark probe into a disposable disk image, offline.
#
#   sudo tools/bench/inject-probe.sh --image DISK (--partlabel LABEL | --partnum N) \
#       [--luks-key-file FILE] [--os-subdir @] [--then HOOK] --record OUT.json
#
# DISK is a raw image or a qcow2 (qcow2 needs qemu-nbd and the nbd module;
# raw needs only loop devices, which is why CI converts to raw first). The
# partition is found by its GPT label (Punar's PUNAR-ROOT-A) or its number
# (Omarchy's archinstall layout names none); with --luks-key-file it is opened
# with cryptsetup; with --os-subdir the filesystem's top level is mounted and
# the operating system is taken from that subdirectory (Omarchy's btrfs "@").
# The key file holds the passphrase that was typed at the installer and is
# typed at every boot, so trailing CR/LF is stripped before cryptsetup sees
# it (`--key-file` would otherwise use the newline as part of the key); the
# stripped copy lives in a private directory and is removed at once.
#
# What it writes into the OS tree, and nothing else:
#   /etc/systemd/system/bench-probe.service
#   /etc/systemd/system/multi-user.target.wants/bench-probe.service (link)
#   /usr/local/lib/bench-probe/{bench-probe.sh,bench-workload.sh,INJECTED}
# --then runs HOOK with BENCH_MOUNT (filesystem top) and BENCH_OSROOT set,
# before unmounting (the Omarchy lane's stock restore uses it).
#
# The record lists every file written with its SHA-256, so a result can be
# traced to the exact probe bytes. Must run as root on Linux; on macOS run it
# inside a privileged Linux container (tools/bench/README.md).
set -euo pipefail
umask 022

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE=""
PARTLABEL=""
PARTNUM=""
KEY_FILE=""
OS_SUBDIR=""
HOOK=""
RECORD=""

die() {
    echo "inject-probe: $*" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --image) IMAGE="$2"; shift 2 ;;
        --partlabel) PARTLABEL="$2"; shift 2 ;;
        --partnum) PARTNUM="$2"; shift 2 ;;
        --luks-key-file) KEY_FILE="$2"; shift 2 ;;
        --os-subdir) OS_SUBDIR="$2"; shift 2 ;;
        --then) HOOK="$2"; shift 2 ;;
        --record) RECORD="$2"; shift 2 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ -n "${IMAGE}" ] && [ -f "${IMAGE}" ] || die "--image must name an existing disk image"
[ -n "${PARTLABEL}" ] || [ -n "${PARTNUM}" ] || die "--partlabel or --partnum is required"
case "${PARTNUM}" in *[!0-9]*) die "--partnum must be a number" ;; esac
[ -n "${RECORD}" ] || die "--record is required"
case "${OS_SUBDIR}" in *..*|/*) die "--os-subdir must be a relative name" ;; esac
[ "$(id -u)" -eq 0 ] || die "must run as root"
for tool in sfdisk losetup mount umount python3 sha256sum; do
    command -v "${tool}" >/dev/null 2>&1 || die "${tool} is required"
done

NBD=""
LOOP=""
MAPPER=""
MNT=""
KEY_DIR=""
cleanup() {
    set +e
    if [ -n "${MNT}" ]; then
        mountpoint -q "${MNT}" && umount "${MNT}"
        rmdir "${MNT}"
    fi
    [ -n "${MAPPER}" ] && cryptsetup close "${MAPPER}"
    [ -n "${LOOP}" ] && losetup -d "${LOOP}"
    [ -n "${NBD}" ] && qemu-nbd --disconnect "${NBD}" >/dev/null
    [ -n "${KEY_DIR}" ] && rm -rf -- "${KEY_DIR}"
}
trap cleanup EXIT

source_dev="${IMAGE}"
case "$(head -c 4 "${IMAGE}" | od -An -c | tr -d ' ')" in
    QFI*)
        command -v qemu-nbd >/dev/null 2>&1 || die "a qcow2 image needs qemu-nbd; convert it to raw instead"
        [ -e /dev/nbd0 ] || modprobe nbd max_part=0 2>/dev/null || true
        for candidate in /dev/nbd*; do
            case "${candidate}" in /dev/nbd*p*) continue ;; esac
            [ -b "${candidate}" ] || continue
            if [ "$(cat "/sys/block/${candidate##*/}/size" 2>/dev/null || echo 0)" = 0 ]; then
                qemu-nbd --connect="${candidate}" --format=qcow2 "${IMAGE}"
                NBD="${candidate}"
                break
            fi
        done
        [ -n "${NBD}" ] || die "no free /dev/nbd device (modprobe nbd)"
        for _ in $(seq 1 50); do
            [ "$(cat "/sys/block/${NBD##*/}/size")" != 0 ] && break
            sleep 0.1
        done
        source_dev="${NBD}"
        ;;
esac

# Partition by GPT label, attached by offset so no partition device nodes
# (and no udev) are needed.
read -r start size < <(sfdisk --json "${source_dev}" | python3 -c '
import json, sys
label, number = sys.argv[1], sys.argv[2]
table = json.load(sys.stdin)["partitiontable"]
sector = table.get("sectorsize", 512)
for index, part in enumerate(table["partitions"], 1):
    if (label and part.get("name") == label) or (not label and str(index) == number):
        print(part["start"] * sector, part["size"] * sector)
        break
else:
    sys.exit("no partition " + (("labelled " + label) if label else ("number " + number)))
' "${PARTLABEL}" "${PARTNUM}")
LOOP="$(losetup --find --show --offset "${start}" --sizelimit "${size}" "${source_dev}")"
fs_dev="${LOOP}"
if [ -n "${KEY_FILE}" ]; then
    command -v cryptsetup >/dev/null 2>&1 || die "--luks-key-file needs cryptsetup"
    [ -r "${KEY_FILE}" ] || die "--luks-key-file ${KEY_FILE} is not readable"
    KEY_DIR="$(mktemp -d /tmp/bench-inject-key.XXXXXX)"
    chmod 0700 "${KEY_DIR}"
    # The typed passphrase: the file's bytes without trailing CR/LF.
    python3 - "${KEY_FILE}" "${KEY_DIR}/key" <<'PY'
import os, sys
data = open(sys.argv[1], "rb").read().rstrip(b"\r\n")
if not data:
    sys.exit("inject-probe: the key file is empty")
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as handle:
    handle.write(data)
PY
    MAPPER="bench-inject-$$"
    cryptsetup open --key-file "${KEY_DIR}/key" "${LOOP}" "${MAPPER}"
    rm -f -- "${KEY_DIR}/key"
    fs_dev="/dev/mapper/${MAPPER}"
fi
MNT="$(mktemp -d /tmp/bench-inject.XXXXXX)"
fstype="$(blkid -o value -s TYPE "${fs_dev}" 2>/dev/null || true)"
if [ "${fstype}" = btrfs ] && [ -n "${OS_SUBDIR}" ]; then
    mount -o subvolid=5 "${fs_dev}" "${MNT}"
else
    mount "${fs_dev}" "${MNT}"
fi
OSROOT="${MNT}${OS_SUBDIR:+/${OS_SUBDIR}}"
[ -d "${OSROOT}/etc" ] && [ -d "${OSROOT}/usr" ] \
    || die "${PARTLABEL:-partition ${PARTNUM}}${OS_SUBDIR:+/${OS_SUBDIR}} does not look like an OS root (no /etc and /usr)"

install -d -m 0755 "${OSROOT}/usr/local/lib/bench-probe" \
    "${OSROOT}/etc/systemd/system/multi-user.target.wants"
install -m 0755 "${HERE}/bench-probe.sh" "${OSROOT}/usr/local/lib/bench-probe/bench-probe.sh"
install -m 0644 "${HERE}/workload/bench-workload.sh" "${OSROOT}/usr/local/lib/bench-probe/bench-workload.sh"
install -m 0644 "${HERE}/bench-probe.service" "${OSROOT}/etc/systemd/system/bench-probe.service"
ln -sfn ../bench-probe.service "${OSROOT}/etc/systemd/system/multi-user.target.wants/bench-probe.service"
{
    echo "This disk is a benchmark copy. tools/bench/inject-probe.sh added:"
    echo "  /etc/systemd/system/bench-probe.service"
    echo "  /etc/systemd/system/multi-user.target.wants/bench-probe.service"
    echo "  /usr/local/lib/bench-probe/"
} > "${OSROOT}/usr/local/lib/bench-probe/INJECTED"

if [ -n "${HOOK}" ]; then
    BENCH_MOUNT="${MNT}" BENCH_OSROOT="${OSROOT}" "${HOOK}"
fi

python3 - "${RECORD}" "${OSROOT}" "${IMAGE}" "${PARTLABEL:-#${PARTNUM}}" "${OS_SUBDIR}" "${fstype}" <<'PY'
import hashlib, json, os, sys
record, osroot, image, label, subdir, fstype = sys.argv[1:7]
files = [
    "etc/systemd/system/bench-probe.service",
    "usr/local/lib/bench-probe/bench-probe.sh",
    "usr/local/lib/bench-probe/bench-workload.sh",
    "usr/local/lib/bench-probe/INJECTED",
]
out = {
    "schema": "punar-bench-injection/1",
    "image": os.path.basename(image),
    "partition": label,
    "os_subdir": subdir,
    "fstype": fstype,
    "files": {f: hashlib.sha256(open(os.path.join(osroot, f), "rb").read()).hexdigest() for f in files},
    "links": {"etc/systemd/system/multi-user.target.wants/bench-probe.service": os.readlink(
        os.path.join(osroot, "etc/systemd/system/multi-user.target.wants/bench-probe.service"))},
}
with open(record, "w") as handle:
    json.dump(out, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
sync
echo "inject-probe: probe injected into ${PARTLABEL:-partition ${PARTNUM}}${OS_SUBDIR:+/${OS_SUBDIR}} of $(basename "${IMAGE}")"
