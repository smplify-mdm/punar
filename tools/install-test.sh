#!/usr/bin/env bash
# Destructively install the final ISO onto one exact disposable qcow2 target,
# then inspect the resulting GPT, LUKS2 header and btrfs subvolume topology.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ISO=${1:-}
PROOF_DIR=${2:-"${REPO_ROOT}/os/images/out/installer-install-proof"}
TARGET_BYTES=$((128 * 1024 * 1024 * 1024))
CI_PASSPHRASE='punar-ci-only-vm-passphrase'

die() {
    echo "install-test: FAIL: $*" >&2
    exit 1
}

[ -n "${ISO}" ] || die "usage: $0 INSTALLER_ISO [PROOF_DIR]"
[ -f "${ISO}" ] || die "installer ISO is missing: ${ISO}"
for command in qemu-system-x86_64 qemu-img qemu-nbd sfdisk cryptsetup btrfs \
    blkid jq python3; do
    command -v "${command}" >/dev/null || die "${command} is required"
done

OVMF_CODE=''
OVMF_VARS=''
for pair in \
    "/usr/share/OVMF/OVMF_CODE_4M.fd:/usr/share/OVMF/OVMF_VARS_4M.fd" \
    "/usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd" \
    "/usr/share/edk2/x64/OVMF_CODE.4m.fd:/usr/share/edk2/x64/OVMF_VARS.4m.fd" \
    "/usr/share/edk2/x64/OVMF_CODE.fd:/usr/share/edk2/x64/OVMF_VARS.fd"
do
    code=${pair%%:*}
    vars=${pair##*:}
    if [ -f "${code}" ] && [ -f "${vars}" ]; then
        OVMF_CODE=${code}
        OVMF_VARS=${vars}
        break
    fi
done
[ -n "${OVMF_CODE}" ] || die 'no supported x86_64 OVMF firmware was found'

if [ "$(uname -m)" = x86_64 ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    ACCEL=kvm
    CPU=host
    DEFAULT_TIMEOUT=1800
else
    ACCEL=tcg
    CPU=max
    DEFAULT_TIMEOUT=7200
    echo 'install-test: warning: KVM unavailable; using TCG' >&2
fi
TIMEOUT=${PUNAR_INSTALL_TIMEOUT:-${DEFAULT_TIMEOUT}}

mkdir -p "${PROOF_DIR}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/punar-install-test.XXXXXX")"
TARGET_DISK="${WORKDIR}/installed-target.qcow2"
VARS_COPY="${WORKDIR}/OVMF_VARS.fd"
SERIAL_LOG="${PROOF_DIR}/install-serial.log"
RUNTIME_LOG="${PROOF_DIR}/install-runtime-proof.log"
APPLY_LOG="${PROOF_DIR}/install-apply-proof.log"
QEMU_LOG="${PROOF_DIR}/install-qemu.log"
NBD_DEVICE=/dev/nbd0
MAPPER_NAME="punar-ci-data-$$"
MOUNT_DIR="${WORKDIR}/data-top"
QEMU_PID=''
NBD_ATTACHED=0
MAPPER_OPEN=0
DATA_MOUNTED=0

cleanup() {
    if [ -n "${QEMU_PID}" ] && kill -0 "${QEMU_PID}" 2>/dev/null; then
        kill "${QEMU_PID}" 2>/dev/null || true
        wait "${QEMU_PID}" 2>/dev/null || true
    fi
    if [ "${DATA_MOUNTED}" -eq 1 ]; then
        sudo umount "${MOUNT_DIR}" 2>/dev/null || true
    fi
    if [ "${MAPPER_OPEN}" -eq 1 ]; then
        sudo cryptsetup close "${MAPPER_NAME}" 2>/dev/null || true
    fi
    if [ "${NBD_ATTACHED}" -eq 1 ]; then
        sudo qemu-nbd --disconnect "${NBD_DEVICE}" >/dev/null 2>&1 || true
    fi
    rm -rf -- "${WORKDIR}"
}
trap cleanup EXIT INT TERM

cp "${OVMF_VARS}" "${VARS_COPY}"
: > "${SERIAL_LOG}"
: > "${RUNTIME_LOG}"
: > "${APPLY_LOG}"
qemu-img create -q -f qcow2 "${TARGET_DISK}" "${TARGET_BYTES}"

echo "==> attended encrypted install (${ACCEL}; disposable ${TARGET_BYTES}-byte target)"
qemu-system-x86_64 \
    -machine "q35,accel=${ACCEL}" \
    -cpu "${CPU}" \
    -m 4096 \
    -smp 4 \
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}" \
    -drive "if=pflash,format=raw,file=${VARS_COPY}" \
    -cdrom "${ISO}" \
    -drive "file=${TARGET_DISK},format=qcow2,if=none,id=punartarget" \
    -device "virtio-blk-pci,drive=punartarget,serial=PUNAR-CI-TARGET" \
    -nic none \
    -display none \
    -serial "file:${SERIAL_LOG}" \
    -monitor none \
    -device virtio-serial-pci \
    -chardev "file,id=runtimeproof,path=${RUNTIME_LOG}" \
    -device "virtserialport,chardev=runtimeproof,name=punar.install-proof" \
    -chardev "file,id=applyproof,path=${APPLY_LOG}" \
    -device "virtserialport,chardev=applyproof,name=punar.install-apply-proof" \
    -no-reboot \
    > "${QEMU_LOG}" 2>&1 &
QEMU_PID=$!
started=$(date +%s)

while :; do
    if grep -aq '^PUNAR_INSTALL_APPLY_FAIL' "${APPLY_LOG}"; then
        tail -n 160 "${SERIAL_LOG}" >&2 || true
        cat "${RUNTIME_LOG}" >&2 || true
        cat "${APPLY_LOG}" >&2 || true
        die 'the live installer rejected or failed the destructive proof'
    fi
    if grep -aq '^PUNAR_INSTALL_APPLY_OK plan_token=[0-9a-f]\{64\}$' "${APPLY_LOG}"; then
        break
    fi
    if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
        QEMU_PID=''
        tail -n 160 "${SERIAL_LOG}" >&2 || true
        cat "${RUNTIME_LOG}" >&2 || true
        cat "${APPLY_LOG}" >&2 || true
        tail -n 100 "${QEMU_LOG}" >&2 || true
        die 'QEMU exited before install.apply completed'
    fi
    now=$(date +%s)
    if [ "$((now - started))" -ge "${TIMEOUT}" ]; then
        tail -n 160 "${SERIAL_LOG}" >&2 || true
        cat "${RUNTIME_LOG}" >&2 || true
        cat "${APPLY_LOG}" >&2 || true
        die "timed out after ${TIMEOUT}s waiting for install.apply"
    fi
    sleep 1
done
finished=$(date +%s)
kill "${QEMU_PID}" 2>/dev/null || true
wait "${QEMU_PID}" 2>/dev/null || true
QEMU_PID=''

echo '==> inspect installed GPT, LUKS2 and btrfs topology'
sudo modprobe nbd max_part=8
[ ! -e "/sys/class/block/${NBD_DEVICE##*/}/pid" ] \
    || die "${NBD_DEVICE} is already attached"
sudo qemu-nbd --connect="${NBD_DEVICE}" "${TARGET_DISK}"
NBD_ATTACHED=1
sudo udevadm settle
for partition in 1 2 3 4; do
    [ -b "${NBD_DEVICE}p${partition}" ] \
        || die "installed partition ${partition} was not discovered"
done

sudo sfdisk --json "${NBD_DEVICE}" \
    | tee "${PROOF_DIR}/sfdisk.json" >/dev/null
python3 - \
    "${PROOF_DIR}/sfdisk.json" \
    "${TARGET_BYTES}" \
    "${REPO_ROOT}/os/images/repart.d/install/20-root-a.conf" \
    "${REPO_ROOT}/os/images/repart.d/install/30-root-b.conf" \
    "${REPO_ROOT}/os/images/repart.d/install/50-data.conf" \
    > "${PROOF_DIR}/layout-report.json" <<'PY'
import json
import pathlib
import sys

table_path, target_bytes, root_a_path, root_b_path, data_path = sys.argv[1:]
table = json.loads(pathlib.Path(table_path).read_text())["partitiontable"]
parts = table.get("partitions", [])
sector = int(table.get("sectorsize", 512))
expected_types = [
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
    "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
    "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
    "0fc63daf-8483-4772-8e79-3d69d8477de4",
]

def configured_uuid(path):
    for line in pathlib.Path(path).read_text().splitlines():
        if line.startswith("UUID="):
            return line.split("=", 1)[1].lower()
    raise SystemExit(f"install-layout-contract: FAIL: no UUID in {path}")

if len(parts) != 4:
    raise SystemExit(f"install-layout-contract: FAIL: expected 4 partitions, found {len(parts)}")
types = [part.get("type", "").lower() for part in parts]
if types != expected_types:
    raise SystemExit(f"install-layout-contract: FAIL: wrong ordered type GUIDs: {types}")
sizes = [int(part["size"]) * sector for part in parts]
if sizes[0] < 1024**3:
    raise SystemExit("install-layout-contract: FAIL: ESP is smaller than 1 GiB")
if sizes[1:3] != [8 * 1024**3, 8 * 1024**3]:
    raise SystemExit(f"install-layout-contract: FAIL: root slot sizes are {sizes[1:3]}")
uuids = [part.get("uuid", "").lower() for part in parts]
expected_uuids = [configured_uuid(root_a_path), configured_uuid(root_b_path), configured_uuid(data_path)]
if uuids[1:] != expected_uuids or uuids[1] == uuids[2]:
    raise SystemExit(f"install-layout-contract: FAIL: fixed PARTUUID contract changed: {uuids[1:]}")
end_bytes = (int(parts[3]["start"]) + int(parts[3]["size"])) * sector
free_bytes = int(target_bytes) - end_bytes
if free_bytes < 0 or free_bytes >= 1024**2:
    raise SystemExit(f"install-layout-contract: FAIL: trailing free space is {free_bytes} bytes")
print(json.dumps({
    "assertions": ["I08", "I09", "I10", "I11"],
    "partition_count": len(parts),
    "type_guids": types,
    "partuuids": uuids,
    "size_bytes": sizes,
    "trailing_free_bytes": free_bytes,
}, sort_keys=True, separators=(",", ":")))
PY

[ "$(sudo blkid -p -s TYPE -o value "${NBD_DEVICE}p1")" = vfat ] \
    || die 'partition 1 is not vfat'
sudo cryptsetup isLuks "${NBD_DEVICE}p4" \
    || die 'partition 4 is not a LUKS container'
sudo cryptsetup luksDump --dump-json-metadata "${NBD_DEVICE}p4" \
    | tee "${PROOF_DIR}/luks-metadata.json" >/dev/null
jq -e '.keyslots | to_entries | any(.value.kdf.type == "argon2id")' \
    "${PROOF_DIR}/luks-metadata.json" >/dev/null \
    || die 'the LUKS2 header has no argon2id keyslot'
luks_uuid=$(sudo cryptsetup luksUUID "${NBD_DEVICE}p4")
[ -n "${luks_uuid}" ] || die 'the LUKS2 header has no UUID'
if git -C "${REPO_ROOT}" grep -F -- "${luks_uuid}" >/dev/null; then
    die 'the per-device LUKS UUID is a committed literal'
fi

printf '%s' "${CI_PASSPHRASE}" \
    | sudo cryptsetup open --type luks2 --key-file=- \
        "${NBD_DEVICE}p4" "${MAPPER_NAME}"
MAPPER_OPEN=1
mkdir -p "${MOUNT_DIR}"
sudo mount -t btrfs -o ro,subvolid=5 \
    "/dev/mapper/${MAPPER_NAME}" "${MOUNT_DIR}"
DATA_MOUNTED=1
sudo btrfs subvolume list -o "${MOUNT_DIR}" \
    | awk '{print $NF}' | LC_ALL=C sort > "${PROOF_DIR}/btrfs-subvolumes.txt"
printf '%s\n' '@home' '@var' '@var-tmp' > "${WORKDIR}/expected-subvolumes.txt"
cmp -s "${WORKDIR}/expected-subvolumes.txt" "${PROOF_DIR}/btrfs-subvolumes.txt" \
    || die 'the encrypted data volume does not contain exactly @var, @home and @var-tmp'

sudo umount "${MOUNT_DIR}"
DATA_MOUNTED=0
sudo cryptsetup close "${MAPPER_NAME}"
MAPPER_OPEN=0
sudo qemu-nbd --disconnect "${NBD_DEVICE}" >/dev/null
NBD_ATTACHED=0

printf 'I08-I13 PASS target_bytes=%s luks_uuid=%s elapsed_seconds=%s\n' \
    "${TARGET_BYTES}" "${luks_uuid}" "$((finished - started))" \
    > "${PROOF_DIR}/result.txt"
echo "install-test: PASS (I08-I13; $((finished - started))s, ${ACCEL})"
