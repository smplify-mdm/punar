#!/usr/bin/env bash
# Plan against one exact disposable disk, authorize that exact plan with an
# ephemeral key, then exercise the production signed PUNAR_ANSWR consumer
# and inspect the resulting GPT, LUKS2 and btrfs topology. No committed test
# key or CI-only destructive executor exists.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ISO=${1:-}
PROOF_DIR=${2:-"${REPO_ROOT}/os/images/out/installer-install-proof"}
RELEASE_TOOL=${3:-${PUNAR_RELEASE_TOOL:-"${REPO_ROOT}/os/images/cache/cargo-target/release/punar-release-tool"}}
TARGET_BYTES=$((128 * 1024 * 1024 * 1024))
SMALL_TARGET_BYTES=$((20 * 1024 * 1024 * 1024))

die() {
    echo "install-test: FAIL: $*" >&2
    exit 1
}

[ "$#" -le 3 ] || die "usage: $0 INSTALLER_ISO [PROOF_DIR] [PUNAR_RELEASE_TOOL]"
[ -n "${ISO}" ] || die "usage: $0 INSTALLER_ISO [PROOF_DIR] [PUNAR_RELEASE_TOOL]"
[ -f "${ISO}" ] || die "installer ISO is missing: ${ISO}"
[ -x "${RELEASE_TOOL}" ] \
    || die "release verifier is missing or not executable: ${RELEASE_TOOL}"
for command in qemu-system-x86_64 qemu-img qemu-nbd sfdisk cryptsetup btrfs \
    blkid jq python3 xorriso mkfs.vfat mcopy sha256sum; do
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
SMALL_TARGET_DISK="${WORKDIR}/undersized-target.qcow2"
ANSWER_DISK="${WORKDIR}/punar-answers.img"
ANSWER_DOCUMENT="${WORKDIR}/answers.json"
ANSWER_SIGNATURE="${WORKDIR}/answers.json.sig"
REFUSAL_ANSWER_DISK="${WORKDIR}/punar-refusal-answers.img"
REFUSAL_ANSWER_DOCUMENT="${WORKDIR}/refusal-answers.json"
REFUSAL_ANSWER_SIGNATURE="${WORKDIR}/refusal-answers.json.sig"
ANSWER_SIGNING_SEED="${WORKDIR}/answers-signing.seed"
ANSWER_PUBLIC_RAW="${WORKDIR}/answers-signing.pub"
ANSWER_PUBLIC_HEX="${WORKDIR}/answers-signing.pub.hex"
RELEASE_DOCUMENT="${WORKDIR}/release.json"
CUSTODY_DOCUMENT="${WORKDIR}/custody.json"
SECRET_PATTERNS="${WORKDIR}/secret-patterns.txt"
VARS_COPY="${WORKDIR}/OVMF_VARS.fd"
SERIAL_LOG="${PROOF_DIR}/install-serial.log"
RUNTIME_LOG="${PROOF_DIR}/install-runtime-proof.log"
UNATTENDED_LOG="${PROOF_DIR}/install-unattended-proof.log"
REFUSAL_LOG="${PROOF_DIR}/install-refusal-proof.log"
REFUSAL_SERIAL_LOG="${PROOF_DIR}/install-refusal-serial.log"
ADMISSION_REFUSAL_LOG="${PROOF_DIR}/install-admission-refusal-proof.log"
ADMISSION_REFUSAL_SERIAL_LOG="${PROOF_DIR}/install-admission-refusal-serial.log"
QEMU_LOG="${PROOF_DIR}/install-qemu.log"
TARGET_PREFIX_BEFORE="${WORKDIR}/target-prefix-before.bin"
TARGET_PREFIX_AFTER="${WORKDIR}/target-prefix-after.bin"
ADMISSION_LARGE_PREFIX_BEFORE="${WORKDIR}/admission-large-prefix-before.bin"
ADMISSION_LARGE_PREFIX_AFTER="${WORKDIR}/admission-large-prefix-after.bin"
ADMISSION_SMALL_PREFIX_BEFORE="${WORKDIR}/admission-small-prefix-before.bin"
ADMISSION_SMALL_PREFIX_AFTER="${WORKDIR}/admission-small-prefix-after.bin"
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
: > "${UNATTENDED_LOG}"
: > "${REFUSAL_LOG}"
: > "${REFUSAL_SERIAL_LOG}"
: > "${ADMISSION_REFUSAL_LOG}"
: > "${ADMISSION_REFUSAL_SERIAL_LOG}"
: > "${QEMU_LOG}"
qemu-img create -q -f qcow2 "${TARGET_DISK}" "${TARGET_BYTES}"
qemu-img create -q -f qcow2 "${SMALL_TARGET_DISK}" "${SMALL_TARGET_BYTES}"

echo "==> discover and plan the blank target (${ACCEL}; zero target writes)"
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
    -no-reboot \
    >> "${QEMU_LOG}" 2>&1 &
QEMU_PID=$!
started=$(date +%s)

while :; do
    if grep -aq '^PUNAR_INSTALL_RUNTIME_FAIL' "${RUNTIME_LOG}"; then
        tail -n 160 "${SERIAL_LOG}" >&2 || true
        cat "${RUNTIME_LOG}" >&2 || true
        die 'the live installer could not produce a read-only target plan'
    fi
    if grep -aq '^PUNAR_INSTALL_RUNTIME_END$' "${RUNTIME_LOG}"; then
        break
    fi
    if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
        QEMU_PID=''
        tail -n 160 "${SERIAL_LOG}" >&2 || true
        cat "${RUNTIME_LOG}" >&2 || true
        tail -n 100 "${QEMU_LOG}" >&2 || true
        die 'QEMU exited before install.plan completed'
    fi
    now=$(date +%s)
    if [ "$((now - started))" -ge "${TIMEOUT}" ]; then
        tail -n 160 "${SERIAL_LOG}" >&2 || true
        cat "${RUNTIME_LOG}" >&2 || true
        die "timed out after ${TIMEOUT}s waiting for install.plan"
    fi
    sleep 1
done
kill "${QEMU_PID}" 2>/dev/null || true
wait "${QEMU_PID}" 2>/dev/null || true
QEMU_PID=''

plan_json=$(sed -n 's/^PUNAR_INSTALL_PLAN_JSON=//p' "${RUNTIME_LOG}" | tail -n 1)
[ -n "${plan_json}" ] || die 'the runtime proof did not export a plan'
plan_token=$(printf '%s' "${plan_json}" | jq -er '.plan_token') \
    || die 'the exported plan has no plan_token'
target_serial=$(printf '%s' "${plan_json}" | jq -er '.plan.disk.serial') \
    || die 'the exported plan has no target serial'
release_id=$(printf '%s' "${plan_json}" | jq -er '.plan.payload.release_id') \
    || die 'the exported plan has no release id'
[ "${target_serial}" = PUNAR-CI-TARGET ] \
    || die 'the exported plan targeted a different disk'

echo '==> prove undersized, stale-plan and managed-agent refusals (zero target writes)'
qemu-img dd -f qcow2 bs=1M count=1 \
    "if=${TARGET_DISK}" "of=${ADMISSION_LARGE_PREFIX_BEFORE}" >/dev/null
qemu-img dd -f qcow2 bs=1M count=1 \
    "if=${SMALL_TARGET_DISK}" "of=${ADMISSION_SMALL_PREFIX_BEFORE}" >/dev/null
cp "${OVMF_VARS}" "${VARS_COPY}"
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
    -drive "file=${SMALL_TARGET_DISK},format=qcow2,if=none,id=punarsmall" \
    -device "virtio-blk-pci,drive=punarsmall,serial=PUNAR-CI-SMALL" \
    -nic none \
    -display none \
    -serial "file:${ADMISSION_REFUSAL_SERIAL_LOG}" \
    -monitor none \
    -device virtio-serial-pci \
    -chardev "file,id=admissionproof,path=${ADMISSION_REFUSAL_LOG}" \
    -device "virtserialport,chardev=admissionproof,name=punar.install-refusal-proof" \
    -no-reboot \
    >> "${QEMU_LOG}" 2>&1 &
QEMU_PID=$!
started=$(date +%s)
while :; do
    if grep -aq '^PUNAR_INSTALL_REFUSALS_OK I36a=invalid_params I36b=invalid_params I36d=denied ' \
        "${ADMISSION_REFUSAL_LOG}"; then
        break
    fi
    if grep -aq '^PUNAR_INSTALL_REFUSALS_FAIL ' "${ADMISSION_REFUSAL_LOG}"; then
        tail -n 160 "${ADMISSION_REFUSAL_SERIAL_LOG}" >&2 || true
        cat "${ADMISSION_REFUSAL_LOG}" >&2 || true
        die 'the privileged live environment could not prove all installer admission refusals'
    fi
    if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
        QEMU_PID=''
        tail -n 160 "${ADMISSION_REFUSAL_SERIAL_LOG}" >&2 || true
        cat "${ADMISSION_REFUSAL_LOG}" >&2 || true
        tail -n 100 "${QEMU_LOG}" >&2 || true
        die 'QEMU exited before the installer admission refusals completed'
    fi
    now=$(date +%s)
    if [ "$((now - started))" -ge "${TIMEOUT}" ]; then
        tail -n 160 "${ADMISSION_REFUSAL_SERIAL_LOG}" >&2 || true
        cat "${ADMISSION_REFUSAL_LOG}" >&2 || true
        die "timed out after ${TIMEOUT}s waiting for installer admission refusals"
    fi
    sleep 1
done
kill "${QEMU_PID}" 2>/dev/null || true
wait "${QEMU_PID}" 2>/dev/null || true
QEMU_PID=''
qemu-img dd -f qcow2 bs=1M count=1 \
    "if=${TARGET_DISK}" "of=${ADMISSION_LARGE_PREFIX_AFTER}" >/dev/null
qemu-img dd -f qcow2 bs=1M count=1 \
    "if=${SMALL_TARGET_DISK}" "of=${ADMISSION_SMALL_PREFIX_AFTER}" >/dev/null
cmp -s "${ADMISSION_LARGE_PREFIX_BEFORE}" "${ADMISSION_LARGE_PREFIX_AFTER}" \
    || die 'an admission refusal changed the 128 GiB target'
cmp -s "${ADMISSION_SMALL_PREFIX_BEFORE}" "${ADMISSION_SMALL_PREFIX_AFTER}" \
    || die 'the undersized-disk refusal changed the 20 GiB target'
sha256sum \
    "${ADMISSION_LARGE_PREFIX_BEFORE}" "${ADMISSION_LARGE_PREFIX_AFTER}" \
    "${ADMISSION_SMALL_PREFIX_BEFORE}" "${ADMISSION_SMALL_PREFIX_AFTER}" \
    > "${PROOF_DIR}/admission-prefix-sha256.txt"
printf '%s\n' \
    'I36a,I36b,I36d PASS typed_verdicts=invalid_params,invalid_params,denied first_mib=byte_identical' \
    > "${PROOF_DIR}/admission-refusal-result.txt"

xorriso -osirrox on -indev "${ISO}" -extract /punar/release.json \
    "${RELEASE_DOCUMENT}" >/dev/null 2>&1 \
    || die 'could not extract the exact release manifest from the ISO'
[ "$(jq -er '.release_id' "${RELEASE_DOCUMENT}")" = "${release_id}" ] \
    || die 'the plan and ISO release ids differ'
release_manifest_sha256=$(sha256sum "${RELEASE_DOCUMENT}" | awk '{print $1}')
head -c 32 /dev/urandom > "${ANSWER_SIGNING_SEED}"
chmod 600 "${ANSWER_SIGNING_SEED}"
"${RELEASE_TOOL}" public-key "${ANSWER_SIGNING_SEED}" "${ANSWER_PUBLIC_RAW}"
od -An -tx1 -v "${ANSWER_PUBLIC_RAW}" | tr -d ' \n' > "${ANSWER_PUBLIC_HEX}"
printf '\n' >> "${ANSWER_PUBLIC_HEX}"
authorization_id=$(head -c 16 "${ANSWER_SIGNING_SEED}" | od -An -tx1 -v | tr -d ' \n')
issued_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
expires_at=$(date -u -d '+1 hour' '+%Y-%m-%dT%H:%M:%SZ')
jq -n \
    --arg authorization_id "${authorization_id}" \
    --arg issued_at "${issued_at}" \
    --arg expires_at "${expires_at}" \
    --arg plan_token "${plan_token}" \
    --arg target_serial "${target_serial}" \
    --arg release_id "${release_id}" \
    --arg release_manifest_sha256 "${release_manifest_sha256}" \
    '{v:1,kind:"punar_unattended_install",authorization_id:$authorization_id,
      issued_at:$issued_at,expires_at:$expires_at,plan_token:$plan_token,
      target_serial:$target_serial,confirm_destroy_disk:$target_serial,
      release_id:$release_id,release_manifest_sha256:$release_manifest_sha256,
      keymap:"us",locale:"C.UTF-8",encryption:"luks2",
      recovery_mode:"personal_copy",passphrase_source:"generated",
      recovery_key_ack:"unattended"}' > "${ANSWER_DOCUMENT}"
"${RELEASE_TOOL}" sign "${ANSWER_SIGNING_SEED}" \
    "${ANSWER_DOCUMENT}" "${ANSWER_SIGNATURE}"

echo '==> refuse a signed answer for the wrong destruction confirmation (zero target writes)'
qemu-img dd -f qcow2 bs=1M count=1 \
    "if=${TARGET_DISK}" "of=${TARGET_PREFIX_BEFORE}" >/dev/null
jq '.confirm_destroy_disk = "PUNAR-CI-WRONG-DISK"' \
    "${ANSWER_DOCUMENT}" > "${REFUSAL_ANSWER_DOCUMENT}"
"${RELEASE_TOOL}" sign "${ANSWER_SIGNING_SEED}" \
    "${REFUSAL_ANSWER_DOCUMENT}" "${REFUSAL_ANSWER_SIGNATURE}"
truncate -s 8M "${REFUSAL_ANSWER_DISK}"
mkfs.vfat -n PUNAR_ANSWR "${REFUSAL_ANSWER_DISK}" >/dev/null
mcopy -i "${REFUSAL_ANSWER_DISK}" "${REFUSAL_ANSWER_DOCUMENT}" ::answers.json
mcopy -i "${REFUSAL_ANSWER_DISK}" "${REFUSAL_ANSWER_SIGNATURE}" ::answers.json.sig

cp "${OVMF_VARS}" "${VARS_COPY}"
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
    -drive "file=${REFUSAL_ANSWER_DISK},format=raw,if=none,id=punaranswers" \
    -device "virtio-blk-pci,drive=punaranswers,serial=PUNAR-CI-ANSWERS" \
    -fw_cfg "name=opt/punar/install-answer-key,file=${ANSWER_PUBLIC_HEX}" \
    -nic none \
    -display none \
    -serial "file:${REFUSAL_SERIAL_LOG}" \
    -monitor none \
    -device virtio-serial-pci \
    -chardev "file,id=refusalproof,path=${REFUSAL_LOG}" \
    -device "virtserialport,chardev=refusalproof,name=punar.install-unattended-proof" \
    -no-reboot \
    >> "${QEMU_LOG}" 2>&1 &
QEMU_PID=$!
started=$(date +%s)
while :; do
    if grep -aq '^PUNAR_UNATTENDED_INSTALL_OK ' "${REFUSAL_LOG}"; then
        die 'a mismatched destruction confirmation was accepted'
    fi
    if grep -aq '^Unattended installation stopped\.' "${REFUSAL_LOG}"; then
        break
    fi
    if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
        QEMU_PID=''
        tail -n 160 "${REFUSAL_SERIAL_LOG}" >&2 || true
        cat "${REFUSAL_LOG}" >&2 || true
        tail -n 100 "${QEMU_LOG}" >&2 || true
        die 'QEMU exited before the mismatched destruction confirmation was refused'
    fi
    now=$(date +%s)
    if [ "$((now - started))" -ge "${TIMEOUT}" ]; then
        tail -n 160 "${REFUSAL_SERIAL_LOG}" >&2 || true
        cat "${REFUSAL_LOG}" >&2 || true
        die "timed out after ${TIMEOUT}s waiting for the signed-answer refusal"
    fi
    sleep 1
done
kill "${QEMU_PID}" 2>/dev/null || true
wait "${QEMU_PID}" 2>/dev/null || true
QEMU_PID=''
grep -aFq 'the target serial does not match the authorized disk' "${REFUSAL_LOG}" \
    || die 'the signed-answer refusal did not name the mismatched target serial'
qemu-img dd -f qcow2 bs=1M count=1 \
    "if=${TARGET_DISK}" "of=${TARGET_PREFIX_AFTER}" >/dev/null
cmp -s "${TARGET_PREFIX_BEFORE}" "${TARGET_PREFIX_AFTER}" \
    || die 'the refused signed answer changed the target disk'
printf '%s\n' \
    'I36c PASS signed_wrong_confirm_destroy_disk=refused first_mib=byte_identical' \
    > "${PROOF_DIR}/refusal-result.txt"

truncate -s 8M "${ANSWER_DISK}"
mkfs.vfat -n PUNAR_ANSWR "${ANSWER_DISK}" >/dev/null
mcopy -i "${ANSWER_DISK}" "${ANSWER_DOCUMENT}" ::answers.json
mcopy -i "${ANSWER_DISK}" "${ANSWER_SIGNATURE}" ::answers.json.sig

echo '==> signed unattended encrypted install with removable key custody'
cp "${OVMF_VARS}" "${VARS_COPY}"
: > "${SERIAL_LOG}"
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
    -drive "file=${ANSWER_DISK},format=raw,if=none,id=punaranswers" \
    -device "virtio-blk-pci,drive=punaranswers,serial=PUNAR-CI-ANSWERS" \
    -fw_cfg "name=opt/punar/install-answer-key,file=${ANSWER_PUBLIC_HEX}" \
    -nic none \
    -display none \
    -serial "file:${SERIAL_LOG}" \
    -monitor none \
    -device virtio-serial-pci \
    -chardev "file,id=unattendedproof,path=${UNATTENDED_LOG}" \
    -device "virtserialport,chardev=unattendedproof,name=punar.install-unattended-proof" \
    -no-reboot \
    >> "${QEMU_LOG}" 2>&1 &
QEMU_PID=$!
started=$(date +%s)
while :; do
    if grep -aq '^PUNAR_UNATTENDED_INSTALL_OK ' "${UNATTENDED_LOG}"; then
        break
    fi
    if grep -aq '^Unattended installation stopped\.' "${UNATTENDED_LOG}"; then
        tail -n 160 "${SERIAL_LOG}" >&2 || true
        cat "${UNATTENDED_LOG}" >&2 || true
        die 'the production unattended installer refused or failed the signed answer medium'
    fi
    if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
        QEMU_PID=''
        tail -n 160 "${SERIAL_LOG}" >&2 || true
        cat "${UNATTENDED_LOG}" >&2 || true
        tail -n 100 "${QEMU_LOG}" >&2 || true
        die 'QEMU exited before unattended install completed'
    fi
    now=$(date +%s)
    if [ "$((now - started))" -ge "${TIMEOUT}" ]; then
        tail -n 160 "${SERIAL_LOG}" >&2 || true
        cat "${UNATTENDED_LOG}" >&2 || true
        die "timed out after ${TIMEOUT}s waiting for unattended install"
    fi
    sleep 1
done
finished=$(date +%s)
kill "${QEMU_PID}" 2>/dev/null || true
wait "${QEMU_PID}" 2>/dev/null || true
QEMU_PID=''
mcopy -i "${ANSWER_DISK}" ::custody.json "${CUSTODY_DOCUMENT}" \
    || die 'unattended install did not return custody.json to the answer medium'
jq -e \
    --arg authorization_id "${authorization_id}" \
    --arg plan_token "${plan_token}" \
    --arg target_serial "${target_serial}" \
    --arg release_id "${release_id}" \
    '.v == 1 and .kind == "punar_unattended_custody"
     and .authorization_id == $authorization_id
     and .plan_token == $plan_token
     and .target_serial == $target_serial
     and .release_id == $release_id
     and (.disk_passphrase | test("^[0-9a-f]{64}$"))
     and (.recovery_key | test("^[^-]+(-[^-]+){7}$"))' \
    "${CUSTODY_DOCUMENT}" >/dev/null \
    || die 'custody.json is incomplete or not bound to the signed authorization'
jq -r '.disk_passphrase,.recovery_key' "${CUSTODY_DOCUMENT}" > "${SECRET_PATTERNS}"
chmod 600 "${SECRET_PATTERNS}"
if grep -aF -f "${SECRET_PATTERNS}" \
    "${SERIAL_LOG}" "${RUNTIME_LOG}" "${UNATTENDED_LOG}" "${QEMU_LOG}" >/dev/null; then
    die 'a generated install secret appeared in live proof output'
fi

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

# `jq -r` appends a line feed, which would change the LUKS passphrase. Keep
# custody extraction byte-exact: the generated passphrase itself has no LF.
jq -jr '.disk_passphrase' "${CUSTODY_DOCUMENT}" \
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
sudo jq -e \
    '.initiated == "unattended"
     and .diskRecovery.mode == "personal_copy"
     and .diskRecovery.acknowledgement == "unattended"
     and .diskEncrypted == true' \
    "${MOUNT_DIR}/@var/lib/punar/install/seed.json" >/dev/null \
    || die 'the installed seed does not retain unattended custody provenance'
[ ! -e "${MOUNT_DIR}/@var/lib/punar/install/custody.json" ] \
    || die 'custody material was copied onto the installed system'
if sudo grep -aRF -f "${SECRET_PATTERNS}" \
    "${MOUNT_DIR}/@var/log" "${MOUNT_DIR}/@var/lib/punar" >/dev/null 2>&1; then
    die 'a generated install secret appeared in installed logs or state'
fi

sudo umount "${MOUNT_DIR}"
DATA_MOUNTED=0
sudo cryptsetup close "${MAPPER_NAME}"
MAPPER_OPEN=0
sudo qemu-nbd --disconnect "${NBD_DEVICE}" >/dev/null
NBD_ATTACHED=0

printf 'I08-I13,I36a-I36d,I36-unattended PASS target_bytes=%s luks_uuid=%s elapsed_seconds=%s\n' \
    "${TARGET_BYTES}" "${luks_uuid}" "$((finished - started))" \
    > "${PROOF_DIR}/result.txt"
echo "install-test: PASS (I08-I13 + I36a-I36d refusals + unattended I36 custody/secrecy; $((finished - started))s, ${ACCEL})"
