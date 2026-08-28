#!/usr/bin/env bash
# Prove systemd-boot's real automatic fallback on a disposable ARM64 disk.
#
# The test adds a counted UKI whose root PARTUUID cannot exist, boots it three
# times, and verifies the firmware-owned filename counter after every failed
# attempt. The fourth boot must skip the exhausted entry and reach the
# permanently uncounted slot-A image. No Punar userspace counter is involved.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${1:-${REPO_ROOT}/os/images/out/punar-dev-arm64.qcow2}"
PROOF_DIR="${2:-${REPO_ROOT}/os/images/out/arm64-update-rollback-proof}"

# shellcheck source=/dev/null
. "${REPO_ROOT}/os/images/arm64/snapshot.env"

BUILDER_TAG="punar-debian-builder:${PUNAR_DEBIAN_SNAPSHOT}-arm64"
SLOT_A_UUID="1beabfe0-9cb8-4b49-91ef-d372b845e7ea"
INVALID_ROOT_UUID="00000000-0000-0000-0000-000000000000"
PENDING_VERSION="2099.01.01.1"
PENDING_STEM="punar_${PENDING_VERSION}"
PENDING_SELECTOR="${PENDING_STEM}*.efi"

die() {
    echo "error: $*" >&2
    exit 1
}

warn() {
    echo "warning: $*" >&2
    if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
        echo "::warning::$*"
    fi
}

for command in docker qemu-img qemu-system-aarch64; do
    command -v "${command}" >/dev/null 2>&1 \
        || die "required command is missing: ${command}"
done
[ -f "${IMAGE}" ] || die "image not found: ${IMAGE}"
docker image inspect "${BUILDER_TAG}" >/dev/null 2>&1 \
    || die "ARM64 builder image is missing: ${BUILDER_TAG}"

FIRMWARE=""
for candidate in \
    /usr/share/AAVMF/AAVMF_CODE.fd \
    /usr/share/AAVMF/AAVMF_CODE.ms.fd \
    /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
    /usr/share/edk2/aarch64/QEMU_EFI.fd \
    /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
    /usr/local/share/qemu/edk2-aarch64-code.fd
do
    if [ -f "${candidate}" ]; then
        FIRMWARE="${candidate}"
        break
    fi
done
[ -n "${FIRMWARE}" ] || die "no supported AArch64 UEFI firmware found"

HOST_ARCH="$(uname -m)"
ACCEL="tcg"
MACHINE="virt,accel=tcg"
CPU="max"
if [ "$(uname -s)" = Darwin ] && [ "${HOST_ARCH}" = arm64 ]; then
    ACCEL="hvf"
    MACHINE="virt,accel=hvf,highmem=off"
    CPU="host"
elif [ -r /dev/kvm ] \
    && { [ "${HOST_ARCH}" = aarch64 ] || [ "${HOST_ARCH}" = arm64 ]; }; then
    ACCEL="kvm"
    MACHINE="virt,accel=kvm"
    CPU="host"
else
    warn "ARM64 KVM/HVF unavailable; rollback proof is TCG-emulated"
fi

BAD_BOOT_TIMEOUT="${PUNAR_ARM64_BAD_BOOT_TIMEOUT:-}"
FALLBACK_TIMEOUT="${PUNAR_ARM64_FALLBACK_TIMEOUT:-}"
if [ -z "${BAD_BOOT_TIMEOUT}" ]; then
    [ "${ACCEL}" = tcg ] && BAD_BOOT_TIMEOUT=900 || BAD_BOOT_TIMEOUT=120
fi
if [ -z "${FALLBACK_TIMEOUT}" ]; then
    [ "${ACCEL}" = tcg ] && FALLBACK_TIMEOUT=900 || FALLBACK_TIMEOUT=180
fi

SCRATCH_PARENT="${RUNNER_TEMP:-/var/tmp}"
SCRATCH_DIR="$(mktemp -d "${SCRATCH_PARENT%/}/punar-update-rollback.XXXXXX")"
RAW_IMAGE="${SCRATCH_DIR}/disk.raw"
QEMU_PID=""

stop_qemu() {
    if [ -n "${QEMU_PID}" ] && kill -0 "${QEMU_PID}" 2>/dev/null; then
        kill "${QEMU_PID}" 2>/dev/null || true
        wait "${QEMU_PID}" 2>/dev/null || true
    fi
    QEMU_PID=""
}

cleanup() {
    stop_qemu
    if [ -f "${RAW_IMAGE}" ]; then
        truncate -s 0 "${RAW_IMAGE}" || true
        unlink "${RAW_IMAGE}" || true
    fi
    find "${SCRATCH_DIR}" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT INT TERM

install -d "${PROOF_DIR}"
find "${PROOF_DIR}" -maxdepth 1 -type f -delete

echo "==> Creating disposable persistent ARM64 rollback disk"
qemu-img convert -O raw -S 4k "${IMAGE}" "${RAW_IMAGE}"

echo "==> Arming a counted UKI that cannot mount a root filesystem"
docker run --rm --privileged --platform linux/arm64 \
    --volume "${SCRATCH_DIR}:/proof" \
    --env "PUNAR_SLOT_A_UUID=${SLOT_A_UUID}" \
    --env "PUNAR_INVALID_ROOT_UUID=${INVALID_ROOT_UUID}" \
    --env "PUNAR_PENDING_STEM=${PENDING_STEM}" \
    --env "PUNAR_PENDING_SELECTOR=${PENDING_SELECTOR}" \
    "${BUILDER_TAG}" bash -ceu '
        for command in sfdisk losetup mount umount mountpoint objcopy grep \
            find sync install sed tr mknod; do
            command -v "${command}" >/dev/null 2>&1 \
                || { echo "error: missing container command: ${command}" >&2; exit 1; }
        done
        for loop_minor in {0..31}; do
            [ -b "/dev/loop${loop_minor}" ] \
                || mknod --mode=0660 "/dev/loop${loop_minor}" b 7 "${loop_minor}"
        done
        [ -c /dev/loop-control ] || mknod --mode=0660 /dev/loop-control c 10 237

        work="$(mktemp -d /run/punar-rollback-arm.XXXXXX)"
        esp_loop=""
        cleanup_container() {
            mountpoint -q "${work}/esp" && umount "${work}/esp" || true
            [ -z "${esp_loop}" ] || losetup --detach "${esp_loop}" || true
            rm -rf "${work}"
        }
        trap cleanup_container EXIT
        mkdir -p "${work}/esp"

        sfdisk --json /proof/disk.raw > "${work}/table.json"
        read -r esp_start esp_size < <(
            python3 - "${work}/table.json" <<"PY"
import json
import sys

parts = json.load(open(sys.argv[1], encoding="utf-8"))["partitiontable"]["partitions"]
if len(parts) != 4 or parts[0].get("name") != "PUNAR-ESP":
    raise SystemExit("unexpected partition layout")
print(parts[0]["start"], parts[0]["size"])
PY
        )
        esp_loop="$(losetup --find --show \
            --offset "$((esp_start * 512))" --sizelimit "$((esp_size * 512))" \
            /proof/disk.raw)"
        mount "${esp_loop}" "${work}/esp"

        good_uki="$(find "${work}/esp/EFI/Linux" -maxdepth 1 -type f \
            -name "*.efi" ! -name "*+[0-9]*-[0-9]*.efi" -print -quit)"
        [ -n "${good_uki}" ] || { echo "error: no uncounted last-known-good UKI" >&2; exit 1; }
        [ "$(find "${work}/esp/EFI/Linux" -maxdepth 1 -type f -name "*.efi" | wc -l)" -eq 1 ] \
            || { echo "error: proof source must contain exactly one UKI" >&2; exit 1; }

        objcopy --only-section=.cmdline --output-target=binary \
            "${good_uki}" "${work}/cmdline"
        tr -d "\000" < "${work}/cmdline" > "${work}/cmdline.txt"
        grep -Fq "root=PARTUUID=${PUNAR_SLOT_A_UUID}" "${work}/cmdline.txt"
        sed "s/${PUNAR_SLOT_A_UUID}/${PUNAR_INVALID_ROOT_UUID}/g" \
            "${work}/cmdline.txt" > "${work}/cmdline-bad.txt"
        printf "\0" >> "${work}/cmdline-bad.txt"

        pending_name="${PUNAR_PENDING_STEM}+3-0.efi"
        install -m 0644 "${good_uki}" \
            "${work}/esp/EFI/Linux/${pending_name}.new"
        objcopy --update-section ".cmdline=${work}/cmdline-bad.txt" \
            "${work}/esp/EFI/Linux/${pending_name}.new"
        objcopy --only-section=.cmdline --output-target=binary \
            "${work}/esp/EFI/Linux/${pending_name}.new" "${work}/cmdline-check"
        tr -d "\000" < "${work}/cmdline-check" \
            | grep -Fq "root=PARTUUID=${PUNAR_INVALID_ROOT_UUID}"
        mv "${work}/esp/EFI/Linux/${pending_name}.new" \
            "${work}/esp/EFI/Linux/${pending_name}"

        printf "preferred %s\ntimeout 0\neditor no\n" "${PUNAR_PENDING_SELECTOR}" \
            > "${work}/esp/loader/loader.conf.new"
        sync -f "${work}/esp/loader/loader.conf.new"
        mv "${work}/esp/loader/loader.conf.new" \
            "${work}/esp/loader/loader.conf"
        sync -f "${work}/esp"

        {
            printf "good_uki=%s\n" "$(basename "${good_uki}")"
            printf "pending_uki=%s\n" "${pending_name}"
        } > /proof/armed.env
        chmod 0644 /proof/armed.env
    '

# shellcheck disable=SC1090,SC1091
. "${SCRATCH_DIR}/armed.env"
[ -n "${good_uki:-}" ] || die "proof did not record the last-known-good UKI"

start_qemu() {
    local log="$1"
    : > "${log}"
    qemu-system-aarch64 \
        -machine "${MACHINE}" \
        -cpu "${CPU}" \
        -m 2048 \
        -smp 4 \
        -bios "${FIRMWARE}" \
        -drive "file=${RAW_IMAGE},format=raw,if=none,id=punardisk,cache=writeback,aio=threads" \
        -device virtio-blk-pci,drive=punardisk,romfile= \
        -nic none \
        -nographic \
        -no-reboot \
        > "${log}" 2>&1 &
    QEMU_PID=$!
}

assert_esp_state() {
    local expected_pending="$1"
    docker run --rm --privileged --platform linux/arm64 \
        --volume "${SCRATCH_DIR}:/proof" \
        --env "PUNAR_GOOD_UKI=${good_uki}" \
        --env "PUNAR_EXPECTED_PENDING=${expected_pending}" \
        --env "PUNAR_PENDING_SELECTOR=${PENDING_SELECTOR}" \
        "${BUILDER_TAG}" bash -ceu '
            for loop_minor in {0..31}; do
                [ -b "/dev/loop${loop_minor}" ] \
                    || mknod --mode=0660 "/dev/loop${loop_minor}" b 7 "${loop_minor}"
            done
            [ -c /dev/loop-control ] \
                || mknod --mode=0660 /dev/loop-control c 10 237
            work="$(mktemp -d /run/punar-rollback-inspect.XXXXXX)"
            esp_loop=""
            cleanup_container() {
                mountpoint -q "${work}/esp" && umount "${work}/esp" || true
                [ -z "${esp_loop}" ] || losetup --detach "${esp_loop}" || true
                rm -rf "${work}"
            }
            trap cleanup_container EXIT
            mkdir -p "${work}/esp"
            read -r esp_start esp_size < <(
                sfdisk --dump /proof/disk.raw \
                    | awk -F "[=,]" "/start=/ {gsub(/ /, \"\", \$2); gsub(/ /, \"\", \$4); print \$2, \$4; exit}"
            )
            esp_loop="$(losetup --find --show \
                --offset "$((esp_start * 512))" --sizelimit "$((esp_size * 512))" \
                /proof/disk.raw)"
            mount -o ro "${esp_loop}" "${work}/esp"
            [ -f "${work}/esp/EFI/Linux/${PUNAR_GOOD_UKI}" ]
            [ -f "${work}/esp/EFI/Linux/${PUNAR_EXPECTED_PENDING}" ]
            [ "$(find "${work}/esp/EFI/Linux" -maxdepth 1 -type f -name "*.efi" | wc -l)" -eq 2 ]
            grep -Fxq "preferred ${PUNAR_PENDING_SELECTOR}" \
                "${work}/esp/loader/loader.conf"
        '
}

echo "==> Exhausting the pending entry through three real firmware boots"
expected_names=(
    "${PENDING_STEM}+2-1.efi"
    "${PENDING_STEM}+1-2.efi"
    "${PENDING_STEM}+0-3.efi"
)
for attempt in 1 2 3; do
    log="${PROOF_DIR}/failed-boot-${attempt}.log"
    echo "    failed attempt ${attempt}/3"
    start_qemu "${log}"
    started="$(date +%s)"
    while :; do
        if grep -Fq 'PUNAR_BOOT_OK' "${log}"; then
            tail -120 "${log}" >&2
            die "counted bad entry unexpectedly reached PUNAR_BOOT_OK"
        fi
        if grep -Fq "${INVALID_ROOT_UUID}" "${log}"; then
            break
        fi
        if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
            tail -120 "${log}" >&2
            die "QEMU exited before attempting the counted bad entry"
        fi
        if [ "$(( $(date +%s) - started ))" -ge "${BAD_BOOT_TIMEOUT}" ]; then
            tail -120 "${log}" >&2
            die "timed out waiting for the bad UKI command line"
        fi
        sleep 1
    done
    stop_qemu
    assert_esp_state "${expected_names[$((attempt - 1))]}"
done

echo "==> Booting once more; systemd-boot must choose last-known-good slot A"
fallback_log="${PROOF_DIR}/fallback-boot.log"
start_qemu "${fallback_log}"
fallback_started="$(date +%s)"
while :; do
    if grep -Fq 'PUNAR_BOOT_OK' "${fallback_log}"; then
        break
    fi
    if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
        tail -160 "${fallback_log}" >&2
        die "QEMU exited before automatic fallback reached PUNAR_BOOT_OK"
    fi
    if [ "$(( $(date +%s) - fallback_started ))" -ge "${FALLBACK_TIMEOUT}" ]; then
        tail -160 "${fallback_log}" >&2
        die "timed out waiting for automatic fallback"
    fi
    sleep 1
done
fallback_elapsed="$(( $(date +%s) - fallback_started ))"
grep -Fq "${SLOT_A_UUID}" "${fallback_log}" \
    || die "fallback boot did not expose slot A's PARTUUID"
grep -Fq "${INVALID_ROOT_UUID}" "${fallback_log}" \
    && die "fallback boot selected the exhausted bad UKI"
stop_qemu
assert_esp_state "${PENDING_STEM}+0-3.efi"

{
    echo "PUNAR_UPDATE_AUTO_ROLLBACK_OK"
    echo "architecture=arm64"
    echo "accelerator=${ACCEL}"
    echo "failed_attempts=3"
    echo "exhausted_entry=${PENDING_STEM}+0-3.efi"
    echo "fallback_entry=${good_uki}"
    echo "fallback_slot=A"
    echo "fallback_boot_seconds=${fallback_elapsed}"
    echo "mechanism=systemd-boot-native-counting"
} > "${PROOF_DIR}/report.txt"

echo "PUNAR_UPDATE_AUTO_ROLLBACK_OK attempts=3 fallback_slot=A accelerator=${ACCEL}"
echo "    proof: ${PROOF_DIR}/report.txt"
