#!/usr/bin/env bash
# Boot the final x86_64 hybrid installer in both supported attachment forms:
# an optical ISO (-cdrom) and the same bytes as a raw USB-like virtio disk.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ISO=${1:-}
PROOF_DIR=${2:-"${REPO_ROOT}/os/images/out/installer-boot-proof"}
BOOT_FORMS=${PUNAR_INSTALLER_BOOT_FORMS:-"optical raw-drive"}

die() {
    echo "installer-boot-test: FAIL: $*" >&2
    exit 1
}

[ -n "${ISO}" ] || die "usage: $0 INSTALLER_ISO [PROOF_DIR]"
[ -f "${ISO}" ] || die "installer ISO is missing: ${ISO}"
command -v qemu-system-x86_64 >/dev/null || die 'qemu-system-x86_64 is required'

OVMF_CODE=''
OVMF_VARS=''
for pair in \
    "/usr/share/OVMF/OVMF_CODE_4M.fd:/usr/share/OVMF/OVMF_VARS_4M.fd" \
    "/usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd" \
    "/usr/share/edk2/x64/OVMF_CODE.4m.fd:/usr/share/edk2/x64/OVMF_VARS.4m.fd" \
    "/usr/share/edk2/x64/OVMF_CODE.fd:/usr/share/edk2/x64/OVMF_VARS.fd" \
    "/opt/homebrew/share/qemu/edk2-x86_64-code.fd:/opt/homebrew/share/qemu/edk2-i386-vars.fd" \
    "/usr/local/share/qemu/edk2-x86_64-code.fd:/usr/local/share/qemu/edk2-i386-vars.fd"
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

HOST_ARCH=$(uname -m)
if [ "${HOST_ARCH}" = x86_64 ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    ACCEL=kvm
    CPU=host
    DEFAULT_TIMEOUT=300
else
    ACCEL=tcg
    CPU=max
    DEFAULT_TIMEOUT=1200
    echo 'installer-boot-test: warning: KVM unavailable; using TCG' >&2
fi
TIMEOUT=${PUNAR_INSTALLER_BOOT_TIMEOUT:-${DEFAULT_TIMEOUT}}

mkdir -p "${PROOF_DIR}"
QEMU_PID=''
cleanup() {
    if [ -n "${QEMU_PID}" ] && kill -0 "${QEMU_PID}" 2>/dev/null; then
        kill "${QEMU_PID}" 2>/dev/null || true
        wait "${QEMU_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

boot_form() {
    local form=$1
    local log="${PROOF_DIR}/${form}-serial.log"
    local vars_copy="${PROOF_DIR}/${form}-OVMF_VARS.fd"
    local started now
    local -a medium_args

    cp "${OVMF_VARS}" "${vars_copy}"
    : > "${log}"
    if [ "${form}" = optical ]; then
        medium_args=(-cdrom "${ISO}")
    else
        medium_args=(-drive "file=${ISO},format=raw,if=virtio,readonly=on")
    fi

    echo "==> installer ${form} boot (${ACCEL}; firmware ${OVMF_CODE})"
    qemu-system-x86_64 \
        -machine "q35,accel=${ACCEL}" \
        -cpu "${CPU}" \
        -m 2048 \
        -smp 2 \
        -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}" \
        -drive "if=pflash,format=raw,file=${vars_copy}" \
        "${medium_args[@]}" \
        -nic none \
        -display none \
        -serial "file:${log}" \
        -monitor none \
        -no-reboot \
        > "${PROOF_DIR}/${form}-qemu.log" 2>&1 &
    QEMU_PID=$!
    started=$(date +%s)

    while :; do
        if grep -aq 'PUNAR_INSTALLER_OK' "${log}"; then
            now=$(date +%s)
            echo "installer-boot-test: ${form} PASS ($((now - started))s, ${ACCEL})"
            kill "${QEMU_PID}" 2>/dev/null || true
            wait "${QEMU_PID}" 2>/dev/null || true
            QEMU_PID=''
            return 0
        fi
        if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
            tail -n 120 "${log}" >&2 || true
            tail -n 80 "${PROOF_DIR}/${form}-qemu.log" >&2 || true
            QEMU_PID=''
            die "QEMU exited before PUNAR_INSTALLER_OK in ${form} mode"
        fi
        now=$(date +%s)
        if [ "$((now - started))" -ge "${TIMEOUT}" ]; then
            kill "${QEMU_PID}" 2>/dev/null || true
            wait "${QEMU_PID}" 2>/dev/null || true
            QEMU_PID=''
            tail -n 120 "${log}" >&2 || true
            die "timed out after ${TIMEOUT}s waiting for ${form} installer boot"
        fi
        sleep 1
    done
}

read -r -a requested_forms <<< "${BOOT_FORMS}"
[ "${#requested_forms[@]}" -gt 0 ] || die 'no installer boot forms were requested'
for form in "${requested_forms[@]}"; do
    case "${form}" in
        optical|raw-drive) boot_form "${form}" ;;
        *) die "unsupported installer boot form: ${form}" ;;
    esac
done
echo "installer-boot-test: PASS (${requested_forms[*]})"
