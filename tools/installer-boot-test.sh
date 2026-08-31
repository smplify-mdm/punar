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
command -v qemu-img >/dev/null || die 'qemu-img is required'
command -v python3 >/dev/null || die 'python3 is required for framebuffer proof capture'

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
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/punar-installer-boot.XXXXXX")"
QEMU_PID=''
QMP_SOCKET=''
cleanup() {
    if [ -n "${QEMU_PID}" ] && kill -0 "${QEMU_PID}" 2>/dev/null; then
        kill "${QEMU_PID}" 2>/dev/null || true
        wait "${QEMU_PID}" 2>/dev/null || true
    fi
    if [ -n "${QMP_SOCKET}" ]; then
        rm -f -- "${QMP_SOCKET}"
    fi
    rm -rf -- "${WORKDIR}"
}
trap cleanup EXIT INT TERM

validate_runtime_proof() {
    local proof_log=$1 form=$2
    python3 - "${proof_log}" "${REPO_ROOT}" "${form}" <<'PY'
import hashlib
import json
import pathlib
import sys

try:
    from jsonschema import Draft202012Validator, RefResolver
except ImportError as error:
    raise SystemExit(f"installer-runtime-contract: FAIL: python3-jsonschema is required: {error}")

proof_path = pathlib.Path(sys.argv[1])
repo_root = pathlib.Path(sys.argv[2])
form = sys.argv[3]
lines = proof_path.read_text(encoding="utf-8").splitlines()

def one(prefix):
    values = [line[len(prefix):] for line in lines if line.startswith(prefix)]
    if len(values) != 1:
        raise SystemExit(
            f"installer-runtime-contract: FAIL: expected one {prefix!r} line, found {len(values)}"
        )
    return json.loads(values[0])

targets = one("PUNAR_INSTALL_TARGETS_JSON=")
plan_result = one("PUNAR_INSTALL_PLAN_JSON=")
if targets.get("v") != 1 or len(targets.get("targets", [])) != 1:
    raise SystemExit("installer-runtime-contract: FAIL: install.targets did not return exactly one target")
target = targets["targets"][0]
if target.get("serial") != "PUNAR-CI-TARGET":
    raise SystemExit("installer-runtime-contract: FAIL: the blank target serial is absent")
if target.get("size_bytes") != 128 * 1024 * 1024 * 1024:
    raise SystemExit("installer-runtime-contract: FAIL: the target is not exactly 128 GiB")
if target.get("eligible") is not True or target.get("partitions") != []:
    raise SystemExit("installer-runtime-contract: FAIL: the blank target is not eligible and empty")

plan_schema = json.loads((repo_root / "schemas/install/plan.json").read_text())
hardware_schema = json.loads(
    (repo_root / "schemas/install/hardware-report.json").read_text()
)
resolver = RefResolver.from_schema(
    plan_schema,
    store={hardware_schema["$id"]: hardware_schema},
)
Draft202012Validator(plan_schema, resolver=resolver).validate(plan_result)

plan = plan_result["plan"]
canonical = json.dumps(
    plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
expected_token = hashlib.sha256(canonical).hexdigest()
if plan_result["plan_token"] != expected_token:
    raise SystemExit("installer-runtime-contract: FAIL: plan_token is not the canonical plan digest")
if plan["disk"]["device"] != target["device"] or plan["disk"]["serial"] != target["serial"]:
    raise SystemExit("installer-runtime-contract: FAIL: plan is not bound to the discovered disk")
if plan["encryption"] != "luks2" or plan["recovery_mode"] != "personal_copy":
    raise SystemExit("installer-runtime-contract: FAIL: plan lost the encrypted personal-recovery choice")

print(
    "installer-runtime-contract: PASS "
    f"form={form} device={target['device']} serial={target['serial']} "
    f"plan_token={plan_result['plan_token']}"
)
PY
}

capture_screen() {
    local screen=$1
    [ -n "${QMP_SOCKET}" ] && [ -S "${QMP_SOCKET}" ] || return 0
    python3 - "${QMP_SOCKET}" "${screen}" <<'PY' || true
import json
import socket
import sys

qmp_socket, screen = sys.argv[1:]
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(5)
    client.connect(qmp_socket)
    stream = client.makefile("rwb", buffering=0)
    json.loads(stream.readline())

    def execute(command, arguments=None):
        request = {"execute": command}
        if arguments is not None:
            request["arguments"] = arguments
        stream.write(json.dumps(request).encode() + b"\n")
        while True:
            response = json.loads(stream.readline())
            if "return" in response:
                return
            if "error" in response:
                raise RuntimeError(response["error"])

    execute("qmp_capabilities")
    execute("screendump", {"filename": screen})
PY
}

boot_form() {
    local form=$1
    local log="${PROOF_DIR}/${form}-serial.log"
    local screen="${PROOF_DIR}/${form}-screen.ppm"
    local vars_copy="${PROOF_DIR}/${form}-OVMF_VARS.fd"
    local runtime_log="${PROOF_DIR}/${form}-runtime-proof.log"
    local target_disk="${WORKDIR}/${form}-target.qcow2"
    local started now
    local -a medium_args

    cp "${OVMF_VARS}" "${vars_copy}"
    : > "${log}"
    : > "${runtime_log}"
    qemu-img create -q -f qcow2 "${target_disk}" 128G
    QMP_SOCKET="/tmp/punar-installer-qmp-$$-${form}.sock"
    rm -f -- "${QMP_SOCKET}"
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
        -drive "file=${target_disk},format=qcow2,if=none,id=punartarget" \
        -device "virtio-blk-pci,drive=punartarget,serial=PUNAR-CI-TARGET" \
        -nic none \
        -display none \
        -serial "file:${log}" \
        -monitor none \
        -qmp "unix:${QMP_SOCKET},server=on,wait=off" \
        -device virtio-serial-pci \
        -chardev "file,id=installproof,path=${runtime_log}" \
        -device "virtserialport,chardev=installproof,name=punar.install-proof" \
        -no-reboot \
        > "${PROOF_DIR}/${form}-qemu.log" 2>&1 &
    QEMU_PID=$!
    started=$(date +%s)

    while :; do
        if grep -aq 'PUNAR_INSTALL_RUNTIME_FAIL' "${runtime_log}"; then
            tail -n 120 "${log}" >&2 || true
            cat "${runtime_log}" >&2 || true
            die "live userspace installer proof failed in ${form} mode"
        fi
        if grep -aq 'PUNAR_INSTALLER_OK' "${log}" \
            && grep -aq 'PUNAR_INSTALL_RUNTIME_STAGE_OK' "${log}" \
            && grep -aq '^PUNAR_INSTALL_RUNTIME_END$' "${runtime_log}"; then
            now=$(date +%s)
            validate_runtime_proof "${runtime_log}" "${form}"
            capture_screen "${screen}"
            echo "installer-boot-test: ${form} PASS ($((now - started))s, ${ACCEL}; live userspace + I06/I07)"
            kill "${QEMU_PID}" 2>/dev/null || true
            wait "${QEMU_PID}" 2>/dev/null || true
            QEMU_PID=''
            rm -f -- "${QMP_SOCKET}"
            QMP_SOCKET=''
            return 0
        fi
        if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
            tail -n 120 "${log}" >&2 || true
            cat "${runtime_log}" >&2 || true
            tail -n 80 "${PROOF_DIR}/${form}-qemu.log" >&2 || true
            QEMU_PID=''
            die "QEMU exited before the initrd and live-userspace proofs completed in ${form} mode"
        fi
        now=$(date +%s)
        if [ "$((now - started))" -ge "${TIMEOUT}" ]; then
            capture_screen "${screen}"
            kill "${QEMU_PID}" 2>/dev/null || true
            wait "${QEMU_PID}" 2>/dev/null || true
            QEMU_PID=''
            rm -f -- "${QMP_SOCKET}"
            QMP_SOCKET=''
            tail -n 120 "${log}" >&2 || true
            cat "${runtime_log}" >&2 || true
            die "timed out after ${TIMEOUT}s waiting for ${form} installer runtime proof"
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
