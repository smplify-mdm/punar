#!/bin/sh
# Emit typed installer results only onto the VM gate's dedicated virtio port.
# No physical machine has this endpoint, and the service is absent from every
# installed root. This lane is deliberately read-only: targets + plan only.
set -eu

PORT=/dev/virtio-ports/punar.install-proof
TARGET_SERIAL=PUNAR-CI-TARGET
TARGET_BYTES=137438953472

fail() {
    printf 'PUNAR_INSTALL_RUNTIME_FAIL stage=%s\n' "$1" > "${PORT}"
    exit 1
}

attempt=0
targets=''
while [ "${attempt}" -lt 60 ]; do
    if targets=$(/usr/bin/punarctl debug rpc install.targets 2>/dev/null); then
        break
    fi
    attempt=$((attempt + 1))
    /usr/bin/sleep 1
done
[ -n "${targets}" ] || fail targets_rpc

printf '%s\n' "${targets}" | /usr/bin/jq -e \
    --arg serial "${TARGET_SERIAL}" \
    --argjson bytes "${TARGET_BYTES}" \
    '.v == 1
     and (.targets | length == 1)
     and .targets[0].serial == $serial
     and .targets[0].size_bytes == $bytes
     and .targets[0].eligible == true
     and (.targets[0].partitions | length == 0)' >/dev/null \
    || fail targets_shape

disk=$(printf '%s\n' "${targets}" | /usr/bin/jq -er '.targets[0].device') \
    || fail target_device
params=$(printf \
    '{"disk":"%s","keymap":"us","encryption":"luks2","recovery_mode":"personal_copy"}' \
    "${disk}")
plan=$(/usr/bin/punarctl debug rpc install.plan --params "${params}" 2>/dev/null) \
    || fail plan_rpc
[ -n "${plan}" ] || fail plan_empty

{
    printf 'PUNAR_INSTALL_RUNTIME_BEGIN\n'
    printf 'PUNAR_INSTALL_TARGETS_JSON=%s\n' "${targets}"
    printf 'PUNAR_INSTALL_PLAN_JSON=%s\n' "${plan}"
    printf 'PUNAR_INSTALL_RUNTIME_END\n'
} > "${PORT}"

