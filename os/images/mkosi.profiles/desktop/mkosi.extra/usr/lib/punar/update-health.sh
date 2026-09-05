#!/bin/sh
# Gate systemd-bless-boot and native Raspberry Pi reconciliation on the four
# product health signals. Firmware owns fallback; the daemon alone reconciles
# its read-only observation with the exact durable pending transaction.
set -eu

RUN_DIR=/run/punar
REPORT="${RUN_DIR}/update-health.json"
STATUS_JSON="${RUN_DIR}/update-health-status.json"
AGENTS_JSON="${RUN_DIR}/update-health-agents.json"
PI_BOOT_PARTITION=/proc/device-tree/chosen/bootloader/partition
PI_TRYBOOT=/proc/device-tree/chosen/bootloader/tryboot
PI_PENDING=/var/lib/punar/update/pending-pi.json
PI_RESULT="${RUN_DIR}/update-pi-reconcile.json"
MAX_WAIT=170

install -d -m 0755 "${RUN_DIR}"

boot=false
control_plane=false
desktop=false
capabilities=false
attempt=0

write_report() {
    tmp="${REPORT}.new"
    jq -n \
        --argjson boot "${boot}" \
        --argjson control_plane "${control_plane}" \
        --argjson desktop "${desktop}" \
        --argjson capabilities "${capabilities}" \
        --argjson waited_seconds "${attempt}" \
        '{schema_version: 1, health: {
            boot_completed: $boot,
            control_plane_answers: $control_plane,
            desktop_ready: $desktop,
            capabilities_verified: $capabilities
          }, waited_seconds: $waited_seconds}' > "${tmp}"
    chmod 0644 "${tmp}"
    mv "${tmp}" "${REPORT}"
}

desktop_marker_is_trusted() {
    # The greeter is a system user (UID < 1000). Only accept a marker from a
    # regular authenticated account, and verify both objects are owned by the
    # UID encoded in /run/user/<uid> before treating the desktop as ready.
    for marker in /run/user/[1-9][0-9][0-9][0-9]*/punar/shell-ready; do
        [ -e "${marker}" ] || continue
        runtime_dir=${marker%/punar/shell-ready}
        runtime_uid=${runtime_dir##*/}
        [ "$(stat -c %u "${runtime_dir}")" = "${runtime_uid}" ] || continue
        [ "$(stat -c %u "${marker}")" = "${runtime_uid}" ] || continue
        return 0
    done
    return 1
}

run_pi_reconcile() {
    result_new="${PI_RESULT}.new"
    if ! /usr/bin/punarctl --json update reconcile-candidate > "${result_new}"; then
        unlink "${result_new}" 2>/dev/null || true
        return 1
    fi
    chmod 0600 "${result_new}"
    mv "${result_new}" "${PI_RESULT}"
    reboot_required=$(jq -r '
        if .requires_normal_reboot == true then "yes"
        elif .requires_normal_reboot == false then "no"
        else "invalid"
        end' "${PI_RESULT}")
    case "${reboot_required}" in
        yes)
            if ! /usr/bin/systemctl --no-block reboot; then
                echo "PUNAR_UPDATE_HEALTH_FAILED pi_candidate=reboot_refused" >&2
                return 1
            fi
            ;;
        no) ;;
        *)
            echo "PUNAR_UPDATE_HEALTH_FAILED pi_candidate=invalid_result" >&2
            return 1
            ;;
    esac
    return 0
}

pi_firmware_fallback_observed() {
    [ -e "${PI_BOOT_PARTITION}" ] && [ -e "${PI_PENDING}" ] || return 1
    current_partition=$(/usr/bin/od -An -tu4 --endian=big "${PI_BOOT_PARTITION}" \
        2>/dev/null | /usr/bin/tr -d '[:space:]')
    [ -n "${current_partition}" ] || return 1
    tryboot=0
    if [ -e "${PI_TRYBOOT}" ]; then
        tryboot=$(/usr/bin/od -An -tu4 --endian=big "${PI_TRYBOOT}" \
            2>/dev/null | /usr/bin/tr -d '[:space:]')
    fi
    [ "${tryboot}" != "1" ] || return 1
    previous_partition=$(jq -r '
        if .previous_slot == "a" then "2"
        elif .previous_slot == "b" then "4"
        else "invalid"
        end' "${PI_PENDING}" 2>/dev/null) || return 1
    [ "${current_partition}" = "${previous_partition}" ]
}

# A normal boot of the recorded previous slot is firmware's explicit fallback
# result. It needs no candidate desktop-health wait. This shell observation
# only avoids a delay: the daemon independently validates firmware, selector
# and pending state before recording/finalizing the fallback.
if pi_firmware_fallback_observed; then
    if ! run_pi_reconcile; then
        echo "PUNAR_UPDATE_HEALTH_FAILED pi_candidate=fallback_reconcile_refused" >&2
        exit 1
    fi
    echo "PUNAR_UPDATE_HEALTH_OK pi_outcome=firmware_fallback"
    exit 0
fi

while [ "${attempt}" -lt "${MAX_WAIT}" ]; do
    systemctl --quiet is-active multi-user.target && boot=true || boot=false

    punard_ok=false
    agentd_ok=false
    if punarctl --json status > "${STATUS_JSON}.new" 2>/dev/null; then
        mv "${STATUS_JSON}.new" "${STATUS_JSON}"
        punard_ok=true
    fi
    if punarctl --json agents list > "${AGENTS_JSON}.new" 2>/dev/null; then
        mv "${AGENTS_JSON}.new" "${AGENTS_JSON}"
        agentd_ok=true
    fi
    if ${punard_ok} && ${agentd_ok}; then
        control_plane=true
    else
        control_plane=false
    fi

    desktop_marker_is_trusted && desktop=true || desktop=false
    if [ -s "${STATUS_JSON}" ] \
        && jq -e '.compliance.overall == "compliant"
            and ([.compliance.capabilities[].state]
                 | all(. == "compliant" or . == "unsupported"))' \
            "${STATUS_JSON}" >/dev/null 2>&1; then
        capabilities=true
    else
        capabilities=false
    fi

    if ${boot} && ${control_plane} && ${desktop} && ${capabilities}; then
        write_report
        # Pi firmware has no systemd-boot bless generator. A boot-only service
        # starts this gate when a pending record existed as the boot transaction
        # was assembled. Only after the durable report above says every signal
        # passed may the paramless, root-only operation reconcile. The daemon
        # independently rechecks firmware state, exact raw root/boot bytes,
        # IMAGE_VERSION, root pairing, selector copies and this report.
        if [ -e "${PI_BOOT_PARTITION}" ] && [ -e "${PI_PENDING}" ]; then
            if ! run_pi_reconcile; then
                echo "PUNAR_UPDATE_HEALTH_FAILED pi_candidate=reconcile_refused" >&2
                exit 1
            fi
        fi
        rm -f "${STATUS_JSON}" "${AGENTS_JSON}" "${PI_RESULT}"
        echo "PUNAR_UPDATE_HEALTH_OK boot=pass control_plane=pass desktop=pass capabilities=pass"
        exit 0
    fi

    attempt=$((attempt + 1))
    sleep 1
done

write_report
rm -f "${STATUS_JSON}.new" "${AGENTS_JSON}.new"
echo "PUNAR_UPDATE_HEALTH_FAILED boot=${boot} control_plane=${control_plane} desktop=${desktop} capabilities=${capabilities}" >&2
exit 1
