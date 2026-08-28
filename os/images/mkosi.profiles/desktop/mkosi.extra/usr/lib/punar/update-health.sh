#!/bin/sh
# Gate systemd-bless-boot on the four product health signals. The bootloader
# owns attempt counting; this unit only decides whether the current entry may
# become permanently good.
set -eu

RUN_DIR=/run/punar
REPORT="${RUN_DIR}/update-health.json"
STATUS_JSON="${RUN_DIR}/update-health-status.json"
AGENTS_JSON="${RUN_DIR}/update-health-agents.json"
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

    [ -e "${RUN_DIR}/shell-ready" ] && desktop=true || desktop=false
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
        unlink "${STATUS_JSON}" "${AGENTS_JSON}" 2>/dev/null || true
        echo "PUNAR_UPDATE_HEALTH_OK boot=pass control_plane=pass desktop=pass capabilities=pass"
        exit 0
    fi

    attempt=$((attempt + 1))
    sleep 1
done

write_report
unlink "${STATUS_JSON}.new" "${AGENTS_JSON}.new" 2>/dev/null || true
echo "PUNAR_UPDATE_HEALTH_FAILED boot=${boot} control_plane=${control_plane} desktop=${desktop} capabilities=${capabilities}" >&2
exit 1
