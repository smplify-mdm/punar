#!/usr/bin/env bash
# Refuse an image tree whose Punar systemd units name missing or wrong-arch
# product binaries. This is deliberately derived from ExecStart rather than a
# second hand-maintained binary list: adding a service creates its own staging
# obligation automatically.
set -euo pipefail

if [ "$#" -ne 5 ]; then
    echo "usage: $0 PRODUCT_BIN_EXTRA DEV_BIN_EXTRA PRODUCT_UNIT_EXTRA DEV_UNIT_EXTRA ELF_MACHINE" >&2
    exit 2
fi

PRODUCT_EXTRA="$1"
DEV_EXTRA="$2"
PRODUCT_UNIT_EXTRA="$3"
DEV_UNIT_EXTRA="$4"
ELF_MACHINE="$5"
checked=0

check_unit_dir() {
    local unit_dir="$1"
    local unit line binary staged

    [ -d "${unit_dir}" ] || return 0
    for unit in "${unit_dir}"/*.service; do
        [ -f "${unit}" ] || continue
        while IFS= read -r line; do
            binary="${line#ExecStart=}"
            binary="${binary%% *}"
            # systemd permits execution-control prefixes before argv[0]. They
            # do not change which product binary the image must contain.
            while [[ "${binary}" == [-+!:@]* ]]; do
                binary="${binary#?}"
            done
            case "${binary}" in
                /usr/bin/punar*) ;;
                *) continue ;;
            esac

            staged="${PRODUCT_EXTRA}${binary}"
            if [ ! -x "${staged}" ]; then
                staged="${DEV_EXTRA}${binary}"
            fi
            if [ ! -x "${staged}" ]; then
                echo "error: $(basename "${unit}") names missing executable ${binary}" >&2
                exit 1
            fi
            if ! readelf -h "${staged}" | grep -q "Machine:.*${ELF_MACHINE}"; then
                echo "error: $(basename "${unit}") names ${binary}, which is not ${ELF_MACHINE}" >&2
                exit 1
            fi
            checked=$((checked + 1))
        done < <(grep '^ExecStart=' "${unit}" || true)
    done
}

check_unit_dir "${PRODUCT_UNIT_EXTRA}/usr/lib/systemd/system"
check_unit_dir "${DEV_UNIT_EXTRA}/usr/lib/systemd/system"

if [ "${checked}" -eq 0 ]; then
    echo "error: no staged Punar service executables were discovered" >&2
    exit 1
fi

echo "PUNAR_STAGED_EXECUTABLES_OK count=${checked} machine=${ELF_MACHINE}"
