#!/bin/sh
# Contract: the built-in Smplify agent is dormant until enrolled
# (docs/development/smplify-enrollment.md section 3.4). A personal device that
# never enrolls runs no Smplify code; an enrolled device's agent cannot be
# stopped by an administrator's systemctl, and is restarted when killed.
#
#   S1  punar-smplifyd.socket listens on the path punard dials and the path
#       the agent binds without systemd, root-only (0600 in a 0700 directory),
#       one agent for every call (Accept=no), its descriptor named as the
#       agent expects, a manual stop refused, a bounded trigger rate, and no
#       [Install];
#   S2  punar-smplifyd.service is started by the socket and nothing else: no
#       RuntimeDirectory= (stopping the service would delete the socket node),
#       Requires=/After= the socket, a manual stop refused, restarted after
#       every exit but the dormant one, whose status is the agent's own
#       constant, no start limit, no network-online ordering, no [Install];
#   S3  punard.service Wants= and is ordered After= the socket, and Requires=
#       neither the socket nor the service (cached policy enforces with the
#       agent down);
#   S4  no tree ships a wants link to either unit, no reviewed enabled-units
#       manifest names the agent, and the Smplify lab installs the socket
#       rather than an enablement;
#   S5  the idle-RAM sampler no longer sums the agent into the resident
#       services (it is not resident on the measured image) and reports its
#       process count instead, which tests/performance/check-budgets.sh gates
#       to zero;
#   S6  each check rejects a fixture tree that breaks it, so a check that
#       silently stopped matching cannot pass for a working one.
#
# Source-tree only: no image build, no root, a few seconds.
set -eu

REPO_ROOT=$(cd -- "$(dirname "$0")/../.." && pwd)

# ini_value FILE SECTION KEY — the value KEY last takes in [SECTION] (the last
# assignment wins, as in systemd), "empty" for a bare `KEY=`, or "unset".
ini_value() {
    awk -v want="[$2]" -v key="$3" '
        /^[[:space:]]*[#;]/ { next }
        /^[[:space:]]*\[/ {
            section = $0
            gsub(/[[:space:]]/, "", section)
            next
        }
        section == want {
            line = $0
            sub(/^[[:space:]]+/, "", line)
            if (index(line, key "=") == 1) {
                seen = 1
                value = substr(line, length(key) + 2)
                sub(/[[:space:]]+$/, "", value)
            }
        }
        END {
            if (!seen) print "unset"
            else if (value == "") print "empty"
            else print value
        }
    ' "$1"
}

# ini_values FILE SECTION KEY — every value KEY takes in [SECTION], one word
# per line (systemd accumulates Wants=/After=/Requires=).
ini_values() {
    awk -v want="[$2]" -v key="$3" '
        /^[[:space:]]*[#;]/ { next }
        /^[[:space:]]*\[/ {
            section = $0
            gsub(/[[:space:]]/, "", section)
            next
        }
        section == want {
            line = $0
            sub(/^[[:space:]]+/, "", line)
            if (index(line, key "=") == 1) {
                n = split(substr(line, length(key) + 2), words, /[[:space:]]+/)
                for (i = 1; i <= n; i++) if (words[i] != "") print words[i]
            }
        }
    ' "$1"
}

has_section() {
    grep -Eq "^[[:space:]]*\[$2\][[:space:]]*$" "$1"
}

# A Rust constant's literal value: `const NAME: T = <value>;`, quotes removed.
rust_const() {
    sed -n "s/.*const $2: [^=]*= *\"\{0,1\}\([^\";]*\)\"\{0,1\};.*/\1/p" "$1" | head -n 1
}

# check_tree ROOT — print every violation; exit non-zero if any.
check_tree() (
    root=$1
    units="${root}/os/images/mkosi.profiles/desktop/mkosi.extra/usr/lib/systemd/system"
    socket="${units}/punar-smplifyd.socket"
    service="${units}/punar-smplifyd.service"
    punard="${units}/punard.service"
    activation="${root}/crates/punar-smplifyd/src/activation.rs"
    violations=0
    violation() {
        printf 'smplifyd-activation violation %s\n' "$*" >&2
        violations=$((violations + 1))
    }
    expect() {
        # expect FILE SECTION KEY WANT
        got=$(ini_value "$1" "$2" "$3")
        [ "${got}" = "$4" ] || violation "S: ${1##*/} [$2] $3=${got}, expected $4"
    }
    lists() {
        # lists FILE SECTION KEY WORD — the accumulated KEY names WORD
        ini_values "$1" "$2" "$3" | grep -Fxq "$4"
    }

    for file in "${socket}" "${service}" "${punard}" "${activation}"; do
        [ -f "${file}" ] || { violation "missing ${file#"${root}"/}"; }
    done
    [ "${violations}" -eq 0 ] || exit 1

    # --- S1 the socket ---------------------------------------------------
    dialed=$(rust_const "${root}/crates/punard/src/enroll.rs" DEFAULT_CONTROL_PLANE_SOCKET)
    bound=$(rust_const "${root}/crates/punar-smplifyd/src/main.rs" DEFAULT_SOCKET)
    listen=$(ini_value "${socket}" Socket ListenStream)
    [ -n "${dialed}" ] || violation "S1: DEFAULT_CONTROL_PLANE_SOCKET not found in punard"
    [ "${listen}" = "${dialed}" ] \
        || violation "S1: the socket listens on ${listen}; punard dials ${dialed}"
    [ "${listen}" = "${bound}" ] \
        || violation "S1: the socket listens on ${listen}; the agent binds ${bound} without systemd"
    expect "${socket}" Socket SocketUser root
    expect "${socket}" Socket SocketGroup root
    expect "${socket}" Socket SocketMode 0600
    expect "${socket}" Socket DirectoryMode 0700
    expect "${socket}" Socket Accept no
    fd_name=$(rust_const "${activation}" LISTENER_NAME)
    [ -n "${fd_name}" ] || violation "S1: LISTENER_NAME not found in activation.rs"
    expect "${socket}" Socket FileDescriptorName "${fd_name}"
    expect "${socket}" Unit RefuseManualStop yes
    for key in TriggerLimitIntervalSec TriggerLimitBurst; do
        case "$(ini_value "${socket}" Socket "${key}")" in
            unset|empty|0|0s|infinity)
                violation "S1: ${key} must bound how often a failing agent is restarted" ;;
        esac
    done
    ! has_section "${socket}" Install || violation "S1: the socket has an [Install] section"

    # --- S2 the service ----------------------------------------------------
    for key in RuntimeDirectory RuntimeDirectoryMode; do
        [ "$(ini_value "${service}" Service "${key}")" = unset ] \
            || violation "S2: the service sets ${key}=, which deletes the socket node when it stops"
    done
    lists "${service}" Unit Requires punar-smplifyd.socket \
        || violation "S2: the service does not Require= its socket"
    lists "${service}" Unit After punar-smplifyd.socket \
        || violation "S2: the service is not ordered After= its socket"
    for key in Wants After Requires; do
        ! lists "${service}" Unit "${key}" network-online.target \
            || violation "S2: the service's ${key}= names network-online.target"
    done
    expect "${service}" Unit RefuseManualStop yes
    expect "${service}" Unit StartLimitIntervalSec 0
    expect "${service}" Service Restart always
    dormant=$(rust_const "${activation}" DORMANT_EXIT_STATUS)
    [ -n "${dormant}" ] || violation "S2: DORMANT_EXIT_STATUS not found in activation.rs"
    expect "${service}" Service RestartPreventExitStatus "${dormant}"
    expect "${service}" Service SuccessExitStatus "${dormant}"
    ! has_section "${service}" Install || violation "S2: the service has an [Install] section"

    # --- S3 punard -----------------------------------------------------------
    lists "${punard}" Unit Wants punar-smplifyd.socket \
        || violation "S3: punard.service does not Want= the agent's socket"
    lists "${punard}" Unit After punar-smplifyd.socket \
        || violation "S3: punard.service is not ordered After= the agent's socket"
    for unit in punar-smplifyd.socket punar-smplifyd.service; do
        ! lists "${punard}" Unit Requires "${unit}" \
            || violation "S3: punard.service Requires= ${unit}; cached policy must enforce without it"
    done

    # --- S4 nothing enables it -----------------------------------------------
    links=""
    for tree in \
        "${root}/os/images/mkosi.profiles" \
        "${root}/os/images/debian-mkosi.extra" \
        "${root}/os/images/installer-initrd" \
        "${root}/os/images/arm64" \
        "${root}/os/images/amd64-debian" \
        "${root}/os/modules"; do
        [ -d "${tree}" ] || continue
        links="${links}$(find "${tree}" -path '*.wants/punar-smplifyd.*' 2>/dev/null || true)"
    done
    [ -z "${links}" ] || violation "S4: a wants link enables the agent: ${links}"
    for manifest in "${root}"/os/images/expected-enabled-units.*.txt; do
        ! grep -q 'punar-smplifyd' "${manifest}" \
            || violation "S4: ${manifest##*/} names punar-smplifyd"
    done
    lab="${root}/tools/prepare-smplify-lab.sh"
    grep -q 'punar-smplifyd\.socket' "${lab}" \
        || violation "S4: the Smplify lab does not install the agent's socket"
    ! grep -Eq 'ln [^|]*punar-smplifyd\.(service|socket)' "${lab}" \
        || violation "S4: the Smplify lab links the agent into a target"

    # --- S5 the idle-RAM sampler -------------------------------------------
    sampler="${root}/os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/idle-ram.sh"
    units_line=$(grep -E '^PUNAR_SERVICE_UNITS=' "${sampler}" || true)
    [ -n "${units_line}" ] || violation "S5: idle-ram.sh has no PUNAR_SERVICE_UNITS"
    case "${units_line}" in
        *punar-smplifyd*) violation "S5: idle-ram.sh sums the agent as a resident service" ;;
    esac
    grep -q 'PUNAR_SMPLIFYD_PROCS=' "${sampler}" \
        || violation "S5: idle-ram.sh does not report the agent's process count"

    [ "${violations}" -eq 0 ]
)

check_tree "${REPO_ROOT}" || {
    echo "smplifyd-activation-contract-test: FAIL" >&2
    exit 1
}

# --- S6: each check rejects a tree that breaks it ----------------------------
WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT INT TERM
fixture() {
    rm -rf "${WORK}/tree"
    mkdir -p "${WORK}/tree"
    (cd "${REPO_ROOT}" && tar -cf - \
        os/images/mkosi.profiles/desktop/mkosi.extra/usr/lib/systemd/system \
        os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/idle-ram.sh \
        os/images/expected-enabled-units.arm64.txt \
        os/images/expected-enabled-units.x86_64.txt \
        os/images/expected-enabled-units.x86_64-debian.txt \
        crates/punard/src/enroll.rs \
        crates/punar-smplifyd/src/main.rs \
        crates/punar-smplifyd/src/activation.rs \
        tools/prepare-smplify-lab.sh) | (cd "${WORK}/tree" && tar -xf -)
}
UNITS=os/images/mkosi.profiles/desktop/mkosi.extra/usr/lib/systemd/system
rejects() {
    # rejects DESCRIPTION — the mutated fixture must fail check_tree
    if check_tree "${WORK}/tree" 2>/dev/null; then
        echo "smplifyd-activation-contract-test: FAIL: a tree where $1 passed" >&2
        exit 1
    fi
}
edit() {
    # edit FILE SED-EXPRESSION
    sed "$2" "${WORK}/tree/$1" > "${WORK}/edited" && mv "${WORK}/edited" "${WORK}/tree/$1"
}
insert_after() {
    # insert_after FILE LINE-PREFIX NEW-LINE — portable across BSD and GNU sed
    awk -v prefix="$2" -v line="$3" '
        { print }
        index($0, prefix) == 1 { print line }
    ' "${WORK}/tree/$1" > "${WORK}/edited" && mv "${WORK}/edited" "${WORK}/tree/$1"
}

fixture
check_tree "${WORK}/tree" || {
    echo "smplifyd-activation-contract-test: FAIL: the unmodified fixture is rejected" >&2
    exit 1
}

fixture; edit "${UNITS}/punar-smplifyd.socket" 's|^ListenStream=.*|ListenStream=/run/punar/other.sock|'
rejects "the socket listens where punard does not dial"
fixture; edit "${UNITS}/punar-smplifyd.socket" 's|^SocketMode=0600|SocketMode=0666|'
rejects "the socket is world-writable"
fixture; edit "${UNITS}/punar-smplifyd.socket" 's|^Accept=no|Accept=yes|'
rejects "every call gets its own agent"
fixture; edit "${UNITS}/punar-smplifyd.socket" 's|^RefuseManualStop=yes|RefuseManualStop=no|'
rejects "the socket can be stopped by hand"
fixture; edit "${UNITS}/punar-smplifyd.socket" 's|^TriggerLimitBurst=.*|TriggerLimitBurst=0|'
rejects "the trigger rate is unbounded"
fixture; printf '\n[Install]\nWantedBy=sockets.target\n' >> "${WORK}/tree/${UNITS}/punar-smplifyd.socket"
rejects "the socket is enabled on every device"
fixture; insert_after "${UNITS}/punar-smplifyd.service" 'StateDirectory=' 'RuntimeDirectory=punar-smplifyd'
rejects "the service owns the socket's directory"
fixture; edit "${UNITS}/punar-smplifyd.service" 's|^RestartPreventExitStatus=.*|RestartPreventExitStatus=74|'
rejects "the dormant status is not the agent's"
fixture; edit "${UNITS}/punar-smplifyd.service" 's|^Restart=always|Restart=on-failure|'
rejects "a killed agent is not restarted"
fixture; edit "${UNITS}/punar-smplifyd.service" 's|^StartLimitIntervalSec=0|StartLimitIntervalSec=10s|'
rejects "a few kills leave the agent stopped"
fixture; edit "${UNITS}/punar-smplifyd.service" 's|^RefuseManualStop=yes|RefuseManualStop=no|'
rejects "the agent can be stopped by hand"
fixture; edit "${UNITS}/punar-smplifyd.service" 's|^After=punar-smplifyd.socket|After=punar-smplifyd.socket network-online.target|'
rejects "the agent waits for the network"
fixture; edit "${UNITS}/punard.service" 's|^Wants=punar-smplifyd.socket|Wants=|'
rejects "punard does not pull in the socket"
fixture; insert_after "${UNITS}/punard.service" 'Wants=punar-smplifyd.socket' 'Requires=punar-smplifyd.service'
rejects "punard cannot run without the agent"
fixture; mkdir -p "${WORK}/tree/${UNITS}/multi-user.target.wants" \
    && ln -s ../punar-smplifyd.service "${WORK}/tree/${UNITS}/multi-user.target.wants/punar-smplifyd.service"
rejects "the agent is enabled at boot"
fixture; printf 'usr/lib/systemd/system/multi-user.target.wants/punar-smplifyd.service -> ../punar-smplifyd.service\n' \
    >> "${WORK}/tree/os/images/expected-enabled-units.x86_64.txt"
rejects "a reviewed manifest enables the agent"
fixture; printf 'ln -sfn ../punar-smplifyd.service /x.wants/\n' \
    >> "${WORK}/tree/tools/prepare-smplify-lab.sh"
rejects "the Smplify lab enables the agent"
fixture; edit crates/punar-smplifyd/src/activation.rs 's|DORMANT_EXIT_STATUS: u8 = 75|DORMANT_EXIT_STATUS: u8 = 76|'
rejects "the agent's dormant status and the unit's differ"
fixture; edit os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/idle-ram.sh \
    's|^PUNAR_SERVICE_UNITS="\(.*\)"|PUNAR_SERVICE_UNITS="\1 punar-smplifyd.service"|'
rejects "the sampler sums the agent as resident"

echo "PUNAR_SMPLIFYD_ACTIVATION_CONTRACT_OK"
