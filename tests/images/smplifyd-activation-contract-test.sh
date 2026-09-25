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
#       constant, at once after a kill and backing off to less than punard's
#       liveness wait, no start limit, no network-online ordering, no
#       CPUAccounting= (removed in systemd 258), no [Install];
#   S3  punard.service Wants= and is ordered After= the socket and the
#       service (it stops first at shutdown), Requires= neither (cached
#       policy enforces with the agent down) in the unit or any drop-in of
#       any profile, refuses a manual stop and is restarted after any exit
#       with no start limit; punard-reconcile.timer, which makes every pass,
#       refuses a manual stop, and the one drop-in that lifts it is the
#       development image's, which release check A5 refuses;
#   S4  no tree ships a wants, requires or upholds link to either unit, no
#       other unit Wants=, Requires=, BindsTo=, Requisite=, Upholds= or
#       PartOf= the agent, no reviewed enabled-units manifest names it, and
#       the Smplify lab installs the socket rather than an enablement;
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

# A systemd time span in milliseconds (`100ms`, `5s`, `2min`, `1`), or empty.
span_ms() {
    case "$1" in
        *ms) n=${1%ms}; unit=1 ;;
        *min) n=${1%min}; unit=60000 ;;
        *s) n=${1%s}; unit=1000 ;;
        *) n=$1; unit=1000 ;;
    esac
    case "${n}" in ''|*[!0-9]*) return 0 ;; esac
    echo $((n * unit))
}

# check_tree ROOT — print every violation; exit non-zero if any.
check_tree() (
    root=$1
    units="${root}/os/images/mkosi.profiles/desktop/mkosi.extra/usr/lib/systemd/system"
    socket="${units}/punar-smplifyd.socket"
    service="${units}/punar-smplifyd.service"
    punard="${units}/punard.service"
    timer="${units}/punard-reconcile.timer"
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

    for file in "${socket}" "${service}" "${punard}" "${timer}" "${activation}"; do
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
    # A call made while a restart is pending waits it out (systemd counts the
    # service as starting and queues no earlier start), so the delay after a
    # kill must be short, and the back-off must end well inside punard's
    # liveness wait.
    restart_ms=$(span_ms "$(ini_value "${service}" Service RestartSec)")
    max_ms=$(span_ms "$(ini_value "${service}" Service RestartMaxDelaySec)")
    liveness=$(sed -n 's/.*IDENTITY_STATUS_CALL_TIMEOUT: Duration = Duration::from_secs(\([0-9]*\));.*/\1/p' \
        "${root}/crates/punard/src/enroll.rs")
    [ -n "${restart_ms}" ] && [ "${restart_ms}" -le 1000 ] \
        || violation "S2: RestartSec=${restart_ms:-unset} ms; a call after a kill waits it out"
    [ -n "${max_ms}" ] && [ -n "${liveness}" ] && [ "${max_ms}" -lt $((liveness * 1000)) ] \
        || violation "S2: RestartMaxDelaySec=${max_ms:-unset} ms is not inside punard's ${liveness:-?} s liveness wait"
    case "$(ini_value "${service}" Service RestartSteps)" in
        unset|empty|0) violation "S2: no RestartSteps=, so a failing agent is restarted without backing off" ;;
    esac
    [ "$(ini_value "${service}" Service CPUAccounting)" = unset ] \
        || violation "S2: the service sets CPUAccounting=, which systemd 258+ warns about on every load"
    ! has_section "${service}" Install || violation "S2: the service has an [Install] section"

    # --- S3 punard and the timer that drives every pass -----------------------
    lists "${punard}" Unit Wants punar-smplifyd.socket \
        || violation "S3: punard.service does not Want= the agent's socket"
    lists "${punard}" Unit After punar-smplifyd.socket \
        || violation "S3: punard.service is not ordered After= the agent's socket"
    lists "${punard}" Unit After punar-smplifyd.service \
        || violation "S3: punard.service is not ordered After= the agent, so it may not stop first"
    for unit_file in "${punard}" $(find "${root}/os/images/mkosi.profiles" -path '*/punard.service.d/*.conf' 2>/dev/null); do
        for unit in punar-smplifyd.socket punar-smplifyd.service; do
            for key in Requires BindsTo Requisite; do
                ! lists "${unit_file}" Unit "${key}" "${unit}" \
                    || violation "S3: ${unit_file#"${root}"/} ${key}= ${unit}; cached policy must enforce without it"
            done
        done
    done
    expect "${punard}" Unit RefuseManualStop yes
    expect "${punard}" Unit StartLimitIntervalSec 0
    expect "${punard}" Service Restart always
    expect "${timer}" Unit RefuseManualStop yes
    lifted=$(grep -rlE '^[[:space:]]*RefuseManualStop=(no|false|0)' \
        "${root}/os/images/mkosi.profiles" 2>/dev/null || true)
    for dropin in ${lifted}; do
        case "${dropin}" in
            */mkosi.profiles/dev/*/punard-reconcile.timer.d/*.conf)
                grep -qF "${dropin##*/}" "${root}/os/images/check-release-image.sh" \
                    || violation "S3: release check A5 does not refuse ${dropin##*/}" ;;
            *) violation "S3: ${dropin#"${root}"/} lifts RefuseManualStop= outside the development image's timer drop-in" ;;
        esac
    done

    # --- S4 nothing enables it -----------------------------------------------
    links=""
    pulls=""
    for tree in \
        "${root}/os/images/mkosi.profiles" \
        "${root}/os/images/debian-mkosi.extra" \
        "${root}/os/images/installer-initrd" \
        "${root}/os/images/arm64" \
        "${root}/os/images/amd64-debian" \
        "${root}/os/modules"; do
        [ -d "${tree}" ] || continue
        links="${links}$(find "${tree}" \( -path '*.wants/punar-smplifyd.*' \
            -o -path '*.requires/punar-smplifyd.*' -o -path '*.upholds/punar-smplifyd.*' \) \
            2>/dev/null || true)"
        # Any other unit pulling the agent in, but punard's Wants= of the
        # socket, which is the whole of its lifetime.
        pulls="${pulls}$(find "${tree}" -type f \( -name '*.service' -o -name '*.socket' \
            -o -name '*.target' -o -name '*.timer' -o -name '*.path' -o -name '*.conf' \) \
            ! -name 'punar-smplifyd.*' -exec grep -lE \
            '^[[:space:]]*(Wants|Requires|BindsTo|Requisite|Upholds|PartOf)=.*punar-smplifyd' {} + \
            2>/dev/null | while IFS= read -r file; do
                if [ "${file##*/}" = punard.service ] \
                    && ! grep -E '^[[:space:]]*(Wants|Requires|BindsTo|Requisite|Upholds|PartOf)=.*punar-smplifyd' "${file}" \
                        | grep -vxq 'Wants=punar-smplifyd.socket'; then
                    continue
                fi
                printf '%s ' "${file#"${root}"/}"
            done)"
    done
    [ -z "${links}" ] || violation "S4: a link enables the agent: ${links}"
    [ -z "${pulls}" ] || violation "S4: another unit pulls the agent in: ${pulls}"
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
        os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/systemd/system \
        os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/idle-ram.sh \
        os/images/check-release-image.sh \
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
fixture; edit os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/idle-ram.sh \
    '/PUNAR_SMPLIFYD_PROCS=/d'
rejects "the sampler does not report the agent's process count"
fixture; edit "${UNITS}/punar-smplifyd.socket" 's|^SocketUser=root|SocketUser=punar|'
rejects "the socket belongs to another user"
fixture; edit "${UNITS}/punar-smplifyd.socket" 's|^SocketGroup=root|SocketGroup=punar|'
rejects "the socket belongs to another group"
fixture; edit "${UNITS}/punar-smplifyd.socket" 's|^DirectoryMode=0700|DirectoryMode=0755|'
rejects "the socket's directory is open to everyone"
fixture; edit "${UNITS}/punar-smplifyd.socket" 's|^FileDescriptorName=.*|FileDescriptorName=other|'
rejects "the descriptor is named as the agent does not expect"
fixture; edit "${UNITS}/punar-smplifyd.socket" 's|^TriggerLimitIntervalSec=.*|TriggerLimitIntervalSec=0|'
rejects "the trigger interval is unbounded"
fixture; edit "${UNITS}/punar-smplifyd.service" 's|^SuccessExitStatus=.*|SuccessExitStatus=0|'
rejects "the dormant exit counts as a failure"
fixture; edit "${UNITS}/punar-smplifyd.service" 's|^Requires=punar-smplifyd.socket|Requires=|'
rejects "the service does not require its socket"
fixture; edit "${UNITS}/punar-smplifyd.service" 's|^After=punar-smplifyd.socket|After=|'
rejects "the service is not ordered after its socket"
fixture; printf '\n[Install]\nWantedBy=multi-user.target\n' >> "${WORK}/tree/${UNITS}/punar-smplifyd.service"
rejects "the service is enabled on every device"
fixture; edit "${UNITS}/punar-smplifyd.service" 's|^RestartSec=.*|RestartSec=10s|'
rejects "a call after a kill waits ten seconds"
fixture; edit "${UNITS}/punar-smplifyd.service" 's|^RestartMaxDelaySec=.*|RestartMaxDelaySec=30s|'
rejects "the back-off outlasts the liveness wait"
fixture; edit "${UNITS}/punar-smplifyd.service" '/^RestartSteps=/d'
rejects "a failing agent is restarted without backing off"
fixture; insert_after "${UNITS}/punar-smplifyd.service" 'IOAccounting=yes' 'CPUAccounting=yes'
rejects "the service sets a directive systemd has removed"
fixture; edit "${UNITS}/punard.service" 's|^After=punar-smplifyd.socket punar-smplifyd.service|After=punar-smplifyd.socket|'
rejects "punard may stop after the agent at shutdown"
fixture; edit "${UNITS}/punard.service" 's|^RefuseManualStop=yes|RefuseManualStop=no|'
rejects "punard can be stopped by hand"
fixture; edit "${UNITS}/punard.service" 's|^Restart=always|Restart=on-failure|'
rejects "a punard stopped by a signal stays stopped"
fixture; edit "${UNITS}/punard.service" 's|^StartLimitIntervalSec=0|StartLimitIntervalSec=10s|'
rejects "a few kills leave punard stopped"
fixture; edit "${UNITS}/punard-reconcile.timer" 's|^RefuseManualStop=yes|RefuseManualStop=no|'
rejects "the reconcile timer can be stopped by hand"
fixture; mkdir -p "${WORK}/tree/${UNITS}/punard.service.d" \
    && printf '[Unit]\nRequires=punar-smplifyd.service\n' > "${WORK}/tree/${UNITS}/punard.service.d/50-x.conf"
rejects "a punard drop-in makes it depend on the agent"
fixture; mkdir -p "${WORK}/tree/${UNITS}/punard.service.d" \
    && printf '[Unit]\nRefuseManualStop=no\n' > "${WORK}/tree/${UNITS}/punard.service.d/50-x.conf"
rejects "a drop-in lets punard be stopped by hand"
fixture; mkdir -p "${WORK}/tree/${UNITS}/punar-smplifyd.service.d" \
    && printf '[Unit]\nRefuseManualStop=no\n' > "${WORK}/tree/${UNITS}/punar-smplifyd.service.d/50-x.conf"
rejects "a drop-in lets the agent be stopped by hand"
fixture; edit os/images/check-release-image.sh 's|10-dev-stoppable.conf|10-other.conf|g'
rejects "release check A5 lets the timer's development drop-in ship"
fixture; mkdir -p "${WORK}/tree/${UNITS}/multi-user.target.requires" \
    && ln -s ../punar-smplifyd.socket "${WORK}/tree/${UNITS}/multi-user.target.requires/punar-smplifyd.socket"
rejects "a requires link pulls the agent in at boot"
fixture; printf '[Unit]\nWants=punar-smplifyd.service\n' > "${WORK}/tree/${UNITS}/punar-x.service"
rejects "another unit pulls the agent in"

echo "PUNAR_SMPLIFYD_ACTIVATION_CONTRACT_OK"
