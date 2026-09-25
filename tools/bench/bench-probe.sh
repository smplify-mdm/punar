#!/bin/sh
# Image-agnostic in-guest benchmark probe (tools/bench/README.md).
#
# Runs as root from bench-probe.service, its own unit and therefore its own
# cgroup, on any systemd distribution: nothing here names a Punar service, and
# the same bytes run on every system the harness measures. It is a
# generalisation of os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/
# idle-ram.sh and keeps that file's canonical method unchanged:
#
#   wait for the graphical session, settle 600 s with no input, then sample
#   every 10 s for 300 s (30 samples); used = MemTotal - MemAvailable.
#
# Everything it reads is streamed as JSON Lines to the virtio-serial port
# bench.export as soon as it is read, so nothing accumulates in the guest's
# tmpfs (which would count as used memory). The host parses the stream
# (tools/bench/bench_parse.py); this script does no arithmetic that a
# reader could want to redo differently.
#
# The probe reports its own cost: its cgroup's memory is sampled with every
# sample and its CPU and writes are in the cgroup snapshots, so the host
# subtracts them.
#
# Test hooks (never set in a measured run): BENCH_ROOT prefixes every /proc
# and /sys path, BENCH_EXPORT names the output, BENCH_TEST_TICK is run between
# phases. tests/performance/bench-probe-test.sh drives them.

set -u

PROBE_VERSION=1
R="${BENCH_ROOT:-}"
PROC="${R}/proc"
SYS="${R}/sys"
CG="${SYS}/fs/cgroup"
RUN="${R}/run"
EXPORT="${BENCH_EXPORT:-/dev/virtio-ports/bench.export}"
BLOB_LIMIT=262144

# Canonical method (idle-ram.sh, PERFORMANCE_BUDGETS.md §2.1-2.2). The
# config channel may change these only to make a run shorter for a smoke
# test; any change makes the run non-canonical and the host refuses to use
# it for a claim.
SETTLE_SECS=600
SAMPLE_COUNT=30
SAMPLE_INTERVAL=10
SESSION_TIMEOUT=1800
POLL_SECS=2
WORKLOAD=no
RUN_ID="unset"
CONFIG_SOURCE="defaults"

PROBE_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
WORKLOAD_SCRIPT="${PROBE_DIR}/bench-workload.sh"
if [ -n "${CREDENTIALS_DIRECTORY:-}" ] && [ -r "${CREDENTIALS_DIRECTORY}/bench.workload" ]; then
    WORKLOAD_SCRIPT="${CREDENTIALS_DIRECTORY}/bench.workload"
fi

is_uint() {
    case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac
}

test_tick() {
    if [ -n "${BENCH_TEST_TICK:-}" ]; then
        "${BENCH_TEST_TICK}" "$1"
    fi
}

pause() {
    if [ "$1" -gt 0 ]; then
        sleep "$1"
    fi
}

load_config() {
    [ -r "$1" ] || return 1
    while IFS='=' read -r key value; do
        case "${key}" in
            settle_secs) is_uint "${value}" && SETTLE_SECS="${value}" ;;
            samples) is_uint "${value}" && [ "${value}" -gt 0 ] && SAMPLE_COUNT="${value}" ;;
            interval) is_uint "${value}" && SAMPLE_INTERVAL="${value}" ;;
            session_timeout) is_uint "${value}" && SESSION_TIMEOUT="${value}" ;;
            workload) case "${value}" in yes|no) WORKLOAD="${value}" ;; esac ;;
            run_id)
                case "${value}" in
                    ''|*[!A-Za-z0-9._-]*) ;;
                    *) RUN_ID="${value}" ;;
                esac
                ;;
        esac
    done < "$1"
    return 0
}

# Per-run settings come from QEMU's fw_cfg (opt/bench/config), so one
# injected image serves every run; the file next to the script is the
# fallback. qemu_fw_cfg is loaded only when absent, and that is recorded.
FW_CFG_LOADED=no
FW_CFG_CONFIG="${SYS}/firmware/qemu_fw_cfg/by_name/opt/bench/config/raw"
if [ ! -e "${SYS}/firmware/qemu_fw_cfg" ] && [ -z "${R}" ] \
        && command -v modprobe >/dev/null 2>&1; then
    modprobe qemu_fw_cfg 2>/dev/null && FW_CFG_LOADED=yes
fi
if load_config "${FW_CFG_CONFIG}"; then
    CONFIG_SOURCE="fw_cfg"
elif [ -n "${CREDENTIALS_DIRECTORY:-}" ] && load_config "${CREDENTIALS_DIRECTORY}/bench.conf"; then
    CONFIG_SOURCE="credential"
elif load_config "${PROBE_DIR}/bench.conf"; then
    CONFIG_SOURCE="file"
fi

CANONICAL=no
if [ "${SETTLE_SECS}" -eq 600 ] && [ "${SAMPLE_COUNT}" -eq 30 ] \
        && [ "${SAMPLE_INTERVAL}" -eq 10 ]; then
    CANONICAL=yes
fi

# No export port means this boot is not a measured run (the harness boots
# the same disk once to create the first account). Wait briefly for udev to
# create the port, then leave quietly.
waited=0
while [ ! -e "${EXPORT}" ] && [ "${waited}" -lt 30 ]; do
    sleep 1
    waited=$((waited + 1))
done
[ -e "${EXPORT}" ] || exit 0
exec 3>>"${EXPORT}"

# ---- JSON helpers (POSIX awk: mawk, gawk and busybox) ----------------------
# jesc escapes one line for a JSON string; numbers are passed through as the
# kernel printed them, after a pattern check, never converted by awk (mawk
# would print large counters in exponent form).
AWK_LIB='
function jesc(s,    out, c) {
    out = ""
    while (match(s, JSON_SPECIAL)) {
        c = substr(s, RSTART, 1)
        out = out substr(s, 1, RSTART - 1) JSON_ESC[c]
        s = substr(s, RSTART + 1)
    }
    return out s
}
function jstr(s) { return "\"" jesc(s) "\"" }
function jnum(v) { return (v ~ /^-?[0-9]+(\.[0-9]+)?$/) ? v : "null" }
function readline1(f,    line, got) {
    got = (getline line < f)
    close(f)
    return (got > 0) ? line : ""
}
BEGIN {
    JSON_ESC["\\"] = "\\\\"
    JSON_ESC["\""] = "\\\""
    JSON_ESC["\n"] = "\\n"
    JSON_ESC["\t"] = "\\t"
    JSON_ESC["\r"] = "\\r"
    _cls = ""
    for (_i = 1; _i < 32; _i++) {
        _c = sprintf("%c", _i)
        if (!(_c in JSON_ESC)) JSON_ESC[_c] = sprintf("\\u%04x", _i)
        if (_i != 10) _cls = _cls _c
    }
    JSON_SPECIAL = "[\\\\\"" _cls "]"
}
'

uptime_now() {
    awk '{print $1}' "${PROC}/uptime"
}

# emit_kv TYPE KEY=VALUE... -- one flat record, every value a JSON string.
# Keys must not be "type" or "uptime", which every record already carries.
emit_kv() {
    record_type=$1
    shift
    printf '%s\n' "$@" | awk -v t="${record_type}" -v up="$(uptime_now)" "${AWK_LIB}"'
        BEGIN { printf "{\"type\":%s,\"uptime\":%s", jstr(t), jnum(up) }
        $0 == "" { next }
        {
            k = $0; sub(/=.*/, "", k)
            v = $0; sub(/^[^=]*=/, "", v)
            printf ",%s:%s", jstr(k), jstr(v)
        }
        END { printf "}\n" }' >&3
}

# blob NAME COMMAND... -- a command's output as one JSON string, with its
# exit status. Output goes through a file under /run only so the status
# survives; the file is removed at once.
BLOB_TMP="${RUN}/bench-probe"
mkdir -p "${BLOB_TMP}" 2>/dev/null || BLOB_TMP="${TMPDIR:-/tmp}"
blob() {
    name=$1
    shift
    out="${BLOB_TMP}/blob.$$"
    if command -v "$1" >/dev/null 2>&1; then
        "$@" > "${out}" 2>&1
        rc=$?
    else
        echo "absent: $1" > "${out}"
        rc=127
    fi
    head -c "${BLOB_LIMIT}" "${out}" | awk -v name="${name}" -v rc="${rc}" \
            -v up="$(uptime_now)" "${AWK_LIB}"'
        BEGIN { printf "{\"type\":\"blob\",\"name\":%s,\"rc\":%s,\"uptime\":%s,\"text\":\"", jstr(name), jnum(rc), jnum(up) }
        { printf "%s\\n", jesc($0) }
        END { printf "\"}\n" }' >&3
    rm -f -- "${out}"
}

# file_blob NAME PATH -- a file's content as a blob (absent is recorded).
file_blob() {
    if [ -r "$2" ]; then
        blob "$1" cat "$2"
    else
        emit_kv absent name="$1" path="$2"
    fi
}

# Used as a command word inside blob's argument list.
# shellcheck disable=SC2329
bounded() {
    if command -v timeout >/dev/null 2>&1; then
        timeout "$@"
    else
        shift
        "$@"
    fi
}

# ---- session detection ------------------------------------------------------
# logind's per-session state files are read directly (no process per poll);
# loginctl is the fallback. Prints "class state type uid user id" per session.
list_sessions() {
    sessions_dir="${RUN}/systemd/sessions"
    found=no
    for f in "${sessions_dir}"/*; do
        [ -f "${f}" ] || continue
        case "${f##*/}" in *.ref) continue ;; esac
        found=yes
        awk -v id="${f##*/}" -F= '
            $1 == "CLASS" { class = $2 }
            $1 == "STATE" { state = $2 }
            $1 == "TYPE" { type = $2 }
            $1 == "UID" { uid = $2 }
            $1 == "USER" { user = $2 }
            END {
                if (class == "") class = "-"
                if (state == "") state = "-"
                if (type == "") type = "-"
                if (uid == "") uid = "-"
                if (user == "") user = "-"
                print class, state, type, uid, user, id
            }' "${f}"
    done
    if [ "${found}" = no ] && command -v loginctl >/dev/null 2>&1; then
        for id in $(loginctl list-sessions --no-legend --no-pager 2>/dev/null | awk '{print $1}'); do
            loginctl show-session "${id}" -p Class -p State -p Type -p User -p Name 2>/dev/null \
                | awk -v id="${id}" -F= '
                    $1 == "Class" { class = $2 }
                    $1 == "State" { state = $2 }
                    $1 == "Type" { type = $2 }
                    $1 == "User" { uid = $2 }
                    $1 == "Name" { user = $2 }
                    END { print (class == "" ? "-" : class), (state == "" ? "-" : state), (type == "" ? "-" : type), (uid == "" ? "-" : uid), (user == "" ? "-" : user), id }'
        done
    fi
}

# processes_of UID -- "comm pid starttime_ticks" for that uid's processes.
processes_of() {
    for d in "${PROC}"/[0-9]*; do
        [ -d "${d}" ] && printf '%s\n' "${d}"
    done | awk -v want="$1" '
        {
            d = $0
            uid = ""
            f = d "/status"
            while ((getline line < f) > 0) {
                if (line ~ /^Uid:/) { split(line, a, /[ \t]+/); uid = a[2]; break }
            }
            close(f)
            if (uid != want) next
            f = d "/comm"
            comm = ""
            if ((getline comm < f) <= 0) comm = ""
            close(f)
            f = d "/stat"
            st = ""
            if ((getline st < f) > 0) {
                sub(/^.*\) /, "", st)
                n = split(st, s, " ")
                start = (n >= 20) ? s[20] : ""
            }
            close(f)
            pid = d; sub(/.*\//, "", pid)
            if (comm != "") print comm, pid, start
        }'
}

GREETER_SEEN=no
SESSION_LINE=""
COMPOSITOR=""
SHELL_PROC=""
wait_for_session() {
    waited=0
    while [ "${waited}" -lt "${SESSION_TIMEOUT}" ]; do
        sessions="$(list_sessions)"
        if [ "${GREETER_SEEN}" = no ]; then
            greeter="$(printf '%s\n' "${sessions}" | awk '$1 == "greeter" && ($2 == "active" || $2 == "online") {print; exit}')"
            if [ -n "${greeter}" ]; then
                # Split on purpose: six space-separated fields.
                # shellcheck disable=SC2086
                set -- ${greeter}
                greeter_procs="$(processes_of "$4")"
                greeter_shell="$(printf '%s\n' "${greeter_procs}" | awk '$1 == "qs" || $1 == "quickshell" || $1 ~ /^sddm-greeter/ || $1 == "gtkgreet" || $1 == "regreet" {print $1; exit}')"
                if [ -n "${greeter_shell}" ]; then
                    GREETER_SEEN=yes
                    emit_kv greeter_ready session="$6" uid="$4" user="$5" session_type="$3" shell="${greeter_shell}" \
                        shell_start_ticks="$(printf '%s\n' "${greeter_procs}" | awk -v s="${greeter_shell}" '$1 == s {print $3; exit}')"
                fi
            fi
        fi
        # A user session that is active, whose owner runs Hyprland and a
        # Quickshell process (quickshell on Omarchy, qs on Punar).
        for candidate in $(printf '%s\n' "${sessions}" | awk '$1 == "user" && $2 == "active" {print $6}'); do
            line="$(printf '%s\n' "${sessions}" | awk -v id="${candidate}" '$6 == id {print; exit}')"
            # shellcheck disable=SC2086
            set -- ${line}
            procs="$(processes_of "$4")"
            COMPOSITOR="$(printf '%s\n' "${procs}" | awk '$1 == "Hyprland" {print; exit}')"
            SHELL_PROC="$(printf '%s\n' "${procs}" | awk '$1 == "qs" || $1 == "quickshell" || $1 == ".quickshell-wra" {print; exit}')"
            if [ -n "${COMPOSITOR}" ] && [ -n "${SHELL_PROC}" ]; then
                SESSION_LINE="${line}"
                return 0
            fi
        done
        test_tick poll
        pause "${POLL_SECS}"
        waited=$((waited + POLL_SECS))
    done
    return 1
}

# ---- snapshots ----------------------------------------------------------------
physical_disks() {
    for d in "${SYS}"/block/*; do
        [ -r "${d}/dev" ] || continue
        name="${d##*/}"
        case "${name}" in
            vd*|sd*|hd*|xvd*|nvme*n*|mmcblk*) ;;
            *) continue ;;
        esac
        case "${name}" in *boot*|*rpmb*) continue ;; esac
        printf '%s %s\n' "${name}" "$(cat "${d}/dev")"
    done
}

emit_devices() {
    {
        physical_disks | awk '{print "disk", $1, $2}'
        for d in "${SYS}"/block/*; do
            [ -r "${d}/dev" ] || continue
            name="${d##*/}"
            case "${name}" in dm-*|md*|zram*) ;; *) continue ;; esac
            slaves=""
            for s in "${d}"/slaves/*; do
                [ -e "${s}" ] && slaves="${slaves}${slaves:+,}${s##*/}"
            done
            printf 'virtual %s %s %s\n' "${name}" "$(cat "${d}/dev")" "${slaves:--}"
        done
    } | awk -v up="$(uptime_now)" "${AWK_LIB}"'
        BEGIN { printf "{\"type\":\"devices\",\"uptime\":%s,\"list\":[", jnum(up) }
        {
            printf "%s{\"kind\":%s,\"name\":%s,\"dev\":%s", sep, jstr($1), jstr($2), jstr($3)
            if ($1 == "virtual") printf ",\"slaves\":%s", jstr($4)
            printf "}"
            sep = ","
        }
        END { printf "]}\n" }' >&3
}

# Every cgroup in the tree: memory, CPU and I/O per device. The host sums
# only what does not overlap (top-level cgroups against the root's device
# counter), never a parent with its children.
emit_cgroups() {
    phase=$1
    find "${CG}" -type d 2>/dev/null | awk -v root="${CG}" -v phase="${phase}" \
            -v up="$(uptime_now)" "${AWK_LIB}"'
        BEGIN { printf "{\"type\":\"cgroups\",\"phase\":%s,\"uptime\":%s,\"list\":[", jstr(phase), jnum(up) }
        {
            d = $0
            rel = substr(d, length(root) + 1)
            if (rel == "") rel = "/"
            mem = jnum(readline1(d "/memory.current"))
            peak = jnum(readline1(d "/memory.peak"))
            cpu = "null"; usr = "null"; sys = "null"
            f = d "/cpu.stat"
            while ((getline line < f) > 0) {
                split(line, a, " ")
                if (a[1] == "usage_usec") cpu = jnum(a[2])
                else if (a[1] == "user_usec") usr = jnum(a[2])
                else if (a[1] == "system_usec") sys = jnum(a[2])
            }
            close(f)
            anon = "null"; file = "null"; shmem = "null"; kern = "null"
            f = d "/memory.stat"
            while ((getline line < f) > 0) {
                split(line, a, " ")
                if (a[1] == "anon") anon = jnum(a[2])
                else if (a[1] == "file") file = jnum(a[2])
                else if (a[1] == "shmem") shmem = jnum(a[2])
                else if (a[1] == "kernel") kern = jnum(a[2])
            }
            close(f)
            io = ""
            f = d "/io.stat"
            while ((getline line < f) > 0) {
                n = split(line, a, " ")
                rb = 0; wb = 0; ri = 0; wi = 0
                for (j = 2; j <= n; j++) {
                    split(a[j], kv, "=")
                    if (kv[1] == "rbytes") rb = kv[2]
                    else if (kv[1] == "wbytes") wb = kv[2]
                    else if (kv[1] == "rios") ri = kv[2]
                    else if (kv[1] == "wios") wi = kv[2]
                }
                io = io (io == "" ? "" : ",") jstr(a[1]) ":[" jnum(rb) "," jnum(wb) "," jnum(ri) "," jnum(wi) "]"
            }
            close(f)
            printf "%s{\"p\":%s,\"mem\":%s,\"peak\":%s,\"anon\":%s,\"file\":%s,\"shmem\":%s,\"kernel\":%s,\"cpu_us\":%s,\"user_us\":%s,\"system_us\":%s,\"io\":{%s}}", sep, jstr(rel), mem, peak, anon, file, shmem, kern, cpu, usr, sys, io
            sep = ","
        }
        END { printf "]}\n" }' >&3
}

emit_counters() {
    phase=$1
    set -- kind=stat "${PROC}/stat" kind=diskstats "${PROC}/diskstats" kind=interrupts "${PROC}/interrupts" kind=vmstat "${PROC}/vmstat"
    for p in cpu memory io irq; do
        [ -r "${PROC}/pressure/${p}" ] && set -- "$@" "kind=psi_${p}" "${PROC}/pressure/${p}"
    done
    awk -v phase="${phase}" -v up="$(uptime_now)" "${AWK_LIB}"'
        kind == "stat" {
            if ($1 ~ /^cpu[0-9]*$/) {
                v = "["
                for (i = 2; i <= 11; i++) v = v (i > 2 ? "," : "") ((i <= NF) ? jnum($i) : "0")
                cpus = cpus (cpus == "" ? "" : ",") jstr($1) ":" v "]"
            } else if ($1 == "intr" || $1 == "ctxt" || $1 == "softirq" || $1 == "processes") {
                other = other (other == "" ? "" : ",") jstr($1) ":" jnum($2)
            }
            next
        }
        kind == "diskstats" {
            if (NF >= 10) disks = disks (disks == "" ? "" : ",") jstr($1 ":" $2) ":{\"name\":" jstr($3) ",\"rd_sectors\":" jnum($6) ",\"wr_ios\":" jnum($8) ",\"wr_sectors\":" jnum($10) "}"
            next
        }
        kind == "interrupts" {
            if (FNR == 1) { ncpu = NF; next }
            irq = $1; sub(/:$/, "", irq)
            total = 0
            for (i = 2; i <= ncpu + 1 && i <= NF; i++) { if ($i ~ /^[0-9]+$/) total += $i; else break }
            desc = ""
            for (j = i; j <= NF; j++) desc = desc (desc == "" ? "" : " ") $j
            irqs = irqs (irqs == "" ? "" : ",") "{\"irq\":" jstr(irq) ",\"total\":" sprintf("%.0f", total) ",\"desc\":" jstr(desc) "}"
            next
        }
        kind == "vmstat" { vm = vm (vm == "" ? "" : ",") jstr($1) ":" jnum($2); next }
        kind ~ /^psi_/ {
            res = substr(kind, 5)
            line = "{"
            for (i = 2; i <= NF; i++) { split($i, kv, "="); line = line (i > 2 ? "," : "") jstr(kv[1]) ":" jnum(kv[2]) }
            psi[res] = psi[res] (psi[res] == "" ? "" : ",") jstr($1) ":" line "}"
            if (!(res in seen)) { seen[res] = 1; order = order (order == "" ? "" : " ") res }
            next
        }
        END {
            printf "{\"type\":\"counters\",\"phase\":%s,\"uptime\":%s,\"stat\":{\"cpus\":{%s}%s},\"diskstats\":{%s},\"interrupts\":[%s],\"vmstat\":{%s},\"pressure\":{", jstr(phase), jnum(up), cpus, (other == "" ? "" : "," other), disks, irqs, vm
            n = split(order, rs, " ")
            for (i = 1; i <= n; i++) printf "%s%s:{%s}", (i > 1 ? "," : ""), jstr(rs[i]), psi[rs[i]]
            printf "}}\n"
        }' "$@" >&3
}

SAMPLE_VM_KEYS='^(nr_free_pages|nr_anon_pages|nr_file_pages|nr_shmem|nr_dirty|nr_writeback|pgfault|pgmajfault|pswpin|pswpout|oom_kill|workingset_refault_anon|workingset_refault_file|pgscan_kswapd|pgscan_direct|pgsteal_kswapd|pgsteal_direct|compact_stall|thp_fault_alloc|thp_collapse_alloc)$'
emit_sample() {
    idx=$1
    set -- kind=uptime "${PROC}/uptime" kind=meminfo "${PROC}/meminfo" kind=vmstat "${PROC}/vmstat" kind=stat "${PROC}/stat" kind=loadavg "${PROC}/loadavg"
    for p in cpu memory io irq; do
        [ -r "${PROC}/pressure/${p}" ] && set -- "$@" "kind=psi_${p}" "${PROC}/pressure/${p}"
    done
    if [ -n "${PROBE_CG_DIR}" ]; then
        [ -r "${PROBE_CG_DIR}/memory.current" ] && set -- "$@" kind=probe_mem "${PROBE_CG_DIR}/memory.current"
        [ -r "${PROBE_CG_DIR}/memory.stat" ] && set -- "$@" kind=probe_memstat "${PROBE_CG_DIR}/memory.stat"
    fi
    awk -v idx="${idx}" -v vmkeys="${SAMPLE_VM_KEYS}" "${AWK_LIB}"'
        kind == "uptime" { up = $1; next }
        kind == "meminfo" { k = $1; sub(/:$/, "", k); mem = mem (mem == "" ? "" : ",") jstr(k) ":" jnum($2); next }
        kind == "vmstat" { if ($1 ~ vmkeys) vm = vm (vm == "" ? "" : ",") jstr($1) ":" jnum($2); next }
        kind == "stat" {
            if ($1 == "cpu") { cpu = "["; for (i = 2; i <= 11; i++) cpu = cpu (i > 2 ? "," : "") ((i <= NF) ? jnum($i) : "0"); cpu = cpu "]" }
            else if ($1 == "intr") intr = jnum($2)
            else if ($1 == "ctxt") ctxt = jnum($2)
            else if ($1 == "procs_running") pr = jnum($2)
            else if ($1 == "procs_blocked") pb = jnum($2)
            next
        }
        kind == "loadavg" { load = "[" jnum($1) "," jnum($2) "," jnum($3) "]"; next }
        kind ~ /^psi_/ {
            res = substr(kind, 5)
            line = "{"
            for (i = 2; i <= NF; i++) { split($i, kv, "="); line = line (i > 2 ? "," : "") jstr(kv[1]) ":" jnum(kv[2]) }
            psi[res] = psi[res] (psi[res] == "" ? "" : ",") jstr($1) ":" line "}"
            if (!(res in seen)) { seen[res] = 1; order = order (order == "" ? "" : " ") res }
            next
        }
        kind == "probe_mem" { pmem = jnum($1); next }
        kind == "probe_memstat" { if ($1 == "anon") panon = jnum($2); else if ($1 == "kernel") pkern = jnum($2); next }
        END {
            if (cpu == "") cpu = "null"
            if (intr == "") intr = "null"
            if (ctxt == "") ctxt = "null"
            if (pr == "") pr = "null"
            if (pb == "") pb = "null"
            if (load == "") load = "null"
            if (pmem == "") pmem = "null"
            if (panon == "") panon = "null"
            if (pkern == "") pkern = "null"
            printf "{\"type\":\"sample\",\"i\":%s,\"uptime\":%s,\"meminfo\":{%s},\"vmstat\":{%s},\"stat\":{\"cpu\":%s,\"intr\":%s,\"ctxt\":%s,\"procs_running\":%s,\"procs_blocked\":%s},\"loadavg\":%s,\"pressure\":{", jnum(idx), jnum(up), mem, vm, cpu, intr, ctxt, pr, pb, load
            n = split(order, rs, " ")
            for (i = 1; i <= n; i++) printf "%s%s:{%s}", (i > 1 ? "," : ""), jstr(rs[i]), psi[rs[i]]
            printf "},\"probe\":{\"memory_current\":%s,\"anon\":%s,\"kernel\":%s}}\n", pmem, panon, pkern
        }' "$@" >&3
}

# Memory-management settings that change what "used" means. They are
# recorded, never changed: a system must not "win" by turning THP off.
emit_mm_facts() {
    thp="${SYS}/kernel/mm/transparent_hugepage"
    {
        for f in enabled defrag shmem_enabled khugepaged/defrag khugepaged/pages_to_scan khugepaged/scan_sleep_millisecs; do
            [ -r "${thp}/${f}" ] && printf 'thp_%s=%s\n' "$(printf '%s' "${f}" | tr '/' '_')" "$(cat "${thp}/${f}")"
        done
        for d in "${thp}"/hugepages-*; do
            [ -r "${d}/enabled" ] && printf 'mthp_%s=%s\n' "${d##*/}" "$(cat "${d}/enabled")"
        done
        for k in min_free_kbytes watermark_scale_factor watermark_boost_factor swappiness vfs_cache_pressure overcommit_memory page-cluster; do
            [ -r "${PROC}/sys/vm/${k}" ] && printf 'vm_%s=%s\n' "${k}" "$(cat "${PROC}/sys/vm/${k}")"
        done
        [ -r "${SYS}/module/zswap/parameters/enabled" ] \
            && printf 'zswap_enabled=%s\n' "$(cat "${SYS}/module/zswap/parameters/enabled")"
        for z in "${SYS}"/block/zram*; do
            [ -d "${z}" ] || continue
            printf 'zram_%s_disksize=%s\n' "${z##*/}" "$(cat "${z}/disksize" 2>/dev/null)"
            printf 'zram_%s_algorithm=%s\n' "${z##*/}" "$(sed -n 's/.*\[\([^]]*\)\].*/\1/p' "${z}/comp_algorithm" 2>/dev/null | head -n 1)"
            printf 'zram_%s_mm_stat=%s\n' "${z##*/}" "$(cat "${z}/mm_stat" 2>/dev/null)"
        done
        awk 'NR > 1 {printf "swap_%s=%s %s %s %s\n", NR - 1, $1, $2, $3, $5}' "${PROC}/swaps" 2>/dev/null
        printf 'pagesize=%s\n' "$(getconf PAGESIZE 2>/dev/null || getconf PAGE_SIZE 2>/dev/null)"
        # The kernel's own reserve, zone by zone, as calculate_totalreserve_pages
        # computes it: the largest lowmem_reserve plus the high watermark
        # (without any temporary boost), capped at the zone's managed pages.
        # MemAvailable subtracts this, and THP raises it through min_free_kbytes.
        [ -r "${PROC}/zoneinfo" ] && awk '
            function flush() {
                if (!inzone) return
                reserve = protmax + (high - boost)
                if (reserve > managed) reserve = managed
                if (reserve < 0) reserve = 0
                total += reserve; sumlow += low; summin += min; sumhigh += high; zones++
            }
            /^Node [0-9]+, zone/ { flush(); inzone = 1; high = low = min = boost = managed = protmax = 0; next }
            $1 == "min" && NF == 2 { min = $2 }
            $1 == "low" && NF == 2 { low = $2 }
            $1 == "high" && NF == 2 { high = $2 }
            $1 == "boost" && NF == 2 { boost = $2 }
            $1 == "managed" && NF == 2 { managed = $2 }
            $1 == "protection:" {
                line = $0; gsub(/[^0-9 ]/, " ", line)
                n = split(line, v, " ")
                for (i = 1; i <= n; i++) if (v[i] + 0 > protmax) protmax = v[i] + 0
            }
            END {
                flush()
                if (zones) printf "zone_totalreserve_pages=%.0f\nzone_wmark_min_pages=%.0f\nzone_wmark_low_pages=%.0f\nzone_wmark_high_pages=%.0f\nzone_count=%d\n", total, summin, sumlow, sumhigh, zones
            }' "${PROC}/zoneinfo"
    } | awk -v phase="$1" -v up="$(uptime_now)" "${AWK_LIB}"'
        BEGIN { printf "{\"type\":\"mm\",\"phase\":%s,\"uptime\":%s", jstr(phase), jnum(up) }
        {
            k = $0; sub(/=.*/, "", k)
            v = $0; sub(/^[^=]*=/, "", v)
            printf ",%s:%s", jstr(k), jstr(v)
        }
        END { printf "}\n" }' >&3
}

emit_facts() {
    os_id="$(awk -F= '$1 == "ID" {gsub(/"/, "", $2); print $2}' "${R}/etc/os-release" 2>/dev/null)"
    os_version="$(awk -F= '$1 == "VERSION_ID" || $1 == "BUILD_ID" {gsub(/"/, "", $2); print $2; exit}' "${R}/etc/os-release" 2>/dev/null)"
    os_pretty="$(awk -F= '$1 == "PRETTY_NAME" {gsub(/"/, "", $2); print $2}' "${R}/etc/os-release" 2>/dev/null)"
    packages=unknown
    package_manager=unknown
    if command -v dpkg-query >/dev/null 2>&1; then
        package_manager=dpkg
        packages="$(dpkg-query -W -f '${Package}\n' 2>/dev/null | wc -l | tr -d ' ')"
    elif command -v pacman >/dev/null 2>&1; then
        package_manager=pacman
        packages="$(pacman -Qq 2>/dev/null | wc -l | tr -d ' ')"
    elif command -v rpm >/dev/null 2>&1; then
        package_manager=rpm
        packages="$(rpm -qa 2>/dev/null | wc -l | tr -d ' ')"
    fi
    cpu_model="$(awk -F': ' '/^model name/ {print $2; exit}' "${PROC}/cpuinfo" 2>/dev/null)"
    ncpu="$(awk '/^cpu[0-9]+ / {n++} END {print n + 0}' "${PROC}/stat")"
    emit_kv facts \
        probe_version="${PROBE_VERSION}" \
        run_id="${RUN_ID}" \
        canonical="${CANONICAL}" \
        settle_secs="${SETTLE_SECS}" \
        samples="${SAMPLE_COUNT}" \
        interval_secs="${SAMPLE_INTERVAL}" \
        config_source="${CONFIG_SOURCE}" \
        fw_cfg_module_loaded="${FW_CFG_LOADED}" \
        injection="$([ -n "${CREDENTIALS_DIRECTORY:-}" ] && [ -r "${CREDENTIALS_DIRECTORY}/bench.probe" ] && echo credential || echo offline)" \
        probe_cgroup="${PROBE_CGROUP}" \
        kernel="$(uname -r 2>/dev/null)" \
        machine="$(uname -m 2>/dev/null)" \
        os_id="${os_id}" \
        os_version="${os_version}" \
        os_pretty="${os_pretty}" \
        packages="${packages}" \
        package_manager="${package_manager}" \
        cpu_model="${cpu_model}" \
        ncpu="${ncpu}" \
        clk_tck="$(getconf CLK_TCK 2>/dev/null || echo 100)" \
        cmdline="$(cat "${PROC}/cmdline" 2>/dev/null)" \
        lockdown="$(cat "${SYS}/kernel/security/lockdown" 2>/dev/null)" \
        lsm="$(cat "${SYS}/kernel/security/lsm" 2>/dev/null)" \
        kptr_restrict="$(cat "${PROC}/sys/kernel/kptr_restrict" 2>/dev/null)" \
        dmesg_restrict="$(cat "${PROC}/sys/kernel/dmesg_restrict" 2>/dev/null)" \
        ptrace_scope="$(cat "${PROC}/sys/kernel/yama/ptrace_scope" 2>/dev/null)" \
        unprivileged_bpf_disabled="$(cat "${PROC}/sys/kernel/unprivileged_bpf_disabled" 2>/dev/null)" \
        unprivileged_userns_clone="$(cat "${PROC}/sys/kernel/unprivileged_userns_clone" 2>/dev/null)" \
        perf_event_paranoid="$(cat "${PROC}/sys/kernel/perf_event_paranoid" 2>/dev/null)" \
        kexec_load_disabled="$(cat "${PROC}/sys/kernel/kexec_load_disabled" 2>/dev/null)" \
        randomize_va_space="$(cat "${PROC}/sys/kernel/randomize_va_space" 2>/dev/null)" \
        bpf_jit_harden="$(cat "${PROC}/sys/net/core/bpf_jit_harden" 2>/dev/null)" \
        protected_symlinks="$(cat "${PROC}/sys/fs/protected_symlinks" 2>/dev/null)" \
        protected_hardlinks="$(cat "${PROC}/sys/fs/protected_hardlinks" 2>/dev/null)"
}

emit_processes() {
    for d in "${PROC}"/[0-9]*; do
        [ -d "${d}" ] && printf '%s\n' "${d}"
    done | awk -v up="$(uptime_now)" "${AWK_LIB}"'
        BEGIN { printf "{\"type\":\"processes\",\"uptime\":%s,\"list\":[", jnum(up) }
        {
            d = $0
            pid = d; sub(/.*\//, "", pid)
            pss = ""; anon = "0"; file = "0"; shm = "0"; rss = "0"; swp = "0"; lck = "0"
            f = d "/smaps_rollup"
            while ((getline line < f) > 0) {
                split(line, a, /[ \t]+/)
                if (a[1] == "Pss:") pss = a[2]
                else if (a[1] == "Pss_Anon:") anon = a[2]
                else if (a[1] == "Pss_File:") file = a[2]
                else if (a[1] == "Pss_Shmem:") shm = a[2]
                else if (a[1] == "Rss:") rss = a[2]
                else if (a[1] == "SwapPss:") swp = a[2]
                else if (a[1] == "Locked:") lck = a[2]
            }
            close(f)
            if (pss == "") next
            comm = readline1(d "/comm")
            cg = readline1(d "/cgroup"); sub(/^0::/, "", cg)
            uid = ""
            f = d "/status"
            while ((getline line < f) > 0) if (line ~ /^Uid:/) { split(line, a, /[ \t]+/); uid = a[2]; break }
            close(f)
            printf "%s{\"pid\":%s,\"comm\":%s,\"uid\":%s,\"cgroup\":%s,\"pss\":%s,\"pss_anon\":%s,\"pss_file\":%s,\"pss_shmem\":%s,\"rss\":%s,\"swap_pss\":%s,\"locked\":%s}", sep, jnum(pid), jstr(comm), jnum(uid), jstr(cg), jnum(pss), jnum(anon), jnum(file), jnum(shm), jnum(rss), jnum(swp), jnum(lck)
            sep = ","
        }
        END { printf "]}\n" }' >&3
}

# Listening sockets from the kernel's own tables, with the owning process
# joined by socket inode. ss is used as well when the image ships it, but
# the image need not (Punar keeps iproute2 out of the base).
emit_sockets() {
    for f in tcp tcp6 udp udp6 raw raw6; do
        file_blob "proc_net_${f}" "${PROC}/net/${f}"
    done
    # ls -l over every fd directory is one process for the whole table; the
    # names parsed are the kernel's own "socket:[inode]" link targets.
    # shellcheck disable=SC2012
    ls -l "${PROC}"/[0-9]*/fd/ 2>/dev/null | awk -v proc="${PROC}" "${AWK_LIB}"'
        /^\/.*:$/ { pid = $0; sub(/^.*\/proc\//, "", pid); sub(/\/fd\/?:$/, "", pid); next }
        /socket:\[/ {
            ino = $NF; gsub(/[^0-9]/, "", ino)
            key = ino " " pid
            if (key in seen) next
            seen[key] = 1
            comm = readline1(proc "/" pid "/comm")
            print ino, pid, (comm == "" ? "?" : comm)
        }' > "${BLOB_TMP}/socket-owners.$$"
    blob socket_owners cat "${BLOB_TMP}/socket-owners.$$"
    rm -f -- "${BLOB_TMP}/socket-owners.$$"
    if command -v ss >/dev/null 2>&1; then
        blob ss_tulpn ss -H -tulpn
    fi
}

emit_privileged_files() {
    # setuid/setgid files on the root and /usr filesystems (the OS itself);
    # /home and /var hold people's files, not the distribution's.
    find "${R}/" "${R}/usr" -xdev -type f \( -perm -4000 -o -perm -2000 \) \
        -exec stat -c '%a %U %n' {} + 2>/dev/null | sort -u > "${BLOB_TMP}/suid.$$"
    blob setid_files cat "${BLOB_TMP}/suid.$$"
    rm -f -- "${BLOB_TMP}/suid.$$"
    if command -v getcap >/dev/null 2>&1; then
        blob file_capabilities bounded 120 getcap -r "${R}/usr"
    else
        emit_kv absent name=file_capabilities reason="getcap not installed"
    fi
}

emit_systemd() {
    blob systemd_analyze_time bounded 60 systemd-analyze time --no-pager
    blob systemd_analyze_blame bounded 60 systemd-analyze blame --no-pager
    blob systemd_analyze_critical_chain bounded 60 systemd-analyze critical-chain --no-pager
    blob systemd_analyze_security bounded 300 systemd-analyze security --no-pager
    blob systemd_manager_timestamps bounded 30 systemctl show \
        -p FirmwareTimestampMonotonic -p LoaderTimestampMonotonic \
        -p KernelTimestampMonotonic -p InitRDTimestampMonotonic \
        -p UserspaceTimestampMonotonic -p FinishTimestampMonotonic
    blob graphical_target bounded 30 systemctl show graphical.target -p ActiveEnterTimestampMonotonic
    blob units_enabled bounded 60 systemctl list-unit-files --state=enabled --no-legend --no-pager
    blob services_running bounded 60 systemctl list-units --type=service --state=running --no-legend --no-pager
    if [ -n "${SESSION_ID:-}" ] && command -v loginctl >/dev/null 2>&1; then
        blob session_properties bounded 30 loginctl show-session "${SESSION_ID}"
    fi
    if command -v nft >/dev/null 2>&1; then
        blob nft_ruleset bounded 60 nft list ruleset
    fi
    blob df bounded 60 df -kP -x tmpfs -x devtmpfs -x efivarfs
    # The operating system's own files, whatever the disk layout: the
    # logical (apparent) size of /usr and /opt, one filesystem each, so
    # compression, subvolumes, snapshots, package caches, logs and home
    # directories count on no system. `df /` would measure the whole btrfs
    # filesystem on one system and one A/B root slot on another.
    os_trees=""
    for tree in "${R}/usr" "${R}/opt"; do
        [ -d "${tree}" ] && os_trees="${os_trees} ${tree}"
    done
    if du -sk --apparent-size /dev/null >/dev/null 2>&1; then
        # shellcheck disable=SC2086 # one word per existing tree
        blob os_files_apparent bounded 300 du -skx --apparent-size ${os_trees}
    else
        # shellcheck disable=SC2086
        blob os_files_allocated bounded 300 du -skx ${os_trees}
    fi
}

# ---- main -------------------------------------------------------------------
PROBE_CGROUP="$(awk -F: '$1 == "0" {print $3; exit}' "${PROC}/self/cgroup" 2>/dev/null)"
PROBE_CG_DIR=""
if [ -n "${PROBE_CGROUP}" ] && [ -d "${CG}${PROBE_CGROUP}" ]; then
    PROBE_CG_DIR="${CG}${PROBE_CGROUP}"
fi

emit_kv probe_start probe_version="${PROBE_VERSION}" run_id="${RUN_ID}" canonical="${CANONICAL}"

if ! wait_for_session; then
    emit_kv error reason=session-not-ready timeout_secs="${SESSION_TIMEOUT}"
    emit_kv "done" status=failed
    exit 1
fi
# shellcheck disable=SC2086 # the session line is space-separated words
set -- ${SESSION_LINE}
SESSION_ID="$6"
SESSION_UID="$4"
SESSION_USER="$5"
# shellcheck disable=SC2086
set -- ${COMPOSITOR}
compositor_start="$3"
# shellcheck disable=SC2086
set -- ${SHELL_PROC}
emit_kv session_ready session="${SESSION_ID}" uid="${SESSION_UID}" user="${SESSION_USER}" \
    session_type="$(printf '%s\n' "${SESSION_LINE}" | awk '{print $3}')" \
    compositor=Hyprland compositor_start_ticks="${compositor_start}" \
    shell="$1" shell_start_ticks="$3"

emit_facts
emit_mm_facts session
emit_devices

emit_kv settle_start secs="${SETTLE_SECS}"
test_tick settle
pause "${SETTLE_SECS}"

emit_kv window_start samples="${SAMPLE_COUNT}" interval_secs="${SAMPLE_INTERVAL}"
emit_counters start
emit_cgroups start
n=0
while [ "${n}" -lt "${SAMPLE_COUNT}" ]; do
    emit_sample "${n}"
    n=$((n + 1))
    test_tick sample
    # Sleep after the last sample too: 30 samples at 10 s describe the whole
    # 300 s window (idle-ram.sh does the same).
    pause "${SAMPLE_INTERVAL}"
done
emit_counters end
emit_cgroups end
emit_kv window_end samples="${SAMPLE_COUNT}"

# After the window, so none of this perturbs it.
emit_mm_facts end
emit_processes
emit_sockets
emit_privileged_files
emit_systemd
emit_kv post_done

if [ "${WORKLOAD}" = yes ]; then
    if [ -r "${WORKLOAD_SCRIPT}" ]; then
        # Sourced, so it reuses the emitters above; every heavy process it
        # starts runs in the session user's own slice, not in this cgroup.
        # shellcheck source=/dev/null
        . "${WORKLOAD_SCRIPT}"
        run_workload
    else
        emit_kv workload status=skipped reason="workload script not injected"
    fi
fi

emit_cgroups final
emit_kv "done" status=ok
exit 0
