#!/usr/bin/env bash
# The benchmark probe against fixture /proc, /sys and /run trees.
#
# Runs tools/bench/bench-probe.sh unchanged under the two shell/awk pairs the
# measured systems ship (dash + mawk on Punar's Debian base, bash + gawk on
# Arch and Omarchy), with every /proc and /sys path under a fixture root
# (tests/performance/bench_fixture.py) whose counters move by a fixed step per
# sample. Then it checks that every line on the export stream is JSON and
# that tools/bench/bench_parse.py derives the exact expected figures: idle
# RAM with the probe subtracted, CPU and steal, wakeups, the write split
# (device = top-level cgroups + kernel/filesystem remainder, zram excluded,
# nothing counted twice), THP and min_free_kbytes, listeners with owners,
# setuid files, systemd-analyze parsing and boot timestamps.
#
# A canonical run (600 s settle, 30 samples at 10 s, with sleep stubbed out)
# and a short fw_cfg-configured run, which must be labelled non-canonical.
# Needs python3; the gawk variant is skipped with a notice if gawk is absent.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE="${REPO_ROOT}/tests/performance/bench_fixture.py"
PROBE="${REPO_ROOT}/tools/bench/bench-probe.sh"
PARSE="${REPO_ROOT}/tools/bench/bench_parse.py"

fail() {
    echo "bench-probe-test: FAIL: $*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail "python3 is required"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

STUBS="${TMP}/stubs"
mkdir -p "${STUBS}"
cat > "${STUBS}/sleep" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "${STUBS}/systemd-analyze" <<'EOF'
#!/bin/sh
case "$1" in
    time)
        echo "Startup finished in 1.500s (kernel) + 2.000s (initrd) + 5.000s (userspace) = 8.500s"
        echo "graphical.target reached after 4.500s in userspace."
        ;;
    blame)
        printf '          2.000s systemd-cryptsetup@root.service\n          1min 1.200s NetworkManager-wait-online.service\n          350ms systemd-journald.service\n'
        ;;
    critical-chain) echo "graphical.target @4.500s" ;;
    security)
        printf 'UNIT                 EXPOSURE PREDICATE HAPPY\nsshd.service              9.6 UNSAFE    :-{\ncups.service              6.2 MEDIUM    :-|\nbench-probe.service       4.1 OK        :-)\n'
        ;;
esac
EOF
cat > "${STUBS}/systemctl" <<'EOF'
#!/bin/sh
case "$1" in
    show)
        if [ "$2" = graphical.target ]; then
            echo "ActiveEnterTimestampMonotonic=8000000"
        else
            printf 'FirmwareTimestampMonotonic=0\nLoaderTimestampMonotonic=0\nKernelTimestampMonotonic=0\nInitRDTimestampMonotonic=1500000\nUserspaceTimestampMonotonic=3500000\nFinishTimestampMonotonic=8500000\n'
        fi
        ;;
    list-unit-files) printf 'sshd.service enabled enabled\ncups.service enabled enabled\n' ;;
    list-units) printf 'sshd.service loaded active running OpenSSH server\n' ;;
esac
EOF
cat > "${STUBS}/loginctl" <<'EOF'
#!/bin/sh
[ "$1" = show-session ] && printf 'Id=%s\nTimestampMonotonic=15000000\nType=wayland\n' "$2"
exit 0
EOF
cat > "${STUBS}/nft" <<'EOF'
#!/bin/sh
printf 'table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n'
EOF
cat > "${STUBS}/dpkg-query" <<'EOF'
#!/bin/sh
printf 'base-files\nlibc6\nsystemd\n'
EOF
cat > "${STUBS}/tick" <<EOF
#!/bin/sh
exec python3 "${FIXTURE}" tick "\${BENCH_ROOT}" "\$1"
EOF
chmod 0755 "${STUBS}"/*

# run_variant NAME SHELL AWK SAMPLES [CONFIG]
run_variant() {
    name=$1
    shell=$2
    awk_binary=$3
    samples=$4
    config=${5:-}
    dir="${TMP}/${name}"
    root="${dir}/root"
    mkdir -p "${dir}/bin"
    python3 "${FIXTURE}" build "${root}"
    ln -s "$(command -v "${awk_binary}")" "${dir}/bin/awk"
    if [ -n "${config}" ]; then
        mkdir -p "${root}/sys/firmware/qemu_fw_cfg/by_name/opt/bench/config"
        printf '%s\n' "${config}" > "${root}/sys/firmware/qemu_fw_cfg/by_name/opt/bench/config/raw"
    fi
    : > "${dir}/export.jsonl"
    if ! BENCH_ROOT="${root}" BENCH_EXPORT="${dir}/export.jsonl" BENCH_TEST_TICK="${STUBS}/tick" \
            PATH="${dir}/bin:${STUBS}:${PATH}" "${shell}" "${PROBE}" 2> "${dir}/stderr.log"; then
        cat "${dir}/stderr.log" >&2
        fail "${name}: the probe exited non-zero"
    fi
    python3 - "${dir}/export.jsonl" <<'PY' || fail "${name}: the export stream is not all JSON"
import json, sys
kinds = []
for number, line in enumerate(open(sys.argv[1], encoding="utf-8"), 1):
    try:
        kinds.append(json.loads(line)["type"])
    except (ValueError, KeyError) as error:
        sys.exit(f"line {number}: {error}: {line[:200]!r}")
for wanted in ("probe_start", "greeter_ready", "session_ready", "facts", "mm", "devices",
               "window_start", "counters", "cgroups", "sample", "window_end", "processes",
               "blob", "post_done", "done"):
    if wanted not in kinds:
        sys.exit(f"no {wanted} record")
if kinds.index("greeter_ready") > kinds.index("session_ready"):
    sys.exit("greeter_ready must precede session_ready")
PY
    python3 "${PARSE}" "${dir}/export.jsonl" --out "${dir}/result.json"
    python3 "${FIXTURE}" check "${dir}/result.json" "${samples}"
    echo "ok   ${name}"
}

run_variant dash-mawk-canonical dash mawk 30
canonical="$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print(r["probe"]["canonical"], r["validity"]["valid_for_claims"], r["probe"]["config_source"])' "${TMP}/dash-mawk-canonical/result.json")"
[ "${canonical}" = "True True defaults" ] \
    || fail "a default run must be canonical and valid for claims (got: ${canonical})"

run_variant dash-mawk-short dash mawk 3 "$(printf 'settle_secs=0\nsamples=3\ninterval=0\nrun_id=fixture-1')"
short="$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print(r["probe"]["canonical"], r["validity"]["valid_for_claims"], r["probe"]["config_source"])' "${TMP}/dash-mawk-short/result.json")"
[ "${short}" = "False False fw_cfg" ] \
    || fail "an overridden run must be non-canonical and never valid for claims (got: ${short})"

if command -v gawk >/dev/null 2>&1 && command -v bash >/dev/null 2>&1; then
    run_variant bash-gawk-canonical bash gawk 30
else
    echo "note bash + gawk variant skipped: gawk not installed"
fi

echo "PUNAR_BENCH_PROBE_TEST_OK"
