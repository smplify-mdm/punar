# shellcheck shell=sh
# Memory-pressure workload (tools/bench/README.md, "Workload lane").
#
# Sourced by bench-probe.sh after the idle window, so it reuses the probe's
# emitters and never overlaps a measurement. Every heavy process runs as the
# signed-in person, in their own systemd user slice (systemd-run --user
# --machine=USER@), so the probe's cgroup stays the probe's.
#
# Identical on every system: 20 local pages in the browser the system ships,
# a headless editor pass over a 50,000-line file, and a container build of a
# FROM-scratch fixture (no base image, no network) with the system's own
# container tool. It records memory pressure (PSI "full" avg10), OOM kills
# (kernel and systemd-oomd), the lowest MemAvailable, swap in use and the time
# each step took. A step whose tool is missing or cannot start is recorded as
# skipped with the reason; the lane is labelled experimental until every step
# has run on every measured system.
#
# The container step cannot be the same program everywhere (rootless podman
# on Punar, root dockerd through one sudo rule on Omarchy, whose work lands
# in system.slice), so the pressure, OOM and lowest-MemAvailable figures are
# also recorded at the moment the container step starts (before_container_*):
# the browser and editor phase is identical on every system and is what the
# report compares; the whole-workload figures are compared only between runs
# that used the same container tool.

WL_BROWSER_SETTLE_SECS="${BENCH_WL_BROWSER_SETTLE_SECS:-60}"
WL_TABS=20
WL_EDITOR_LINES=50000
WL_FIXTURE_FILES=2000
WL_STEP_TIMEOUT=600

wl_user_run() {
    # wl_user_run UNIT [--wait] -- COMMAND...: run as the session user in
    # their user manager. Prints nothing; returns the command's status with
    # --wait.
    unit=$1
    shift
    # Bounded as a whole too: a user manager that never answers must not
    # hold the run. -k: a process busy in a long computation may not act on
    # SIGTERM (Neovim queues it until its event loop runs), so KILL follows.
    timeout -k 15 $((WL_STEP_TIMEOUT + 120)) \
        systemd-run --quiet --machine="${SESSION_USER}@.host" --user --collect \
            --unit="${unit}" --property=MemoryAccounting=yes \
            --setenv=WAYLAND_DISPLAY="${WL_WAYLAND}" --setenv=XDG_SESSION_TYPE=wayland \
            "$@"
}

wl_uptime_ms() {
    awk '{printf "%.0f\n", $1 * 1000}' "${PROC}/uptime"
}

wl_meminfo() {
    awk -v k="$1:" '$1 == k {print $2; exit}' "${PROC}/meminfo"
}

wl_oom_kills() {
    awk '$1 == "oom_kill" {print $2; exit}' "${PROC}/vmstat"
}

wl_psi_full_total() {
    awk '$1 == "full" { for (i = 2; i <= NF; i++) { split($i, kv, "="); if (kv[1] == "total") print kv[2] } }' \
        "${PROC}/pressure/memory" 2>/dev/null
}

wl_summarize() {
    # wl_summarize SAMPLES [LINES]: "psi_full_max available_min_kb swap_max_kb n"
    # over the first LINES one-second samples (all of them without LINES).
    awk -v limit="${2:-0}" '
        limit > 0 && NR > limit { exit }
        NR == 1 { maxp = $1; mina = $2; maxs = $3 }
        { if ($1 + 0 > maxp + 0) maxp = $1; if ($2 + 0 < mina + 0) mina = $2; if ($3 + 0 > maxs + 0) maxs = $3; n++ }
        END { if (n == 0) print "- - - 0"; else printf "%s %s %s %d\n", maxp, mina, maxs, n }' "$1"
}

wl_oomd_kills_since() {
    if command -v journalctl >/dev/null 2>&1; then
        journalctl -u systemd-oomd.service --since "@$1" -o cat --no-pager 2>/dev/null | grep -c -i 'killed' || true
    else
        echo unknown
    fi
}

wl_generate_fixtures() {
    dir=$1
    mkdir -p "${dir}/pages" "${dir}/editor" "${dir}/container/data"
    # Twenty deterministic pages: text, a table and styling, no network.
    i=1
    while [ "${i}" -le "${WL_TABS}" ]; do
        awk -v n="${i}" 'BEGIN {
            printf "<!doctype html><html><head><meta charset=\"utf-8\"><title>Bench page %02d</title>", n
            printf "<style>body{font:15px sans-serif;margin:2em}td{border:1px solid #999;padding:2px 6px}.c%d{color:#246}</style></head><body>", n
            printf "<h1>Bench page %02d</h1>", n
            for (p = 0; p < 1200; p++) printf "<p class=\"c%d\">Paragraph %d of page %d. The quick brown fox jumps over the lazy dog while the benchmark measures memory pressure.</p>", n, p, n
            printf "<table>"
            for (r = 0; r < 400; r++) { printf "<tr>"; for (c = 0; c < 8; c++) printf "<td>%d.%d</td>", r, c; printf "</tr>" }
            printf "</table></body></html>\n"
        }' > "${dir}/pages/page$(printf '%02d' "${i}").html"
        i=$((i + 1))
    done
    awk -v lines="${WL_EDITOR_LINES}" 'BEGIN {
        for (i = 0; i < lines; i++) printf "int value_%d = %d; /* line %d of the editor fixture */\n", i, (i * 7919) % 100003, i
    }' > "${dir}/editor/big.c"
    # About 40 MB in 2,000 files, deterministic (Park-Miller: every product
    # stays below 2^53, so mawk and gawk print the same bytes).
    awk -v dir="${dir}/container/data" -v files="${WL_FIXTURE_FILES}" 'BEGIN {
        x = 12345
        for (f = 0; f < files; f++) {
            path = sprintf("%s/f%04d.txt", dir, f)
            for (l = 0; l < 256; l++) {
                x = (x * 16807) % 2147483647
                printf "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x\n", x, x + 1, x + 2, x + 3, x + 4, x + 5, x + 6, x + 7, x + 8, x + 9 > path
            }
            close(path)
        }
    }'
    printf 'FROM scratch\nCOPY data/ /data/\n' > "${dir}/container/Containerfile"
}

run_workload() {
    wl_start_ms="$(wl_uptime_ms)"
    WL_DIR="${R}/var/tmp/bench-workload"
    WL_WAYLAND=""
    for socket in "${RUN}/user/${SESSION_UID}"/wayland-*; do
        case "${socket}" in *.lock) continue ;; esac
        [ -S "${socket}" ] && WL_WAYLAND="${socket##*/}" && break
    done
    emit_kv workload_start user="${SESSION_USER}" wayland="${WL_WAYLAND:-none}" \
        browser_settle_secs="${WL_BROWSER_SETTLE_SECS}" tabs="${WL_TABS}" \
        editor_lines="${WL_EDITOR_LINES}" fixture_files="${WL_FIXTURE_FILES}"

    rm -rf -- "${WL_DIR}"
    emit_kv workload_step step=fixtures
    wl_generate_fixtures "${WL_DIR}"
    chown -R "${SESSION_UID}" "${WL_DIR}" 2>/dev/null

    oom_start="$(wl_oom_kills)"
    psi_start="$(wl_psi_full_total)"
    # One-second sampler: PSI full avg10, MemAvailable and swap in use.
    samples="${BLOB_TMP}/workload-samples.$$"
    : > "${samples}"
    (
        while :; do
            awk '
                FILENAME ~ /pressure/ && $1 == "full" { split($2, kv, "="); full = kv[2] }
                FILENAME ~ /meminfo/ && $1 == "MemAvailable:" { avail = $2 }
                FILENAME ~ /meminfo/ && $1 == "SwapTotal:" { st = $2 }
                FILENAME ~ /meminfo/ && $1 == "SwapFree:" { sf = $2 }
                END { printf "%s %s %s\n", (full == "" ? "0" : full), avail, st - sf }
            ' "${PROC}/pressure/memory" "${PROC}/meminfo" 2>/dev/null >> "${samples}"
            sleep 1
        done
    ) &
    sampler=$!
    oomd_since="$(date +%s)"

    # Step 1: the browser with twenty local pages, left open for the rest.
    emit_kv workload_step step=browser
    browser_cmd=""
    for candidate in chromium chromium-browser google-chrome-stable; do
        if command -v "${candidate}" >/dev/null 2>&1; then
            browser_cmd="${candidate}"
            break
        fi
    done
    browser_status=skipped
    browser_reason="no chromium on this system"
    if [ -n "${browser_cmd}" ] && [ -n "${WL_WAYLAND}" ]; then
        set --
        i=1
        while [ "${i}" -le "${WL_TABS}" ]; do
            set -- "$@" "file://${WL_DIR#"${R}"}/pages/page$(printf '%02d' "${i}").html"
            i=$((i + 1))
        done
        if wl_user_run bench-wl-browser -- "${browser_cmd}" --ozone-platform=wayland \
                --user-data-dir="${WL_DIR#"${R}"}/browser-profile" --no-first-run \
                --no-default-browser-check --disable-sync --password-store=basic \
                --new-window "$@"; then
            sleep "${WL_BROWSER_SETTLE_SECS}"
            if systemctl --machine="${SESSION_USER}@.host" --user --quiet is-active bench-wl-browser.service; then
                browser_status=ok
                browser_reason=""
            else
                browser_status=failed
                browser_reason="the browser exited during the settle"
            fi
        else
            browser_status=failed
            browser_reason="systemd-run could not start the browser"
        fi
    elif [ -n "${browser_cmd}" ]; then
        browser_reason="no Wayland socket for the session"
    fi

    # Step 2: a batch-mode editor pass over 50,000 lines: substitute across
    # the file, sort it, delete a tenth of it, write it. Ex mode never stops
    # at a prompt; the step is bounded all the same. (Reindenting with = was
    # tried and dropped: Vim's C indenter is superlinear on a file of 50,000
    # top-level lines, which measures the algorithm, not the system.)
    emit_kv workload_step step=editor
    editor_status=skipped
    editor_reason="no nvim on this system"
    editor_ms=""
    if command -v nvim >/dev/null 2>&1; then
        t0="$(wl_uptime_ms)"
        if wl_user_run bench-wl-editor --wait --pipe -- timeout -k 15 "${WL_STEP_TIMEOUT}" \
                nvim -n -i NONE -u NONE -es -c 'silent %s/value/VALUE/ge' \
                -c 'silent sort' -c 'silent g/0 of the/d' -c 'wq' \
                "${WL_DIR#"${R}"}/editor/big.c" </dev/null >/dev/null 2>&1; then
            editor_status=ok
            editor_reason=""
        else
            editor_status=failed
            editor_reason="nvim exited non-zero"
        fi
        editor_ms=$(($(wl_uptime_ms) - t0))
    fi

    # The browser and editor phase ends here; it is the same on every system.
    before_container_ms=$(($(wl_uptime_ms) - wl_start_ms))
    before_lines="$(wc -l < "${samples}" | tr -d ' ')"
    before_oom="$(wl_oom_kills)"
    before_psi="$(wl_psi_full_total)"
    before_oomd="$(wl_oomd_kills_since "${oomd_since}")"

    # Step 3: a container build of the fixture, with the system's own tool.
    emit_kv workload_step step=container
    container_status=skipped
    container_reason="no podman or docker on this system"
    container_tool=""
    container_ms=""
    if command -v podman >/dev/null 2>&1; then
        container_tool=podman
        t0="$(wl_uptime_ms)"
        if wl_user_run bench-wl-container --wait --pipe -- timeout -k 15 "${WL_STEP_TIMEOUT}" \
                podman build --network=none --pull=never -t localhost/bench-fixture:latest \
                -f "${WL_DIR#"${R}"}/container/Containerfile" "${WL_DIR#"${R}"}/container" \
                </dev/null >/dev/null 2>&1; then
            container_status=ok
            container_reason=""
        else
            container_status=failed
            container_reason="rootless podman build failed"
        fi
        container_ms=$(($(wl_uptime_ms) - t0))
        wl_user_run bench-wl-container-clean --wait --pipe -- timeout -k 15 120 \
            podman rmi -f localhost/bench-fixture:latest </dev/null >/dev/null 2>&1
    elif command -v docker >/dev/null 2>&1 && [ -d "${R}/opt/bench/fixture" ]; then
        # Stock Omarchy gives the person no docker group; the harness adds one
        # sudo rule for exactly this command, removed with the disk
        # (tools/bench/omarchy/restore-stock.sh records it as a deviation).
        container_tool=docker-sudo-rule
        cp -R "${WL_DIR}/container/." "${R}/opt/bench/fixture/"
        t0="$(wl_uptime_ms)"
        if wl_user_run bench-wl-container --wait --pipe -- timeout -k 15 "${WL_STEP_TIMEOUT}" \
                sudo -n /usr/bin/docker build -t bench-fixture /opt/bench/fixture \
                </dev/null >/dev/null 2>&1; then
            container_status=ok
            container_reason=""
        else
            container_status=failed
            container_reason="docker build through the scoped sudo rule failed"
        fi
        container_ms=$(($(wl_uptime_ms) - t0))
    fi

    sleep 10
    browser_peak=""
    browser_cg="${CG}/user.slice/user-${SESSION_UID}.slice/user@${SESSION_UID}.service/app.slice/bench-wl-browser.service"
    [ -r "${browser_cg}/memory.peak" ] && browser_peak="$(cat "${browser_cg}/memory.peak")"
    if [ "${browser_status}" = ok ]; then
        systemctl --machine="${SESSION_USER}@.host" --user stop bench-wl-browser.service >/dev/null 2>&1
    fi
    wl_end_ms="$(wl_uptime_ms)"
    kill "${sampler}" 2>/dev/null
    wait "${sampler}" 2>/dev/null

    oom_end="$(wl_oom_kills)"
    psi_end="$(wl_psi_full_total)"
    oomd_kills="$(wl_oomd_kills_since "${oomd_since}")"
    before="$(wl_summarize "${samples}" "${before_lines:-0}")"
    if [ "${before_lines:-0}" -eq 0 ]; then
        before="- - - 0"
    fi
    summary="$(wl_summarize "${samples}")"
    # shellcheck disable=SC2086 # four space-separated numbers
    set -- ${before:-"- - - 0"}
    before_psi_max=$1 before_avail_min=$2 before_swap_max=$3 before_n=$4
    # shellcheck disable=SC2086
    set -- ${summary:-"- - - 0"}
    rm -f -- "${samples}"
    rm -rf -- "${WL_DIR}"

    emit_kv workload status=done experimental=yes \
        completion_ms=$((wl_end_ms - wl_start_ms)) \
        browser_status="${browser_status}" browser_reason="${browser_reason}" \
        browser_cmd="${browser_cmd}" browser_peak_bytes="${browser_peak}" \
        editor_status="${editor_status}" editor_reason="${editor_reason}" editor_ms="${editor_ms}" \
        container_status="${container_status}" container_reason="${container_reason}" \
        container_tool="${container_tool}" container_ms="${container_ms}" \
        psi_full_avg10_max="$1" mem_available_min_kb="$2" swap_used_max_kb="$3" pressure_samples="$4" \
        psi_full_total_start_us="${psi_start}" psi_full_total_end_us="${psi_end}" \
        oom_kills_kernel="$((${oom_end:-0} - ${oom_start:-0}))" oom_kills_oomd="${oomd_kills}" \
        before_container_ms="${before_container_ms}" before_container_psi_full_avg10_max="${before_psi_max}" \
        before_container_mem_available_min_kb="${before_avail_min}" \
        before_container_swap_used_max_kb="${before_swap_max}" before_container_samples="${before_n}" \
        before_container_psi_full_total_end_us="${before_psi}" \
        before_container_oom_kills_kernel="$((${before_oom:-0} - ${oom_start:-0}))" \
        before_container_oom_kills_oomd="${before_oomd}"
}
