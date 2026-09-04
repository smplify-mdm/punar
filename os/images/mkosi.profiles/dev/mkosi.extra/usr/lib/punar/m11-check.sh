#!/bin/sh
# M11 in-VM exercise: the upstream Chromium boundary, root-owned web-app
# inventory, rebuildable user launchers, browser contexts, sandbox evidence,
# the graphical window, and clean uninstall. Runs as root after M10 and before
# M12; every user action runs through the live session as the console user.
#
# This script always exits 0. The hard verdict is the final line in
# /run/punar/m11-report.txt, parsed by tools/boot-test.sh.

set -u

RUN_DIR=/run/punar
REPORT="${RUN_DIR}/m11-report.txt"
CTL=/usr/bin/punarctl
PUNAR_HOME=/home/punar
PUNAR_UID="$(id -u punar 2>/dev/null || echo 1000)"
PUNAR_RUN="/run/user/${PUNAR_UID}"
APPS_ROOT="/var/lib/punar/web-apps/${PUNAR_UID}/apps"
CONTEXT_ROOT="${PUNAR_HOME}/.local/share/punar/browser/contexts"
DESKTOP_ROOT="${PUNAR_HOME}/.local/share/applications"
ICON_ROOT="${PUNAR_HOME}/.local/share/icons/hicolor/256x256/apps"
DENYLIST=/usr/share/punar/browser/forbidden-tokens.txt
MANAGED_POLICY=/etc/chromium/policies/managed/punar-managed.json
MOCK=punar-mock-smplify.service
MOCK_SOCK=/run/punar-mock-smplify/api.sock
TIMER=punard-reconcile.timer
DRIFT_BUDGET_SECS=375
AUDIT_LOG=/var/log/punar/audit.jsonl
NOTES_URL=file:///usr/share/punar/fixtures/webapps/notes/index.html
FIXTURE_MANIFEST=/usr/share/punar/fixtures/webapps/notes/punar-webapp.json
FAILED=0
NOTES_JOB=""
FIXTURE_JOB=""
BROWSER_JOB=""

: > "${REPORT}"

note() { printf '%s\n' "$*" >> "${REPORT}"; }

check_eq() {
    if [ "$2" = "$3" ]; then
        note "ok   $1 = $3"
    else
        note "FAIL $1 (expected '$2', got '$3')"
        FAILED=1
    fi
}

check_true() {
    if [ "$2" -eq 0 ]; then
        note "ok   $1"
    else
        note "FAIL $1 (status $2)"
        FAILED=1
    fi
}

jq_check() {
    if jq -e "$3" "$2" >/dev/null 2>&1; then
        note "ok   $1"
    else
        note "FAIL $1 (jq filter: $3; input: $(head -c 280 "$2" 2>/dev/null || echo absent))"
        FAILED=1
    fi
}

grep_row() {
    if grep -qiF "$3" "$2" 2>/dev/null; then
        note "ok   $1"
    else
        note "FAIL $1 (missing '$3'; input: $(head -c 280 "$2" 2>/dev/null || echo absent))"
        FAILED=1
    fi
}

HIS=""
for dir in "${PUNAR_RUN}"/hypr/*/; do
    [ -d "${dir}" ] || continue
    HIS="$(basename "${dir}")"
    break
done
WL_DISPLAY=""
for socket in "${PUNAR_RUN}"/wayland-*; do
    case "${socket}" in
        *.lock) ;;
        *) [ -S "${socket}" ] && WL_DISPLAY="$(basename "${socket}")" && break ;;
    esac
done

as_punar() {
    runuser -u punar -- env \
        "HOME=${PUNAR_HOME}" \
        "XDG_RUNTIME_DIR=${PUNAR_RUN}" \
        "DBUS_SESSION_BUS_ADDRESS=unix:path=${PUNAR_RUN}/bus" \
        "WAYLAND_DISPLAY=${WL_DISPLAY}" \
        "HYPRLAND_INSTANCE_SIGNATURE=${HIS}" \
        "$@"
}

chromium_pids() {
    for proc in /proc/[0-9]*; do
        [ -r "${proc}/cmdline" ] || continue
        [ "$(stat -c '%u' "${proc}" 2>/dev/null || echo -1)" = "${PUNAR_UID}" ] || continue
        if tr '\000' ' ' < "${proc}/cmdline" 2>/dev/null | grep -qF '/usr/lib/chromium/chromium'; then
            basename "${proc}"
        fi
    done
}

profile_browser_pid() {
    profile=$1
    for pid in $(chromium_pids); do
        cmdline="$(tr '\000' ' ' < "/proc/${pid}/cmdline" 2>/dev/null)"
        case "${cmdline}" in
            *"--user-data-dir=${profile}"*)
                case "${cmdline}" in *"--type="*) ;; *) printf '%s\n' "${pid}"; return 0 ;; esac
                ;;
        esac
    done
    return 1
}

profile_pss_kib() {
    profile=$1
    total=0
    for pid in $(chromium_pids); do
        cmdline="$(tr '\000' ' ' < "/proc/${pid}/cmdline" 2>/dev/null)"
        case "${cmdline}" in
            *"--user-data-dir=${profile}"*)
                value="$(awk '/^Pss:/{print $2}' "/proc/${pid}/smaps_rollup" 2>/dev/null || echo 0)"
                total=$((total + value))
                ;;
        esac
    done
    printf '%s\n' "${total}"
}

stop_browsers() {
    pids="$(chromium_pids)"
    # Intentional word splitting: chromium_pids prints one validated decimal
    # process id per line and kill accepts the resulting argument vector.
    # shellcheck disable=SC2086
    [ -z "${pids}" ] || kill ${pids} >/dev/null 2>&1 || true
    waited=0
    while [ "${waited}" -lt 30 ] && [ -n "$(chromium_pids)" ]; do
        sleep 1
        waited=$((waited + 1))
    done
    pids="$(chromium_pids)"
    # shellcheck disable=SC2086
    [ -z "${pids}" ] || kill -9 ${pids} >/dev/null 2>&1 || true
}

# Invoked through EXIT.
# shellcheck disable=SC2317,SC2329
cleanup() {
    stop_browsers
    [ -z "${NOTES_JOB}" ] || wait "${NOTES_JOB}" >/dev/null 2>&1 || true
    [ -z "${FIXTURE_JOB}" ] || wait "${FIXTURE_JOB}" >/dev/null 2>&1 || true
    [ -z "${BROWSER_JOB}" ] || wait "${BROWSER_JOB}" >/dev/null 2>&1 || true
    "${CTL}" --json enroll stop >/dev/null 2>&1 || true
    systemctl stop "${MOCK}" >/dev/null 2>&1 || true
    as_punar "${CTL}" --json web-apps uninstall notes --yes >/dev/null 2>&1 || true
    as_punar "${CTL}" --json web-apps uninstall notes-fixture --yes --purge-data >/dev/null 2>&1 || true
    as_punar "${CTL}" --json web-apps uninstall linear --yes >/dev/null 2>&1 || true
    as_punar "${CTL}" --json web-apps context delete atlas --purge-data >/dev/null 2>&1 || true
    systemctl start "${TIMER}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Deterministic single-actor setup. The timer is restarted for the explicit
# browser-policy drift proof and left in its shipped active state afterward.
systemctl stop "${TIMER}" >/dev/null 2>&1 || true

note "M11 browser, web-app and context exercise"
note "started $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# 1. The shipped boundary and fresh personal state.
check_eq "punard.service active" active "$(systemctl is-active punard.service 2>/dev/null || true)"
if [ -n "${HIS}" ] && [ -n "${WL_DISPLAY}" ]; then
    note "ok   live Hyprland/Wayland session discovered"
else
    note "FAIL live Hyprland/Wayland session missing (hypr=${HIS:-absent}, wayland=${WL_DISPLAY:-absent})"
    FAILED=1
fi

as_punar "${CTL}" --json capabilities > "${RUN_DIR}/m11-capabilities.json" 2>&1
jq_check "browser.policy is the fifth typed capability with a closed desired-state set" \
    "${RUN_DIR}/m11-capabilities.json" \
    '(.capabilities | length) == 5 and ([.capabilities[].capability] | index("browser.policy")) != null and (.capabilities[] | select(.capability == "browser.policy") | .allowed_desired_states) == ["managed", "unmanaged"]'

if [ -x /usr/lib/chromium/chromium ]; then
    note "ok   upstream Chromium real binary exists"
else
    note "FAIL /usr/lib/chromium/chromium is absent or not executable"
    FAILED=1
fi
if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f='${Package} ${Version}\n' chromium chromium-common chromium-sandbox \
        > "${RUN_DIR}/m11-browser-package.txt" 2>&1
    check_true "Debian package manager owns the real Chromium binary" \
        "$(dpkg-query -S /usr/lib/chromium/chromium >/dev/null 2>&1; echo $?)"
elif command -v pacman >/dev/null 2>&1; then
    pacman -Q chromium > "${RUN_DIR}/m11-browser-package.txt" 2>&1
    check_true "Arch package manager owns the real Chromium binary" \
        "$(pacman -Qo /usr/lib/chromium/chromium >/dev/null 2>&1; echo $?)"
else
    note "FAIL no supported package manager can attest Chromium provenance"
    FAILED=1
fi

if grep -q '^\[Install\]' /usr/lib/systemd/system/punar-m11-check.service 2>/dev/null \
        || find /usr/lib/systemd/system -path '*.wants/*' -lname '*punar-m11-check.service' | grep -q .; then
    note "FAIL punar-m11-check.service is enableable or enabled"
    FAILED=1
else
    note "ok   punar-m11-check.service is a never-enabled CI oneshot"
fi

for path in /etc/chromium-flags.conf "${PUNAR_HOME}/.config/chromium-flags.conf" \
    /etc/chromium/policies/recommended; do
    if [ -e "${path}" ]; then
        note "FAIL mutable or recommended Chromium input exists: ${path}"
        FAILED=1
    else
        note "ok   forbidden Chromium input absent: ${path}"
    fi
done

: > "${RUN_DIR}/m11-forbidden-matches.txt"
for path in /usr/local/share/applications \
    /usr/share/applications "${PUNAR_HOME}/.local/share/applications" \
    /etc/chromium/policies/managed "${PUNAR_HOME}/.config/hypr" \
    /usr/lib/punar; do
    [ -e "${path}" ] || continue
    grep -aR -n -F -f "${DENYLIST}" "${path}" \
        >> "${RUN_DIR}/m11-forbidden-matches.txt" 2>/dev/null || true
done
find /usr/share/punar -type f ! -path "${DENYLIST}" -exec \
    grep -aH -n -F -f "${DENYLIST}" {} \; \
    >> "${RUN_DIR}/m11-forbidden-matches.txt" 2>/dev/null || true
if [ -s "${RUN_DIR}/m11-forbidden-matches.txt" ]; then
    note "FAIL a browser weakening token entered a Punar launch or policy surface ($(head -c 300 "${RUN_DIR}/m11-forbidden-matches.txt"))"
    FAILED=1
else
    note "ok   forbidden Chromium token scan is empty across every Punar entry point"
fi

as_punar "${CTL}" --json web-apps list > "${RUN_DIR}/m11-context-list.json" 2>&1
jq_check "fresh inventory has exactly the personal context and no demo apps" \
    "${RUN_DIR}/m11-context-list.json" \
    '(.apps | length) == 0 and [.contexts[].id] == ["personal"] and ([.contexts[].id | select(startswith("org-"))] | length) == 0'

# 2. User-owned contexts and both offline install sources.
as_punar "${CTL}" --json web-apps context create atlas --name Atlas \
    > "${RUN_DIR}/m11-context-create.json" 2>&1
check_true "atlas context creation succeeds as the console user" "$?"
AUDIT_START="$(wc -l < "${AUDIT_LOG}" 2>/dev/null || echo 0)"

as_punar "${CTL}" web-apps install "${NOTES_URL}" --name Notes \
    --context personal --workspace atlas > "${RUN_DIR}/m11-install.txt" 2>&1
check_true "generated-icon web app installs through the typed user path" "$?"
grep_row "human install renders an uppercase installed verdict" \
    "${RUN_DIR}/m11-install.txt" "INSTALLED"

RECORD="${APPS_ROOT}/notes.json"
DESKTOP="${DESKTOP_ROOT}/punar-webapp-notes.desktop"
ICON="${ICON_ROOT}/punar-webapp-notes.png"
cp "${RECORD}" "${RUN_DIR}/m11-webapp-record.json" 2>/dev/null || true
jq_check "root-owned record has the complete web-app shape" "${RECORD}" \
    '.v == 1 and .id == "notes" and .name == "Notes" and .context == "personal" and .workspace == "atlas" and .origin == "file://" and .managed == false and (.icon.sha256 | test("^[0-9a-f]{64}$"))'
check_eq "web-app record mode/owner" "600 root root" \
    "$(stat -c '%a %U %G' "${RECORD}" 2>/dev/null || echo absent)"
check_eq "desktop entry mode/owner" "644 punar punar" \
    "$(stat -c '%a %U %G' "${DESKTOP}" 2>/dev/null || echo absent)"
grep_row "desktop entry launches only the typed id" "${DESKTOP}" "Exec=punarctl web-apps launch notes"
grep_row "desktop entry and compositor share a stable class" "${DESKTOP}" "StartupWMClass=punar-webapp-notes"
if grep -qi chromium "${DESKTOP}" 2>/dev/null; then
    note "FAIL derived desktop entry contains a Chromium token"
    FAILED=1
else
    note "ok   derived desktop entry cannot inject Chromium flags"
fi
check_eq "icon digest equals the root-owned record" \
    "$(jq -r '.icon.sha256' "${RECORD}" 2>/dev/null)" \
    "$(sha256sum "${ICON}" 2>/dev/null | awk '{print $1}')"
check_eq "icon carries the PNG signature" 89504e470d0a1a0a \
    "$(od -An -tx1 -N8 "${ICON}" 2>/dev/null | tr -d ' \n')"

FIRST_ICON="$(sha256sum "${ICON}" | awk '{print $1}')"
as_punar "${CTL}" --json web-apps uninstall notes --yes >/dev/null 2>&1
as_punar "${CTL}" --json web-apps install "${NOTES_URL}" --name Notes \
    --context personal --workspace atlas >/dev/null 2>&1
check_eq "generated monogram bytes are deterministic across reinstall" \
    "${FIRST_ICON}" "$(sha256sum "${ICON}" 2>/dev/null | awk '{print $1}')"

as_punar "${CTL}" --json web-apps install --from-manifest "${FIXTURE_MANIFEST}" \
    --context atlas > "${RUN_DIR}/m11-fixture-install.json" 2>&1
check_true "strict local-manifest install succeeds without a fetch" "$?"
jq_check "manifest fields round-trip into the daemon record" \
    "${APPS_ROOT}/notes-fixture.json" \
    '.id == "notes-fixture" and .name == "Notes Fixture" and .context == "atlas" and .workspace == "atlas" and .icon.kind == "file"'

as_punar "${CTL}" --json web-apps install https://linear.app --name Linear \
    --context atlas > "${RUN_DIR}/m11-linear-install.json" 2>&1
check_true "HTTPS identity installs without contacting its origin" "$?"
as_punar "${CTL}" --json web-apps launch linear --dry-run \
    > "${RUN_DIR}/m11-argv-dryrun.txt" 2>&1
jq_check "dry-run is an exact closed Chromium argv with origin and context" \
    "${RUN_DIR}/m11-argv-dryrun.txt" \
    '.program == "/usr/lib/chromium/chromium" and (.argv | length) == 7 and (.argv | index("--app=https://linear.app")) != null and (.argv | index("--class=punar-webapp-linear")) != null and (.argv | map(select(startswith("--user-data-dir="))) | length) == 1'
if grep -F -f "${DENYLIST}" "${RUN_DIR}/m11-argv-dryrun.txt" >/dev/null 2>&1; then
    note "FAIL dry-run argv contains a forbidden Chromium token"
    FAILED=1
else
    note "ok   dry-run argv contains no weakening token"
fi

# 3. Native app window and live Chromium sandbox evidence.
as_punar "${CTL}" web-apps launch notes > "${RUN_DIR}/m11-notes-launch.txt" 2>&1 &
NOTES_JOB=$!
waited=0
while [ "${waited}" -lt 150 ]; do
    as_punar hyprctl -j clients 2>/dev/null | jq -e \
        '.[] | select(.class == "punar-webapp-notes" or .initialClass == "punar-webapp-notes")' \
        >/dev/null 2>&1 && break
    sleep 1
    waited=$((waited + 1))
done
as_punar hyprctl -j clients > "${RUN_DIR}/m11-clients.json" 2>&1
jq_check "installed web app is a native compositor client on its workspace" \
    "${RUN_DIR}/m11-clients.json" \
    '[.[] | select((.class == "punar-webapp-notes" or .initialClass == "punar-webapp-notes") and (.workspace.name | ascii_downcase) == "atlas")] | length == 1'

PERSONAL_PROFILE="${CONTEXT_ROOT}/personal"
ATLAS_PROFILE="${CONTEXT_ROOT}/atlas"
PERSONAL_PID="$(profile_browser_pid "${PERSONAL_PROFILE}" 2>/dev/null || true)"
if [ -n "${PERSONAL_PID}" ]; then
    note "ok   browser process carries the personal profile in the closed argv"
else
    note "FAIL no browser process carries ${PERSONAL_PROFILE}"
    FAILED=1
fi

zygotes=0
renderers=0
sandbox_bad=0
for pid in $(chromium_pids); do
    cmdline="$(tr '\000' ' ' < "/proc/${pid}/cmdline" 2>/dev/null)"
    case "${cmdline}" in *--type=zygote*) zygotes=$((zygotes + 1)) ;; esac
    case "${cmdline}" in
        *--type=renderer*)
            renderers=$((renderers + 1))
            grep -q '^Seccomp:[[:space:]]*2$' "/proc/${pid}/status" 2>/dev/null || sandbox_bad=1
            grep -q '^NoNewPrivs:[[:space:]]*1$' "/proc/${pid}/status" 2>/dev/null || sandbox_bad=1
            ;;
    esac
done
if [ "${zygotes}" -ge 1 ] && [ "${renderers}" -ge 1 ] && [ "${sandbox_bad}" -eq 0 ]; then
    note "ok   live Chromium tree has zygote and seccomp/no-new-privs renderers"
else
    note "FAIL live sandbox evidence incomplete (zygotes=${zygotes}, renderers=${renderers}, bad=${sandbox_bad})"
    FAILED=1
fi
check_eq "setuid sandbox fallback mode/owner" "4755 root root" \
    "$(stat -c '%a %U %G' /usr/lib/chromium/chrome-sandbox 2>/dev/null || echo absent)"
if [ "$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo 0)" -gt 0 ]; then
    note "ok   unprivileged user namespaces remain available"
else
    note "FAIL unprivileged user namespaces are disabled"
    FAILED=1
fi

as_punar hyprctl dispatch workspace name:atlas >/dev/null 2>&1 || true
sleep 2
as_punar grim "${RUN_DIR}/punar-m11.png" >/dev/null 2>&1
if [ -s "${RUN_DIR}/punar-m11.png" ]; then
    note "ok   native web-app screenshot is non-empty"
else
    note "FAIL native web-app screenshot is absent or empty"
    FAILED=1
fi

PERSONAL_PSS="$(profile_pss_kib "${PERSONAL_PROFILE}")"

# 4. A second context is a distinct profile and process tree.
as_punar "${CTL}" web-apps launch notes-fixture --context atlas \
    > "${RUN_DIR}/m11-fixture-launch.txt" 2>&1 &
FIXTURE_JOB=$!
waited=0
while [ "${waited}" -lt 150 ]; do
    [ -n "$(profile_browser_pid "${ATLAS_PROFILE}" 2>/dev/null || true)" ] && break
    sleep 1
    waited=$((waited + 1))
done
ATLAS_PID="$(profile_browser_pid "${ATLAS_PROFILE}" 2>/dev/null || true)"
if [ -n "${PERSONAL_PID}" ] && [ -n "${ATLAS_PID}" ] && [ "${PERSONAL_PID}" != "${ATLAS_PID}" ]; then
    note "ok   personal and atlas contexts are distinct browser process trees"
else
    note "FAIL contexts do not have distinct browser pids (personal=${PERSONAL_PID:-absent}, atlas=${ATLAS_PID:-absent})"
    FAILED=1
fi
check_eq "personal context directory mode/owner" "700 punar punar" \
    "$(stat -c '%a %U %G' "${PERSONAL_PROFILE}" 2>/dev/null || echo absent)"
check_eq "atlas context directory mode/owner" "700 punar punar" \
    "$(stat -c '%a %U %G' "${ATLAS_PROFILE}" 2>/dev/null || echo absent)"

ATLAS_PSS="$(profile_pss_kib "${ATLAS_PROFILE}")"
note "PUNAR_M11_WEBAPP_RSS_MB=$(((PERSONAL_PSS + 1023) / 1024))"
note "PUNAR_M11_CONTEXT_DELTA_MB=$(((ATLAS_PSS + 1023) / 1024))"

as_punar "${CTL}" --json web-apps context use atlas \
    > "${RUN_DIR}/m11-context-active.json" 2>&1
jq_check "manual context selection becomes the next browser default" \
    "${RUN_DIR}/m11-context-active.json" \
    '.active == "atlas" and .active_cause == "manual"'
as_punar "${CTL}" web-apps context status > "${RUN_DIR}/m11-context-status.txt" 2>&1
grep_row "context status says existing windows are unchanged" \
    "${RUN_DIR}/m11-context-status.txt" "EXISTING WINDOWS"
grep_row "context status says workspace changes do not launch apps" \
    "${RUN_DIR}/m11-context-status.txt" "WORKSPACE CHANGES DO NOT START APPS"

# 5. The PUNAR+B command target opens a normal browser in the chosen context.
stop_browsers
[ -z "${NOTES_JOB}" ] || wait "${NOTES_JOB}" >/dev/null 2>&1 || true
[ -z "${FIXTURE_JOB}" ] || wait "${FIXTURE_JOB}" >/dev/null 2>&1 || true
NOTES_JOB=""
FIXTURE_JOB=""
# Chromium may buffer LevelDB writes while the page is live. Inspect the
# profiles only after both processes have exited so this remains deterministic
# on slower TCG and storage-constrained CI hosts.
if grep -raF 'punar-ctx-probe-personal' "${PERSONAL_PROFILE}" >/dev/null 2>&1 \
        && ! grep -raF 'punar-ctx-probe-atlas' "${PERSONAL_PROFILE}" >/dev/null 2>&1 \
        && grep -raF 'punar-ctx-probe-atlas' "${ATLAS_PROFILE}" >/dev/null 2>&1 \
        && ! grep -raF 'punar-ctx-probe-personal' "${ATLAS_PROFILE}" >/dev/null 2>&1; then
    note "ok   browser storage probe values remain separated by context"
else
    note "FAIL profile storage did not prove two-way context separation"
    FAILED=1
fi

as_punar "${CTL}" web-apps browse --context atlas \
    > "${RUN_DIR}/m11-browser-launch.txt" 2>&1 &
BROWSER_JOB=$!
waited=0
while [ "${waited}" -lt 150 ]; do
    [ -n "$(profile_browser_pid "${ATLAS_PROFILE}" 2>/dev/null || true)" ] && break
    sleep 1
    waited=$((waited + 1))
done
if [ -n "$(profile_browser_pid "${ATLAS_PROFILE}" 2>/dev/null || true)" ]; then
    note "ok   normal browser command opens with the selected atlas profile"
else
    note "FAIL normal browser command did not open with the atlas profile"
    FAILED=1
fi
if grep -qF 'browser = "punarctl web-apps browse"' /etc/xdg/hypr/hyprland.lua \
        2>/dev/null && grep -qF 'bind(mod .. " + B", hl.dsp.exec_cmd(ctx.browser)' \
        /etc/xdg/hypr/punar-binds.lua 2>/dev/null; then
    note "ok   PUNAR+B resolves to the typed context-aware browser command"
else
    note "FAIL shipped compositor config does not route PUNAR+B through punarctl"
    FAILED=1
fi
stop_browsers
[ -z "${BROWSER_JOB}" ] || wait "${BROWSER_JOB}" >/dev/null 2>&1 || true
BROWSER_JOB=""

# 6. Enrollment derives the managed context and a closed browser policy.
if systemctl start "${MOCK}" >/dev/null 2>&1; then
    note "ok   managed-policy mock started only for this check"
else
    note "FAIL managed-policy mock could not start"
    FAILED=1
fi
waited=0
while [ "${waited}" -lt 15 ] && [ ! -S "${MOCK_SOCK}" ]; do
    sleep 1
    waited=$((waited + 1))
done
if [ -S "${MOCK_SOCK}" ]; then
    note "ok   managed-policy mock socket became ready"
else
    note "FAIL managed-policy mock socket is absent"
    FAILED=1
fi

"${CTL}" --json enroll start acme.com > "${RUN_DIR}/m11-enroll.json" 2>&1
check_true "enrollment for browser-policy proof succeeds" "$?"
as_punar "${CTL}" --json web-apps list > "${RUN_DIR}/m11-managed-list.json" 2>&1
jq_check "enrollment derives one non-deletable org context and disables user install" \
    "${RUN_DIR}/m11-managed-list.json" \
    '(.contexts | any(.id == "org-acme" and .derived == true and .deletable == false and .simulated == ["certificate_roots"])) and .policy.managed == true and .policy.allow_user_install == false'

as_punar "${CTL}" --json web-apps context delete org-acme \
    > "${RUN_DIR}/m11-org-delete-refusal.txt" 2>&1
check_eq "derived org context deletion is denied" 3 "$?"
grep_row "derived-context denial explains that enrollment owns it" \
    "${RUN_DIR}/m11-org-delete-refusal.txt" "organization contexts are derived from enrollment"

check_eq "managed Chromium policy mode/owner" "644 root root" \
    "$(stat -c '%a %U %G' "${MANAGED_POLICY}" 2>/dev/null || echo absent)"
cp "${MANAGED_POLICY}" "${RUN_DIR}/m11-managed-policy.json" 2>/dev/null || true
jq_check "managed policy is closed and keeps hardening values non-weakening" \
    "${RUN_DIR}/m11-managed-policy.json" \
    '.SitePerProcess == true and .RemoteDebuggingAllowed == false and .SSLErrorOverrideAllowed == false and .InsecurePrivateNetworkRequestsAllowed == false and (.URLBlocklist | index("https://social.example")) != null'

as_punar "${CTL}" --json web-apps install https://social.example --name Social \
    > "${RUN_DIR}/m11-origin-denial.txt" 2>&1
check_eq "organization-denied origin cannot be installed" 3 "$?"
grep_row "origin denial cites the effective organization policy" \
    "${RUN_DIR}/m11-origin-denial.txt" "eng-baseline-v12"

MANAGED_BEFORE="$(sha256sum "${MANAGED_POLICY}" 2>/dev/null | awk '{print $1}')"
printf '\n' >> "${MANAGED_POLICY}"
"${CTL}" --json capabilities get browser.policy \
    > "${RUN_DIR}/m11-browser-drift.json" 2>&1
jq_check "manual policy corruption is observed as drift" \
    "${RUN_DIR}/m11-browser-drift.json" '.descriptor.current_state == "drifted"'
if systemctl start "${TIMER}" >/dev/null 2>&1; then
    note "ok   scheduled reconcile timer armed for browser-policy drift"
else
    note "FAIL scheduled reconcile timer could not start"
    FAILED=1
fi
deadline=$(($(date +%s) + DRIFT_BUDGET_SECS))
while [ "$(date +%s)" -lt "${deadline}" ]; do
    [ "$(sha256sum "${MANAGED_POLICY}" 2>/dev/null | awk '{print $1}')" = "${MANAGED_BEFORE}" ] && break
    sleep 5
done
check_eq "browser policy returns to its rendered digest" "${MANAGED_BEFORE}" \
    "$(sha256sum "${MANAGED_POLICY}" 2>/dev/null | awk '{print $1}')"
"${CTL}" --json audit tail -n 100 > "${RUN_DIR}/m11-browser-reconcile.json" 2>&1
jq_check "timer-driven browser-policy repair is audited" \
    "${RUN_DIR}/m11-browser-reconcile.json" \
    '.events | any(.action == "reconcile.remediate" and .resource == "browser.policy" and .result == "success")'

systemctl stop "${MOCK}" >/dev/null 2>&1 || true
"${CTL}" --json enroll stop > "${RUN_DIR}/m11-unenroll.json" 2>&1
check_true "offline unenrollment restores personal browser mode" "$?"
as_punar "${CTL}" --json web-apps list > "${RUN_DIR}/m11-personal-list.json" 2>&1
jq_check "org context disappears after unenrollment" \
    "${RUN_DIR}/m11-personal-list.json" \
    '.policy.managed == false and ([.contexts[].id | select(startswith("org-"))] | length) == 0'
if [ ! -e "${MANAGED_POLICY}" ]; then
    note "ok   personal mode has no managed Chromium policy file"
else
    note "FAIL managed Chromium policy survived unenrollment"
    FAILED=1
fi

# 7. Audit privacy, offline update provenance, and lifecycle cleanup.
tail -n "+$((AUDIT_START + 1))" "${AUDIT_LOG}" \
    > "${RUN_DIR}/m11-audit-window.jsonl" 2>/dev/null || true
if jq -e -s 'any(.action == "webapp.install" and .resource == "webapp:notes" and .result == "installed")' \
        "${RUN_DIR}/m11-audit-window.jsonl" >/dev/null 2>&1; then
    note "ok   web-app installation is represented in the typed audit window"
else
    note "FAIL web-app installation audit event is absent"
    FAILED=1
fi
if grep -Eqi 'punar-ctx-probe|browser/contexts/|cookie' \
        "${RUN_DIR}/m11-audit-window.jsonl" 2>/dev/null; then
    note "FAIL audit window contains browser profile or page-storage detail"
    FAILED=1
else
    note "ok   audit window contains no browser profile, cookie, or page-storage detail"
fi

"${CTL}" update status > "${RUN_DIR}/m11-update-status.txt" 2>&1
check_true "offline update status reads local system/browser evidence" "$?"
grep_row "update status names the browser engine" \
    "${RUN_DIR}/m11-update-status.txt" "CHROMIUM"
grep_row "update status states the browser security-channel posture" \
    "${RUN_DIR}/m11-update-status.txt" "SECURITY CHANNEL"

DESKTOP_BEFORE="$(sha256sum "${DESKTOP}" | awk '{print $1}')"
rm -f "${DESKTOP}"
as_punar "${CTL}" --json web-apps sync > "${RUN_DIR}/m11-sync.json" 2>&1
check_eq "sync reconstructs the desktop entry byte-for-byte" \
    "${DESKTOP_BEFORE}" "$(sha256sum "${DESKTOP}" 2>/dev/null | awk '{print $1}')"

stop_browsers
NOTES_JOB=""
FIXTURE_JOB=""
as_punar "${CTL}" web-apps uninstall notes --yes \
    > "${RUN_DIR}/m11-uninstall.txt" 2>&1
check_true "default uninstall succeeds" "$?"
grep_row "default uninstall tells the user browser data was kept" \
    "${RUN_DIR}/m11-uninstall.txt" "BROWSER PROFILE DATA WAS KEPT"
if [ ! -e "${RECORD}" ] && [ ! -e "${DESKTOP}" ] && [ ! -e "${ICON}" ] \
        && [ -d "${PERSONAL_PROFILE}" ]; then
    note "ok   uninstall removes identity artifacts and keeps profile data by default"
else
    note "FAIL uninstall identity/data lifecycle is inconsistent"
    FAILED=1
fi

as_punar "${CTL}" --json web-apps uninstall notes-fixture --yes --purge-data >/dev/null 2>&1
as_punar "${CTL}" --json web-apps uninstall linear --yes >/dev/null 2>&1
as_punar "${CTL}" --json web-apps context delete atlas --purge-data >/dev/null 2>&1
as_punar "${CTL}" --json web-apps context status > "${RUN_DIR}/m11-context-after-delete.json" 2>&1
jq_check "deleting the active context falls back to personal" \
    "${RUN_DIR}/m11-context-after-delete.json" \
    '.active == "personal" and .active_cause == "default"'
if [ ! -e "${ATLAS_PROFILE}" ] \
        && ! find "${PUNAR_HOME}" /var/lib/punar -name '*punar-webapp-notes*' -print 2>/dev/null | grep -q .; then
    note "ok   explicit purge removes atlas data and no Notes launcher identity survives"
else
    note "FAIL purge left an atlas profile or Notes launcher identity"
    FAILED=1
fi

stop_browsers
if [ -z "$(chromium_pids)" ]; then
    note "ok   every Chromium process started by the exercise is gone"
else
    note "FAIL Chromium processes survived exercise cleanup"
    FAILED=1
fi
if grep -F 'punar-browser' /usr/lib/punar/idle-ram.sh >/dev/null 2>&1; then
    note "FAIL browser integration entered the resident-services budget list"
    FAILED=1
else
    note "ok   browser integration adds no resident Punar service"
fi

if [ "${FAILED}" -eq 0 ]; then
    note "PUNAR_M11_OK"
else
    note "PUNAR_M11_FAIL"
fi
cat "${REPORT}"
exit 0
