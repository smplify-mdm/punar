#!/bin/sh
# M6 in-VM developer-environment exercise (milestone-6.md §10; SPEC
# sections 16, 17). Runs AS ROOT via punar-m6-check.service; every
# punar-env and podman invocation runs AS punar (punar-env refuses uid 0
# by design — rootless podman is the whole point) via the established
# runuser pattern. idle-ram.sh starts this synchronously AFTER
# punar-m5-check.service and BEFORE the artifact export, so everything
# written into /run/punar here (m6-report.txt, m6-status.txt,
# m6-status.json, m6-podman-info.json, m6-podman-ps.txt, m6-*.txt
# snapshots) ships in the same export tar.
#
# The script ALWAYS exits 0: the verdict lives in /run/punar/m6-report.txt
# (`PUNAR_M6_OK` / `PUNAR_M6_FAIL` final line, per-assertion `ok`/`FAIL`
# lines above it) and is echoed to the console for the serial log. The
# host gate (tools/boot-test.sh phase 8) parses the exported report and
# hard-fails on PUNAR_M6_FAIL or a truncated report.
#
# The journey (milestone-6.md §10, 9 assertion groups): rootless preflight
# (podman info + the M1 subuid mapping) → Atlas fixture copied to
# ~punar/atlas → init idempotence (byte-identity) + scaffold validity in a
# scratch dir → up (staged archive 0644, podman load, running container,
# --network none, /workspace bind) → shell exit-code passthrough +
# rootless uid-mapping write proof → status verbatim-render greps + jq on
# --json → agent launch honesty (real membership check + clean failure) →
# destroy (container gone, project files intact, idempotent) → verdict.
# No screenshots: this is a CLI milestone; the exported m6-status.txt is
# the human evidence.
#
# Honesty note (spec 1.22): everything asserted here is the DECLARED
# surface plus the one grant M6 realizes (the /workspace bind mount).
# Network zones, credentials and agent sessions are asserted as labeled
# declarations (enforced M12/M9/M7), never as enforcement.
# IMAGE TOOLING TRAP (CI run 32852810872): the punar-desktop image has NO
# diffutils — `cmp` and `diff` do not exist. A bare `cmp -s a b` fails as
# command-not-found and reads as a content mismatch. Compare files with
# sha256sum (coreutils, always present). Do not reintroduce cmp/diff here.

set -u

RUN_DIR=/run/punar
REPORT="${RUN_DIR}/m6-report.txt"
ENV_BIN=/usr/bin/punar-env
FIXTURE_DIR=/usr/share/punar/fixtures/projects/atlas
ARCHIVE=/usr/share/punar/oci/punar-env-base.tar
NOTE=/usr/share/punar/oci/punar-env-base.note.txt
IMAGE_REF=localhost/punar-env-base:m6
CONTAINER=punar-env-atlas
PUNAR_HOME=/home/punar
ATLAS="${PUNAR_HOME}/atlas"
SCRATCH="${PUNAR_HOME}/m6-scratch"
FAILED=0

: > "${REPORT}"

note() { printf '%s\n' "$*" >> "${REPORT}"; }

# check_eq <name> <expected> <actual>
check_eq() {
    if [ "$2" = "$3" ]; then
        note "ok   $1 = $3"
    else
        note "FAIL $1 (expected '$2', got '$3')"
        FAILED=1
    fi
}

# jq_check <name> <json-file> <jq filter that must be truthy>
jq_check() {
    if jq -e "$3" "$2" >/dev/null 2>&1; then
        note "ok   $1"
    else
        note "FAIL $1 (jq filter: $3; input head: $(head -c 240 "$2" 2>/dev/null || echo absent))"
        FAILED=1
    fi
}

# grep_re <name> <file> <ERE that must match some line>
# The shape-matching sibling of grep_row. punar-env's human output is NOT
# uppercased (that is punarctl's fmt::verdict), so this stays case-sensitive
# like grep_row below it.
grep_re() {
    if grep -qE "$3" "$2" 2>/dev/null; then
        note "ok   $1"
    else
        note "FAIL $1 (no line matching: '$3')"
        FAILED=1
    fi
}

# grep_row <name> <file> <fixed string that must be present>
grep_row() {
    if grep -qF "$3" "$2" 2>/dev/null; then
        note "ok   $1"
    else
        note "FAIL $1 (missing: '$3')"
        FAILED=1
    fi
}

# All punar-env/podman work runs as punar with the live logind session's
# runtime dir (greetd autologin created it) — fixed argv end to end, no
# shell string ever crosses the runuser boundary. punar-env takes the
# project directory via -C, so no cwd juggling is needed.
PUNAR_UID="$(id -u punar 2>/dev/null || echo 1000)"
as_punar() {
    runuser -u punar -- env "XDG_RUNTIME_DIR=/run/user/${PUNAR_UID}" \
        "HOME=${PUNAR_HOME}" "$@"
}

# --- 1. rootless preflight ---------------------------------------------------
as_punar podman info --format json > "${RUN_DIR}/m6-podman-info.json" \
    2> "${RUN_DIR}/m6-podman-info-stderr.txt"
check_eq "podman info as punar exit code" 0 "$?"
jq_check "podman info: rootless true" "${RUN_DIR}/m6-podman-info.json" \
    '.host.security.rootless == true'
if grep -q '^punar:100000:65536$' /etc/subuid \
        && grep -q '^punar:100000:65536$' /etc/subgid; then
    note "ok   subuid/subgid mapping punar:100000:65536 present (M1 rootless design)"
else
    note "FAIL subuid/subgid mapping missing (subuid: $(tr '\n' ' ' < /etc/subuid 2>/dev/null))"
    FAILED=1
fi
# Recorded, not asserted: the storage/cgroup config actually in effect.
note "info storage driver: $(jq -r '.store.graphDriverName // "unknown"' "${RUN_DIR}/m6-podman-info.json" 2>/dev/null)"
note "info cgroup manager: $(jq -r '.host.cgroupManager // "unknown"' "${RUN_DIR}/m6-podman-info.json" 2>/dev/null)"

# --- 2. fixture copy ---------------------------------------------------------
if [ -f "${FIXTURE_DIR}/project-environment.yaml" ]; then
    note "ok   staged Atlas fixture present at ${FIXTURE_DIR}"
else
    note "FAIL staged Atlas fixture missing at ${FIXTURE_DIR}"
    FAILED=1
fi
mkdir -p "${ATLAS}"
# Copy errors are REPORTED, never swallowed (a silent cp failure cost a CI
# cycle in run 32852810872: the manifest mismatch had no visible cause).
if ! cp "${FIXTURE_DIR}/project-environment.yaml" \
        "${FIXTURE_DIR}/project-network-policy.json" "${ATLAS}/" \
        > "${RUN_DIR}/m6-fixture-cp.txt" 2>&1; then
    note "FAIL fixture copy failed: $(head -c 200 "${RUN_DIR}/m6-fixture-cp.txt")"
    FAILED=1
fi
chown -R punar:punar "${ATLAS}"
# Self-diagnosing comparison: on mismatch, print both digests and both
# stat lines so the CI log names the cause without an image autopsy.
FIXTURE_SHA="$(sha256sum "${FIXTURE_DIR}/project-environment.yaml" 2>&1 | cut -d" " -f1)"
ATLAS_SHA="$(sha256sum "${ATLAS}/project-environment.yaml" 2>&1 | cut -d" " -f1)"
if [ "${FIXTURE_SHA}" = "${ATLAS_SHA}" ]; then
    note "ok   copied manifest byte-identical to the staged fixture = ${ATLAS_SHA}"
else
    note "FAIL copied manifest differs: staged=${FIXTURE_SHA} copy=${ATLAS_SHA}"
    note "     staged: $(ls -l "${FIXTURE_DIR}/project-environment.yaml" 2>&1)"
    note "     copy:   $(ls -l "${ATLAS}/project-environment.yaml" 2>&1)"
    note "     staged head: $(head -c 120 "${FIXTURE_DIR}/project-environment.yaml" 2>&1 | tr "\n" "|")"
    note "     copy   head: $(head -c 120 "${ATLAS}/project-environment.yaml" 2>&1 | tr "\n" "|")"
    FAILED=1
fi

# --- 3. init idempotence + scaffold validity ---------------------------------
sha_before="$(sha256sum "${ATLAS}/project-environment.yaml" | cut -d' ' -f1)"
as_punar "${ENV_BIN}" -C "${ATLAS}" init > "${RUN_DIR}/m6-init.txt" 2>&1
check_eq "init on the existing manifest exit code" 0 "$?"
if grep -q 'already initialized' "${RUN_DIR}/m6-init.txt"; then
    note "ok   init reports already initialized"
else
    note "FAIL init output: $(head -c 240 "${RUN_DIR}/m6-init.txt" 2>/dev/null)"
    FAILED=1
fi
sha_after="$(sha256sum "${ATLAS}/project-environment.yaml" | cut -d' ' -f1)"
check_eq "manifest byte-identical after init (sha256)" "${sha_before}" "${sha_after}"

# Scaffold path: init in a fresh empty dir writes punar-env.yaml, and the
# binary's own strict parser accepts it (status parses the manifest before
# it renders — a schema-invalid scaffold could not get that far).
as_punar mkdir "${SCRATCH}"
as_punar "${ENV_BIN}" -C "${SCRATCH}" init > "${RUN_DIR}/m6-scratch-init.txt" 2>&1
check_eq "scaffold init exit code" 0 "$?"
if [ -f "${SCRATCH}/punar-env.yaml" ]; then
    note "ok   scaffold wrote punar-env.yaml"
else
    note "FAIL scaffold did not write punar-env.yaml"
    FAILED=1
fi
as_punar "${ENV_BIN}" -C "${SCRATCH}" status \
    > "${RUN_DIR}/m6-scratch-status.txt" 2>&1
check_eq "status parses the scaffold (own strict parser) exit code" 0 "$?"
rm -rf "${SCRATCH}"

# --- 4. up -------------------------------------------------------------------
check_eq "staged OCI archive mode" "644" "$(stat -c '%a' "${ARCHIVE}" 2>/dev/null)"
as_punar "${ENV_BIN}" -C "${ATLAS}" up > "${RUN_DIR}/m6-up.txt" 2>&1
check_eq "punar-env up exit code" 0 "$?"
as_punar podman image exists "${IMAGE_REF}" >/dev/null 2>&1
check_eq "podman image exists ${IMAGE_REF} (the offline load happened)" 0 "$?"
as_punar podman container inspect "${CONTAINER}" \
    > "${RUN_DIR}/m6-inspect.json" 2>/dev/null
check_eq "podman container inspect ${CONTAINER} exit code" 0 "$?"
jq_check "container running with both dev.punar.* labels" \
    "${RUN_DIR}/m6-inspect.json" \
    '.[0].State.Status == "running"
     and .[0].Config.Labels["dev.punar.managed-by"] == "punar-env"
     and .[0].Config.Labels["dev.punar.project"] == "atlas"'
jq_check "network mode none (M6 honesty: no faked networking)" \
    "${RUN_DIR}/m6-inspect.json" \
    '.[0].HostConfig.NetworkMode == "none"'
jq_check "project bind-mounted rw at /workspace" \
    "${RUN_DIR}/m6-inspect.json" \
    ".[0].Mounts | any(.Type == \"bind\" and .Source == \"${ATLAS}\"
       and .Destination == \"/workspace\" and .RW == true)"
as_punar "${ENV_BIN}" -C "${ATLAS}" up > "${RUN_DIR}/m6-up-again.txt" 2>&1
check_eq "second up exit code (idempotent)" 0 "$?"
if grep -q 'already up' "${RUN_DIR}/m6-up-again.txt"; then
    note "ok   second up reports already up"
else
    note "FAIL second up output: $(head -c 240 "${RUN_DIR}/m6-up-again.txt" 2>/dev/null)"
    FAILED=1
fi
# The ps snapshot CI uploads as evidence (running state; §10 exports).
as_punar podman ps -a > "${RUN_DIR}/m6-podman-ps.txt" 2>&1

# --- 5. shell passthrough + workspace writable -------------------------------
# The release marker read from INSIDE the container must match the pin the
# build recorded in the staged digest note — proof the staged archive is
# what actually runs (milestone-6.md §6.2).
snap_date="$(sed -n 's/^snapshot: //p' "${NOTE}" 2>/dev/null | head -n 1)"
# Compatibility with pre-multi-architecture M6 archives. New builders expose
# the substrate-neutral snapshot field above; older x86 images only embedded
# the Arch Linux Archive date in the input description.
if [ -z "${snap_date}" ]; then
    snap_date="$(sed -n 's/^input: .* (ALA \(.*\), extra repo)$/\1/p' "${NOTE}" 2>/dev/null)"
fi
as_punar "${ENV_BIN}" -C "${ATLAS}" shell -c 'cat /etc/punar-env-base-release' \
    > "${RUN_DIR}/m6-shell-release.txt" 2>&1
check_eq "shell -c cat release marker exit code" 0 "$?"
check_eq "release marker matches the staged archive's recorded pin" \
    "punar-env-base m6 ${snap_date}" \
    "$(head -n 1 "${RUN_DIR}/m6-shell-release.txt" 2>/dev/null)"
as_punar "${ENV_BIN}" -C "${ATLAS}" shell -c 'exit 42' >/dev/null 2>&1
check_eq "shell -c 'exit 42' passes the container exit code through" 42 "$?"
as_punar "${ENV_BIN}" -C "${ATLAS}" shell -c 'touch /workspace/.m6-write' \
    >/dev/null 2>&1
check_eq "shell -c touch /workspace/.m6-write exit code" 0 "$?"
if [ -f "${ATLAS}/.m6-write" ]; then
    note "ok   container write surfaced on the host at ${ATLAS}/.m6-write"
else
    note "FAIL ${ATLAS}/.m6-write missing on the host"
    FAILED=1
fi
check_eq "host-side .m6-write owner (rootless uid mapping)" "punar" \
    "$(stat -c '%U' "${ATLAS}/.m6-write" 2>/dev/null)"

# --- 6. status: D-014 render verbatim + --json -------------------------------
# Non-TTY capture, so the render is column-clean with no ANSI (the state
# word is the only colored token, and only on a terminal). Every grep
# below is a fixed string from the milestone-6.md §7 target render —
# fixture values verbatim, per-row enforcement labels intact.
as_punar "${ENV_BIN}" -C "${ATLAS}" status > "${RUN_DIR}/m6-status.txt" 2>&1
check_eq "punar-env status exit code" 0 "$?"
grep_row "status masthead" "${RUN_DIR}/m6-status.txt" "PUNAR-ENV · ATLAS"
grep_row "status environment row (running)" "${RUN_DIR}/m6-status.txt" \
    "Environment   devcontainer · running · punar-env-atlas"
grep_row "status workspace row (applied bind mount)" "${RUN_DIR}/m6-status.txt" \
    "Workspace     ${ATLAS} → /workspace · read_write (applied · bind mount)"
# The enforcement column's whole vocabulary, in one place. A row may say it is
# applied, or enforced, or that it is a declaration whose enforcement is still
# owed — and in that last case it must name the milestone that owes it. Every
# permissions row below matches THIS, not a milestone number, so the day
# punar-netd or the broker relabels a row, the edit is here and not in six
# assertions (docs/development/checks-conventions.md).
ENFORCE_RE='(applied( \(bind mount\))?|enforced|declared · (enforced( M[0-9]+)?|applied|not realized in M[0-9]+))'

# Milestone-agnostic: the row must say the container is isolated AND state
# where the declared zones stand — a milestone while enforcement is pending,
# or plain "enforced" once punar-netd lands. Pinning "M12" here would fail
# the day M12 ships, for a change that is correct.
grep_re "status network row (isolated, and the enforcement status of the declared zones is stated)" \
    "${RUN_DIR}/m6-status.txt" \
    '^Network +isolated \(M[0-9]+\) · declared zones enforced( M[0-9]+)?$'
grep_row "toolchains declared header" "${RUN_DIR}/m6-status.txt" \
    "TOOLCHAINS · DECLARED"
grep_row "toolchain node 24 verbatim" "${RUN_DIR}/m6-status.txt" \
    "  node        24"
grep_row "toolchain rust stable verbatim" "${RUN_DIR}/m6-status.txt" \
    "  rust        stable"
grep_re "services declared-not-started header" "${RUN_DIR}/m6-status.txt" \
    '^SERVICES · DECLARED · not started( in M[0-9]+)?$'
grep_row "service postgres declared" "${RUN_DIR}/m6-status.txt" \
    "  postgres    declared"
grep_re "ai agents declared header (declared, and the milestone that brings sessions is named)" \
    "${RUN_DIR}/m6-status.txt" '^AI AGENTS · DECLARED · sessions arrive M[0-9]+$'
grep_row "ai agents row verbatim" "${RUN_DIR}/m6-status.txt" \
    "  claude-code · codex"
grep_re "permissions filesystem row (the one applied grant)" \
    "${RUN_DIR}/m6-status.txt" \
    "^ +filesystem +project +read_write +${ENFORCE_RE}$"
grep_re "permissions network internet allow" "${RUN_DIR}/m6-status.txt" \
    "^ +network +internet +allow +${ENFORCE_RE}$"
grep_re "permissions network corp_dev allow" "${RUN_DIR}/m6-status.txt" \
    "^ +network +corp_dev +allow +${ENFORCE_RE}$"
grep_re "permissions network corp_prod deny" "${RUN_DIR}/m6-status.txt" \
    "^ +network +corp_prod +deny +${ENFORCE_RE}$"
grep_re "permissions credentials github allow" "${RUN_DIR}/m6-status.txt" \
    "^ +credentials +github +allow +${ENFORCE_RE}$"
grep_re "permissions credentials aws_dev request" "${RUN_DIR}/m6-status.txt" \
    "^ +credentials +aws_dev +request +${ENFORCE_RE}$"
grep_re "permissions credentials aws_prod deny" "${RUN_DIR}/m6-status.txt" \
    "^ +credentials +aws_prod +deny +${ENFORCE_RE}$"
# The rule the six rows above are only instances of, and the one that keeps
# working when every one of those milestone labels changes: a row that says
# `declared` must go on to say WHERE the declaration stands. A row ending at
# the bare word `declared` is the honesty failure — it reads as a granted
# permission on a surface (spec 1.22). This sweep is what makes a future
# relabelling of the enforcement column a one-line edit above rather than a
# CI failure whose cause has to be re-diagnosed.
# Scoped to the PERMISSIONS grid on purpose: `  postgres    declared` under
# SERVICES is not bare — its section header carries the status for the whole
# block ("not started"). A permissions row has no such header to lean on.
bare_declared="$(sed -n '/^PERMISSIONS/,/^$/p' "${RUN_DIR}/m6-status.txt" 2>/dev/null |
    grep -E '^ +(filesystem|network|credentials) ' |
    grep -cE 'declared[[:space:]]*$')"
if [ "${bare_declared}" = "0" ]; then
    note "ok   no permissions row renders as a bare 'declared' — every declaration states where its enforcement stands"
else
    note "FAIL ${bare_declared} permissions row(s) render as a bare 'declared' with no enforcement status: $(sed -n '/^PERMISSIONS/,/^$/p' "${RUN_DIR}/m6-status.txt" | grep -E '^ +(filesystem|network|credentials) ' | grep -E 'declared[[:space:]]*$' | head -c 200)"
    FAILED=1
fi
if grep -qi 'organization' "${RUN_DIR}/m6-status.txt"; then
    note "FAIL status renders an organization row (unmanaged-first: never)"
    FAILED=1
else
    note "ok   no organization rows (unmanaged-first)"
fi
as_punar "${ENV_BIN}" -C "${ATLAS}" status --json \
    > "${RUN_DIR}/m6-status.json" 2>/dev/null
check_eq "punar-env status --json exit code" 0 "$?"
jq_check "status --json: shape, state, workspace mode, enforcement labels present" \
    "${RUN_DIR}/m6-status.json" \
    '.v == 1 and .project == "atlas" and .container == "punar-env-atlas"
     and .state == "running" and .workspace.mode == "read_write"
     and (.enforcement | keys | contains(["ai","credentials","network"]))
     and (.enforcement | to_entries | all(((.value | type) == "string")
            and (.value | test("^(M[0-9]+[+]?(/M[0-9]+[+]?)*|enforced|applied)$"))))'

# --- 7. agent launch honesty -------------------------------------------------
# M7 replaced the stub with a real launcher (milestone-7.md §5): without
# PUNAR_AGENT_MOCK the adapter's real executable (`claude`) is absent from
# this image, so the launch must FAIL CLEANLY rather than fake a session.
# The managed-launch happy path is m7-check's job, not this one.
as_punar "${ENV_BIN}" -C "${ATLAS}" agent claude-code \
    >/dev/null 2> "${RUN_DIR}/m6-agent-declared.txt"
agent_declared_rc=$?
if [ "${agent_declared_rc}" -ne 0 ] \
        && grep -qi 'claude' "${RUN_DIR}/m6-agent-declared.txt"; then
    note "ok   declared agent with no installed executable fails cleanly (no faked session)"
else
    note "FAIL declared-agent launch: exit ${agent_declared_rc}, stderr: $(head -c 240 "${RUN_DIR}/m6-agent-declared.txt" 2>/dev/null)"
    FAILED=1
fi
as_punar "${ENV_BIN}" -C "${ATLAS}" agent not-in-manifest \
    >/dev/null 2> "${RUN_DIR}/m6-agent-undeclared.txt"
agent_rc=$?
if [ "${agent_rc}" -ne 0 ] \
        && grep -q 'not declared' "${RUN_DIR}/m6-agent-undeclared.txt"; then
    note "ok   undeclared agent refused with the not-declared error (membership check is real)"
else
    note "FAIL undeclared agent: exit ${agent_rc}, stderr: $(head -c 240 "${RUN_DIR}/m6-agent-undeclared.txt" 2>/dev/null)"
    FAILED=1
fi

# --- 8. destroy --------------------------------------------------------------
as_punar "${ENV_BIN}" -C "${ATLAS}" destroy > "${RUN_DIR}/m6-destroy.txt" 2>&1
check_eq "punar-env destroy exit code" 0 "$?"
if as_punar podman container exists "${CONTAINER}" >/dev/null 2>&1; then
    note "FAIL container ${CONTAINER} still exists after destroy"
    FAILED=1
else
    note "ok   container ${CONTAINER} gone after destroy"
fi
POST_SHA="$(sha256sum "${ATLAS}/project-environment.yaml" 2>&1 | cut -d" " -f1)"
if [ "${POST_SHA}" = "${ATLAS_SHA}" ] && [ -f "${ATLAS}/.m6-write" ]; then
    note "ok   project files intact after destroy (manifest unchanged, .m6-write present)"
else
    note "FAIL destroy touched project files: before=${ATLAS_SHA} after=${POST_SHA} write=$([ -f "${ATLAS}/.m6-write" ] && echo present || echo missing)"
    FAILED=1
fi
as_punar "${ENV_BIN}" -C "${ATLAS}" destroy \
    > "${RUN_DIR}/m6-destroy-again.txt" 2>&1
check_eq "second destroy exit code (idempotent)" 0 "$?"
if grep -q 'nothing to destroy' "${RUN_DIR}/m6-destroy-again.txt"; then
    note "ok   second destroy reports nothing to destroy"
else
    note "FAIL second destroy output: $(head -c 240 "${RUN_DIR}/m6-destroy-again.txt" 2>/dev/null)"
    FAILED=1
fi
# Post-destroy ps appended to the same snapshot (before/after evidence).
{
    echo "--- after destroy ---"
    as_punar podman ps -a 2>&1
} >> "${RUN_DIR}/m6-podman-ps.txt"

# --- 9. verdict --------------------------------------------------------------
if [ "${FAILED}" -eq 0 ]; then
    note "PUNAR_M6_OK"
else
    note "PUNAR_M6_FAIL"
fi
# Full report onto stdout -> journal+console -> serial log, so a failed
# export still leaves the per-assertion detail (and the verdict fallback
# tools/boot-test.sh greps for) in serial.log.
cat "${REPORT}"
exit 0
