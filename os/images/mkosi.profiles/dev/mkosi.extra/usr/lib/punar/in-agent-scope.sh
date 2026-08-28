#!/bin/sh
# Run one command from INSIDE a managed agent session's cgroup
# (docs/development/milestone-9.md §12). Dev/CI only — started by
# m9-check.sh, never by anything a user runs.
#
# WHY THIS EXISTS. M9's central claims are about what an AI AGENT may do,
# and Punar decides that from the peer's cgroup at accept() (spec 22, the
# shared rule in punar_common::principal). The M8 exercise got its one
# agent-originated call by having punar-mock-agent make it; M9 needs to make
# several, interleaved with human resolutions, so the check has to be able
# to run an arbitrary punarctl invocation as the agent.
#
# It does that the only honest way available: it MOVES ITSELF into the
# session's real scope cgroup — the same cgroup punar-env created and the
# same one the kernel reports — and then execs. Nothing is faked: no scope
# is invented, no session id is spelled by hand, and the daemon reads the
# same /proc/<pid>/cgroup it would read for a real agent child.
#
# WHY THE CALLER MUST FORK THIS FROM THE USER MANAGER. cgroup v2 delegation
# containment permits a migration only from inside the destination's
# delegated subtree. A process started by this root system service lives in
# system.slice, whose common ancestor with the agent scope is the root
# cgroup — root-owned, so the write is refused. m9-check therefore runs this
# script through `systemd-run --user`, which places it under
# user@<uid>.service where the migration is permitted. That is the same M7
# hard lesson punar-env's own launch path rests on.
#
# Usage: in-agent-scope.sh <scope-cgroup-procs-path> <command> [args...]
# Exit codes: the command's own, except 97 (could not join the cgroup) and
# 98 (usage) — chosen outside punarctl's documented 0..5 range so a
# harness failure can never be mistaken for a daemon verdict.
set -u

SCOPE_PROCS="${1:-}"
if [ -z "${SCOPE_PROCS}" ] || [ "$#" -lt 2 ]; then
    echo "in-agent-scope.sh: usage: <scope-cgroup-procs> <command> [args...]" >&2
    exit 98
fi
shift

if ! echo $$ > "${SCOPE_PROCS}" 2>/dev/null; then
    echo "in-agent-scope.sh: could not join ${SCOPE_PROCS} (cgroup delegation refused the migration)" >&2
    exit 97
fi

exec "$@"
