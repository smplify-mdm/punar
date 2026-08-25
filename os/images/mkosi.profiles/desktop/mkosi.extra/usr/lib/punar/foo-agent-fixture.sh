#!/bin/sh
# foo-agent-fixture.sh — the dev/CI shadow-AI DETECTION fixture
# (docs/development/milestone-7.md §7.1/§12; SPEC sections 23, 25, 75 step 10).
#
# fixtures/agents/unknown-agent/foo-agent.json describes a suspicious agent
# binary at ~/Downloads/foo-agent. Detection needs a REAL process to find —
# a heuristic asserted against a process that does not exist proves nothing —
# so m7-check installs THIS script as /home/punar/Downloads/foo-agent (0755,
# punar-owned) and starts it as the punar user. punar-agentd's /proc walk
# then matches the `downloads-foo-agent` pattern from
# /usr/share/punar/agents/signatures/suspected.json and classifies it
# UNKNOWN · SUSPECTED.
#
# It is deliberately, verifiably innocuous: it prints what it is and then
# sleeps until signaled. No network (the CI VM has none), no files written,
# no AI anything. The name is the entire point — the fixture exists to prove
# that Punar's detection is a *heuristic over what a program looks like*, not
# knowledge of what a program does. That honesty is the M7 claim (spec 23:
# "Do not claim perfect detection").
#
# The block is `wait` on a background sleep — a blocking wait, never a
# polling loop (SPEC section 6.3).
#
# NOTE for m7-check (punar-agentd's cmdline retention rule): the walker
# keeps only ABSOLUTE path arguments, so this must be started either
# directly (shebang; argv[0] is the absolute script path) or as
# `sh /home/punar/Downloads/foo-agent`. Starting it from inside the
# directory as `sh ./foo-agent` would present a relative argv and match
# nothing.

set -u

echo "punar dev/CI fixture: shadow-AI DETECTION stand-in, not an AI agent"
echo "Path: $0"
echo "Behavior: sleeps until SIGTERM/SIGINT. It performs no AI work, opens no"
echo "network connections, and writes no files."

trap 'exit 0' TERM INT
sleep infinity &
wait $!
