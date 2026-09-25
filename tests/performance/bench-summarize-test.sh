#!/usr/bin/env bash
# The benchmark harness's host side against canned inputs: the D1 rule and
# the report (tools/bench/bench_report.py), the parser's edge cases
# (bench_parse.py), the privacy summary on a synthetic packet capture
# (pcap_summary.py), nmap parsing (portscan.py), the dispatch plan
# (bench_plan.py), the Omarchy lane's CIDATA rendering and stock restore, and
# where the release image's test account is read from. Standard library
# Python only; the CIDATA case is skipped without openssl.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
command -v python3 >/dev/null 2>&1 || { echo "bench-summarize-test: FAIL: python3 is required" >&2; exit 1; }
python3 -B "${REPO_ROOT}/tests/performance/bench_summarize_test.py"
echo "PUNAR_BENCH_SUMMARIZE_TEST_OK"
