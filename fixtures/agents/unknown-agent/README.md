# Unknown-agent (shadow AI) fixture

This fixture is DATA describing a SIMULATED threat for shadow-AI detection tests
(spec sections 23, 25, 75 step 10): it contains no actual executable logic, only
metadata about a fake suspicious binary named `foo-agent` at `~/Downloads/foo-agent`
that contacts `api.foo.ai` and reads the Atlas source repository (spec section 25
"UNKNOWN AI ACTIVITY" example). `api.foo.ai` is a fictional domain.

- `foo-agent.json` — agent-definition consumed by the detection test harness; the
  simulation metadata (executable path, network destination, expected
  classification) lives in `adapter_config`, the schema's sanctioned free-form
  extension point, because agent definitions model KNOWN agents and have no
  fields for detection observations.
- `registry-record.json` — the registry record the detector is expected to emit:
  classification `unknown` (spec section 19.1 UNKNOWN / SUSPECTED); `version`
  `"unknown"` and `environment` `"host"` are sentinels since a suspicious binary
  has no reported version and runs outside any managed environment.
- `ledger-summary.json` — the expected Access Ledger summary backing the section
  25 "Access:" lines (Atlas repository, api.foo.ai) with one Level 4
  `unknown_ai_execution` security event, retrievable by the mocked authorized
  Smplify query in demo step 10.
