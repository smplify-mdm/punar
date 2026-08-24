# Agent fixtures (hero demo, spec section 75 steps 5 and 10)

AI-agent fixtures for the MVP hero demo (`docs/product/SPEC_v0.2.md` section 75):
the managed Claude Code session (step 5) and the shadow-AI "unknown agent"
simulation (step 10; Milestone 10 "fixture unknown agent").

This directory is hero-demo-oriented and does not follow the
`fixtures/<domain>/{valid,invalid}/` layout; every file here is a VALID document.
File-to-schema mapping for the validator:

| File | Schema |
| --- | --- |
| `claude-code.json` | `schemas/ai-agent/agent-definition.json` |
| `claude-code.registry-record.json` | `schemas/ai-agent/registry-record.json` |
| `unknown-agent/foo-agent.json` | `schemas/ai-agent/agent-definition.json` |
| `unknown-agent/registry-record.json` | `schemas/ai-agent/registry-record.json` |
| `unknown-agent/ledger-summary.json` | `schemas/ai-agent/ledger-summary.json` |

`claude-code.registry-record.json` reproduces the spec section 19.2 example
values verbatim (`agt_123`, `alice@acme.com`, `atlas`, `atlas-dev-42`, managed);
the spec's `"..."` placeholder for `started_at` is replaced with a concrete
RFC 3339 timestamp and `version` stays literally `"x.y.z"`, matching
`fixtures/ai-agent/valid/registry-record.spec-19-2.json`.

See `unknown-agent/README.md` for the shadow-AI simulation notes.
