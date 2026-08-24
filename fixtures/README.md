# Punar Fixtures

Deterministic mock data for tests and the MVP hero demo (spec section 75). The MVP has no real Smplify control plane (spec section 49: "MVP uses a mocked Smplify control plane"); these files stand in for it.

**Identifiers are load-bearing.** Tests, the mock control plane, and the hero demo script reference `acme`, `dev_123`, `eng-baseline-v12`, `engineering-standard`, `eng-ai-v3`, `atlas`, etc. by exact value — they come from the spec's own examples (sections 38, 40, 53). Do not rename them without updating every consumer.

## Layout

Two kinds of directories:

1. **Schema-domain fixtures** — `<domain>/valid/` and `<domain>/invalid/` cases exercising the schemas in `schemas/<domain>/` (`ai-agent`, `audit`, `capability`, `desired-state`, `network`, `policy`). Valid files must validate; invalid files must fail for the one reason their filename states.
2. **Mock control-plane seed data** — `organizations/` and `policies/`, consumed by enrollment (spec section 49), policy tests, and the hero demo. All seed files are valid documents.

Empty directories are placeholders for future domains.

## Fixture-to-schema mapping

For schema-domain directories, the fixture directory names the schema domain and the filename's longest schema-basename prefix names the schema file (e.g. `policy/valid/ai-policy-*.yaml` -> `schemas/policy/ai-policy.json`; the `audit/` and `network/` domains use the prefix before the first `.`). Seed directories do not correspond to a schema domain, so their mapping is explicit:

| File | Schema |
| --- | --- |
| `organizations/acme/org.json` | none (see below) |
| `organizations/acme/desired-state-eng-baseline-v12.json` | `schemas/desired-state/desired-state.json` |
| `organizations/acme/policy-source-eng-baseline-v12.json` | `schemas/policy/policy-source.json` |
| `policies/ai-policy-engineering-standard.yaml` | `schemas/policy/ai-policy.json` |
| `policies/policy-source-eng-ai-v3.json` | `schemas/policy/policy-source.json` |

`org.json` is the mocked organization descriptor for enrollment discovery (id, name, mock control-plane endpoint, and pointers to the org's baseline and AI policy). No organization schema exists yet in `schemas/` — the validator must skip it; if an organization schema is added later, wire it into this table.

## The Acme seed

- `organizations/acme/desired-state-eng-baseline-v12.json` — the Acme engineering baseline `DeviceDesiredState`: the spec section 38 example plus the section 44.4 firewall defaults (inbound deny / outbound allow). `metadata.device` is pinned to `dev_123` (the device id used by spec sections 38 and 53) because the desired-state schema requires a device id; the mock control plane substitutes the enrolling device's id at enrollment time, and tests expect `dev_123`.
- `organizations/acme/policy-source-eng-baseline-v12.json` — provenance envelope binding policy id `eng-baseline-v12` and source name `Acme Engineering Baseline` (both verbatim from the spec section 40 explain output) to the baseline. It carries no embedded `policy` payload: the body is the sibling desired-state file, referenced by policy id, so there is a single source of truth.
- `policies/ai-policy-engineering-standard.yaml` — the `engineering-standard` AI authority policy the baseline references via `spec.ai.policy`. The body is the spec section 20 example verbatim.
- `policies/policy-source-eng-ai-v3.json` — provenance envelope giving that policy its id `eng-ai-v3`, the id cited by the spec section 53 audit example (`"policy_ids": ["eng-ai-v3"]`). As above, the body lives in the sibling YAML file. Both Acme envelopes use `source_kind: organization_baseline` / `precedence_rank: 2` (spec section 39's "Organization Mandatory Policy" rung, matching `policy/valid/policy-source-org-baseline.json`).

## Validation

Every file with a schema in the table above (and everything under the schema-domain `valid/` directories) must validate against its schema; `tools/validate-schemas.sh` runs the checks in Docker (no local jsonschema on hosts), converting YAML to JSON first and resolving `$ref`s from the local `schemas/` tree by `$id` — never over the network. Conventions: `schemas/README.md`.
