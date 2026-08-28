# Punar Schema Conventions

Contract layer for Punar (Smplify). Every schema in this tree follows the conventions below. The authoritative behavioral spec is `docs/product/SPEC_v0.2.md`; where a schema and the spec's examples disagree, the spec wins and the schema is a bug.

## Draft and `$id`

- All schemas are **JSON Schema draft 2020-12** (`"$schema": "https://json-schema.org/draft/2020-12/schema"`).
- Every schema declares an `$id` of the form:

  ```
  https://schemas.punar.dev/v1alpha1/<domain>/<name>.json
  ```

  where `<domain>` is the directory under `schemas/` (`common`, `ai-agent`, `audit`, `capability`, `desired-state`, `install`, `network`, `policy`, `project`, `update`) and `<name>` is the file basename. Example: `https://schemas.punar.dev/v1alpha1/audit/audit-event.json`.
- The `$id` host is a namespace, not a live URL. Validators must resolve refs from the local `schemas/` tree (preload/registry), never over the network.

## Versioning

- Everything is **v1alpha1**. Alpha means fields may still be added compatibly without ceremony.
- **Breaking changes bump the version** (`v1alpha1` -> `v1alpha2` -> ... -> `v1beta1` -> `v1`): renaming/removing a field, tightening a type or pattern, narrowing an enum, adding a new `required` field. A version bump creates a new `/v1alpha2/` path segment in `$id` (and a new directory tree); old versions are not edited in place.
- YAML document kinds carry their spec `apiVersion` strings **verbatim** and these are independent of the schema-tree version:
  - `apiVersion: smplify.io/v1alpha1` for `kind: DeviceDesiredState` (spec section 38)
  - `apiVersion: punar.dev/v1alpha1` for `kind: ProjectEnvironment` (spec section 17)

  Schemas must validate these exact strings (use `const`).

## Naming: the deliberate asymmetry

The spec uses two naming styles on purpose. **Preserve both; do not "normalize".**

1. **YAML configuration documents use camelCase** for field names. These are the human-authored, Kubernetes-flavored manifests: `DeviceDesiredState`, `ProjectEnvironment`, application policy, AI model governance. Examples straight from the spec: `diskEncryption`, `secureBoot`, `allowUserInstall`, `privateRelay`, `unknownEndpoints`, `cloudModels`. (Single-word keys like `firewall`, `required`, `channel` are unaffected.) Note the spec still uses snake_case for a few *values and leaf keys inside manifests* where it does so explicitly (e.g. `read_write`, `corp_dev`, `aws_prod`, `non_compliant`); copy the spec's examples exactly rather than applying a blanket rule.
2. **JSON runtime records use snake_case** for field names. These are machine-emitted records: AI Agent Registry entries (`session_id`, `process_id`, `started_at`), approval gates (`approval_id`, `expires_at`), capability registry entries (`current_state`, `desired_state`, `requires_reboot`, `managed_by`), audit events (`event_id`, `device_id`, `user_id`, `agent_session_id`, `project_id`, `policy_ids`).

Rule of thumb: if the document has an `apiVersion`/`kind` header, it is camelCase YAML; if it is a record produced by a daemon (registry, ledger, audit, approval), it is snake_case JSON.

Schema `$defs` names and fixture filenames are snake_case / kebab-case respectively.

## Enum and value conventions

- Enum values are lowercase snake_case: `ai_agent`, `approval_required`, `non_compliant`.
- Decisions are `allow | deny | approval_required` (spec section 20). Manifest credential grants additionally use the value `request` in spec examples (sections 17, 20); model that as a manifest-local enum (`allow | deny | request`), not by widening the shared `decision` def.
- Capability ids are dotted snake_case paths (`security.firewall`, `system.install_package`). The camelCase path in `punarctl policy explain security.diskEncryption` is a YAML config path, not a capability id.
- Timestamps are RFC 3339 strings. Because `format` is annotation-only in draft 2020-12's default vocabulary, the shared `timestamp` def also asserts a pattern.
- Prefixed ids: `dev_*` devices, `agt_*` agent sessions, `apr_*` approvals, `evt_*` audit events.

## Shared definitions

`schemas/common/defs.json` (`$id: https://schemas.punar.dev/v1alpha1/common/defs.json`) holds the cross-domain `$defs`. Reference them by absolute `$id`, e.g.:

```json
{ "$ref": "https://schemas.punar.dev/v1alpha1/common/defs.json#/$defs/decision" }
```

| `$def` | Meaning | Spec |
| --- | --- | --- |
| `principal_kind` | `device, human, organization, project, application, ai_agent, service` | 18 |
| `decision` | `allow, deny, approval_required` | 20 |
| `capability_id` | dotted snake_case path, pattern-asserted | 28, 41 |
| `device_id` | `^dev_[A-Za-z0-9]+$` | 38, 53 |
| `agent_session_id` | `^agt_[A-Za-z0-9]+$` | 19.2, 28, 53 |
| `approval_id` | `^apr_[A-Za-z0-9]+$` | 28 |
| `event_id` | `^evt_[A-Za-z0-9]+$` | 53 |
| `timestamp` | RFC 3339, `format: date-time` + pattern | throughout |
| `risk` | `low, medium, high` | 28, 41 |
| `agent_classification` | `managed, observed, unknown` | 19.1 |
| `compliance_state` | `compliant, non_compliant, remediating, unknown, unsupported, exception` | 52 |

## Schema strictness

- Domain schemas set `"additionalProperties": false` on record objects so drift from the spec is caught early (alpha contracts should fail loudly).
- Mark as `required` exactly the fields present in the spec's examples unless the spec text says a field is optional.
- Give every schema a `title` and a `description` citing the spec section.

## Validation

- `tools/validate-schemas.sh` (written by a later agent) validates every schema against the 2020-12 metaschema and every fixture under `fixtures/` against its schema. The host has no local python-jsonschema/node; validation runs in a Docker container. YAML fixtures are converted to JSON before validation.
- Fixtures live in `fixtures/<domain>/`, with both `valid/` and `invalid/` cases where practical.

## Rust reconciliation (deferred)

The Rust types in `crates/punar-common` are being written by a concurrent workflow and are **not yet generated from or checked against these schemas**. Reconciling them (serde rename rules matching the camelCase/snake_case asymmetry, enum mirrors of the shared defs) is **Milestone 3** work. Do not hand-sync them now.
