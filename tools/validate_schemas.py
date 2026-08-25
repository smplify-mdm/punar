#!/usr/bin/env python3
"""Punar contract-layer validation harness.

Checks, in order:
  1. Every schema under schemas/**/ is itself a valid JSON Schema draft 2020-12
     document (Draft202012Validator.check_schema).
  2. Every example under schemas/**/examples/ validates against its schema.
  3. Every fixture under fixtures/**/ validates against its schema; files in an
     invalid/ directory must FAIL validation (and the harness fails if they pass).
  4. Every staged runtime data file under the desktop image's
     /usr/share/punar/agents tree (AI agent adapter definitions, M7) validates
     against its schema -- the adapters are data the image ships, so the schema
     guards them exactly like a fixture (docs/development/milestone-7.md 5.4).

Refs (e.g. to schemas/common/defs.json) resolve from the local schemas/ tree via
a referencing.Registry keyed by each schema's $id -- never over the network
(schemas/README.md: the $id host is a namespace, not a live URL).

Document-to-schema mapping is the explicit MANIFEST below (explicit beats magic).
Entries are (glob-pattern, schema-path-or-None) pairs matched against
repo-relative POSIX paths; FIRST match wins; None means "known file, no schema,
skip". A README.md anywhere is skipped implicitly. Any .json/.yaml/.yml document
that matches no manifest entry is an ERROR: extend the manifest when adding a
domain. Mapping sources: fixtures/README.md ("Fixture-to-schema mapping"),
fixtures/agents/README.md and fixtures/projects/atlas/README.md tables.

Run via tools/validate-schemas.sh (Docker; the host has no local jsonschema).
Exit status: 0 iff every check passes.
"""

from __future__ import annotations

import fnmatch
import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

REPO = Path(__file__).resolve().parent.parent
SCHEMAS = REPO / "schemas"
FIXTURES = REPO / "fixtures"
# Staged runtime data shipped inside the desktop image (M7 adapters, signature
# heuristics). Validated in place so the file the image ships is the file the
# schema checked -- no copy to drift.
STAGED_AGENTS = REPO / "os/images/mkosi.profiles/desktop/mkosi.extra/usr/share/punar/agents"

# ---------------------------------------------------------------------------
# MANIFEST: (glob over repo-relative posix path, schema repo-relative path).
# First match wins. Schema None => deliberately unvalidated seed file.
# ---------------------------------------------------------------------------
MANIFEST: list[tuple[str, str | None]] = [
    # --- schemas/**/examples/ ------------------------------------------------
    ("schemas/ai-agent/examples/agent-definition*", "schemas/ai-agent/agent-definition.json"),
    ("schemas/ai-agent/examples/ledger-summary*", "schemas/ai-agent/ledger-summary.json"),
    ("schemas/ai-agent/examples/registry-record*", "schemas/ai-agent/registry-record.json"),
    ("schemas/audit/examples/approval.*", "schemas/audit/approval.json"),
    ("schemas/audit/examples/audit-event.*", "schemas/audit/audit-event.json"),
    ("schemas/capability/examples/*", "schemas/capability/capability-descriptor.json"),
    ("schemas/desired-state/examples/*", "schemas/desired-state/desired-state.json"),
    ("schemas/network/examples/network-zone*", "schemas/network/network-zone.json"),
    ("schemas/network/examples/project-network-policy*", "schemas/network/project-network-policy.json"),
    ("schemas/policy/examples/ai-policy-*", "schemas/policy/ai-policy.json"),
    ("schemas/policy/examples/model-governance-*", "schemas/policy/model-governance.json"),
    ("schemas/policy/examples/policy-source-*", "schemas/policy/policy-source.json"),
    ("schemas/project/examples/*", "schemas/project/project-environment.json"),
    ("schemas/workspace/examples/*", "schemas/workspace/workspace-state.json"),
    # --- fixtures/<domain>/{valid,invalid}/ ---------------------------------
    ("fixtures/ai-agent/*/agent-definition.*", "schemas/ai-agent/agent-definition.json"),
    ("fixtures/ai-agent/*/ledger-summary.*", "schemas/ai-agent/ledger-summary.json"),
    ("fixtures/ai-agent/*/registry-record.*", "schemas/ai-agent/registry-record.json"),
    ("fixtures/audit/*/approval.*", "schemas/audit/approval.json"),
    ("fixtures/audit/*/audit-event.*", "schemas/audit/audit-event.json"),
    ("fixtures/capability/*/*", "schemas/capability/capability-descriptor.json"),
    ("fixtures/desired-state/*/*", "schemas/desired-state/desired-state.json"),
    ("fixtures/network/*/network-zone.*", "schemas/network/network-zone.json"),
    ("fixtures/network/*/project-network-policy.*", "schemas/network/project-network-policy.json"),
    ("fixtures/policy/*/ai-policy-*", "schemas/policy/ai-policy.json"),
    ("fixtures/policy/*/model-governance-*", "schemas/policy/model-governance.json"),
    ("fixtures/policy/*/policy-source-*", "schemas/policy/policy-source.json"),
    ("fixtures/project/*/project-environment.*", "schemas/project/project-environment.json"),
    ("fixtures/workspace/*/workspace-state.*", "schemas/workspace/workspace-state.json"),
    # --- seed data: fixtures/agents/ (fixtures/agents/README.md table) ------
    ("fixtures/agents/claude-code.registry-record.json", "schemas/ai-agent/registry-record.json"),
    ("fixtures/agents/claude-code.json", "schemas/ai-agent/agent-definition.json"),
    ("fixtures/agents/unknown-agent/foo-agent.json", "schemas/ai-agent/agent-definition.json"),
    ("fixtures/agents/unknown-agent/registry-record.json", "schemas/ai-agent/registry-record.json"),
    ("fixtures/agents/unknown-agent/ledger-summary.json", "schemas/ai-agent/ledger-summary.json"),
    # --- seed data: fixtures/organizations/ (fixtures/README.md table) ------
    ("fixtures/organizations/acme/org.json", None),  # no organization schema yet
    ("fixtures/organizations/acme/desired-state-*.json", "schemas/desired-state/desired-state.json"),
    ("fixtures/organizations/acme/policy-source-*.json", "schemas/policy/policy-source.json"),
    # --- seed data: fixtures/policies/ (fixtures/README.md table) -----------
    ("fixtures/policies/ai-policy-*.yaml", "schemas/policy/ai-policy.json"),
    ("fixtures/policies/policy-source-*.json", "schemas/policy/policy-source.json"),
    # --- staged runtime data: desktop image /usr/share/punar/agents (M7) ----
    ("os/images/mkosi.profiles/desktop/mkosi.extra/usr/share/punar/agents/adapters/*.json",
     "schemas/ai-agent/agent-definition.json"),
    # Detection heuristics are an internal input, versioned by review rather
    # than by schema (milestone-7.md section 7.1) -- known file, no schema.
    ("os/images/mkosi.profiles/desktop/mkosi.extra/usr/share/punar/agents/signatures/*.json", None),
    # The M8 comm -> process-class table is the same kind of thing: an
    # internal heuristic input, versioned by review, deliberately without a
    # schema (milestone-8.md section 3.2). It is STAGED here from
    # crates/punar-agentd/data by scripts/container-build.sh -- the daemon
    # compiles the same file in as its fallback, so the two cannot drift.
    ("os/images/mkosi.profiles/desktop/mkosi.extra/usr/share/punar/agents/process-classes.json", None),
    # --- seed data: fixtures/projects/atlas/ (its README.md table) ----------
    ("fixtures/projects/atlas/project-environment.yaml", "schemas/project/project-environment.json"),
    ("fixtures/projects/atlas/project-network-policy.json", "schemas/network/project-network-policy.json"),
]

DOC_SUFFIXES = {".json", ".yaml", ".yml"}


def load_doc(path: Path):
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def rel(path: Path) -> str:
    return path.relative_to(REPO).as_posix()


def map_schema(relpath: str) -> tuple[bool, str | None]:
    """Return (matched, schema_relpath_or_None)."""
    for pattern, schema in MANIFEST:
        if fnmatch.fnmatch(relpath, pattern):
            return True, schema
    return False, None


def main() -> int:
    failures = 0
    schema_count = 0
    doc_count = 0

    def report(ok: bool, label: str, detail: str = "") -> None:
        nonlocal failures
        mark = "PASS" if ok else "FAIL"
        print(f"[{mark}] {label}" + (f"\n       {detail}" if detail else ""))
        if not ok:
            failures += 1

    # -- 1. Load every schema, check it against the metaschema, build registry
    schema_paths = sorted(
        p for p in SCHEMAS.rglob("*.json") if "examples" not in p.relative_to(SCHEMAS).parts
    )
    registry = Registry()
    schemas: dict[str, dict] = {}  # repo-relative path -> schema doc
    for sp in schema_paths:
        label = f"schema  {rel(sp)}"
        try:
            doc = json.loads(sp.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(doc)
        except Exception as exc:  # noqa: BLE001 - report and continue
            report(False, label, f"{type(exc).__name__}: {exc}")
            continue
        schema_count += 1
        sid = doc.get("$id")
        if not sid:
            report(False, label, "schema has no $id")
            continue
        registry = registry.with_resource(sid, Resource.from_contents(doc))
        schemas[rel(sp)] = doc
        report(True, label)

    validators: dict[str, Draft202012Validator] = {}

    def validator_for(schema_rel: str) -> Draft202012Validator | None:
        if schema_rel not in validators:
            doc = schemas.get(schema_rel)
            if doc is None:
                return None
            validators[schema_rel] = Draft202012Validator(doc, registry=registry)
        return validators[schema_rel]

    # -- 2 & 3. Validate examples and fixtures per the manifest
    doc_paths = sorted(
        [p for p in SCHEMAS.rglob("examples/*") if p.suffix in DOC_SUFFIXES]
        + [p for p in FIXTURES.rglob("*") if p.is_file() and p.suffix in DOC_SUFFIXES]
        + [p for p in STAGED_AGENTS.rglob("*") if p.is_file() and p.suffix in DOC_SUFFIXES]
    )
    for dp in doc_paths:
        relpath = rel(dp)
        matched, schema_rel = map_schema(relpath)
        if not matched:
            report(False, f"unmapped {relpath}", "no MANIFEST entry -- add one (or map to None to skip)")
            continue
        if schema_rel is None:
            print(f"[SKIP] {relpath} (no schema by design)")
            continue
        expect_invalid = "invalid" in Path(relpath).parts
        label = f"{'invalid' if expect_invalid else 'doc'}     {relpath}"
        validator = validator_for(schema_rel)
        if validator is None:
            report(False, label, f"mapped schema {schema_rel} missing or failed metaschema check")
            continue
        try:
            instance = load_doc(dp)
        except Exception as exc:  # noqa: BLE001
            report(False, label, f"unparseable: {type(exc).__name__}: {exc}")
            continue
        doc_count += 1
        errors = sorted(validator.iter_errors(instance), key=lambda e: e.json_path)
        if expect_invalid:
            if errors:
                report(True, label, f"fails as expected: {errors[0].json_path}: {errors[0].message[:120]}")
            else:
                report(False, label, "expected to FAIL validation but passed")
        else:
            if errors:
                first = errors[0]
                report(False, label, f"{first.json_path}: {first.message[:300]} (schema {schema_rel})")
            else:
                report(True, label)

    print(
        f"\n{schema_count} schemas metaschema-checked, {doc_count} documents validated "
        f"({'ALL PASS' if failures == 0 else f'{failures} FAILURE(S)'})"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
