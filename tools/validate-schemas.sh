#!/usr/bin/env bash
# Validate every Punar schema and fixture in a Docker container.
# The host needs no local python-jsonschema/node; see tools/validate_schemas.py.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

docker run --rm -v "${REPO}:/w" -w /w python:3.12-slim sh -c \
  "pip install -q jsonschema pyyaml referencing && \
   python tools/validate_schemas.py && \
   python tests/unit/install-plan-schema-test.py"
