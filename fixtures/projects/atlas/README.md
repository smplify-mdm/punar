# Atlas project fixtures (hero demo, spec section 75 steps 3-4 and 9)

Project fixtures for the mocked Acme "Atlas" project used by the MVP hero demo
(`docs/product/SPEC_v0.2.md` section 75) and Milestone 6 ("Deliver `punar-env`,
Podman/devcontainer, and Atlas fixture").

This directory is hero-demo-oriented and does not follow the
`fixtures/<domain>/{valid,invalid}/` layout; every file here is a VALID document.
File-to-schema mapping for the validator:

| File | Schema | Provenance |
| --- | --- | --- |
| `project-environment.yaml` | `schemas/project/project-environment.json` | Spec section 17 YAML example, byte-verbatim below the one provenance comment line |
| `project-network-policy.json` | `schemas/network/project-network-policy.json` | Spec section 36 ATLAS table (internet allow, corp_dev allow, corp_prod deny); same content as `fixtures/network/valid/project-network-policy.atlas.json` |

YAML fixtures are converted to JSON before validation (see `schemas/README.md`).
