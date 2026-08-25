# Architecture Decisions

Index of Architecture Decision Records (ADRs) for Punar.

## Process

Significant, hard-to-reverse technical choices are recorded as ADRs in
[`docs/architecture/adr/`](docs/architecture/adr/), numbered sequentially
(`ADR-NNN-short-title.md`) and written from the template at
[`docs/architecture/adr/TEMPLATE.md`](docs/architecture/adr/TEMPLATE.md)
(Context / Options considered / Decision / Consequences / Revisit triggers).

An ADR moves through statuses: `In progress` (being drafted or evaluated),
`Proposed` (drafted, awaiting ratification), `Accepted`, `Superseded by ADR-NNN`, or `Rejected`. Accepted ADRs are not
edited to say something different; a new ADR supersedes them. Each new ADR
gets one row in the index below.

## Index

| ADR | Title | Status | Date |
| --- | --- | --- | --- |
| [ADR-001](docs/architecture/adr/ADR-001-distribution-substrate.md) | Distribution Substrate | Accepted | 2026-08-24 |
| [ADR-002](docs/architecture/adr/ADR-002-first-party-binaries.md) | Distribution of First-Party Binaries | Accepted | 2026-08-25 |
| [ADR-003](docs/architecture/adr/ADR-003-ab-slots-over-snapper.md) | A/B root slots as the rollback mechanism (supersedes ADR-001's MVP snapper choice) | Accepted | 2026-08-25 |
