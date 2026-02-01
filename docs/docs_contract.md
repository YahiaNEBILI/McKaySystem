# Documentation Contract

Status: Canonical  
Last reviewed: 2026-02-01

This repository contains an AWS-centric FinOps engine (checkers → findings → correlation → exports).
Documentation is treated like an API: **few canonical contracts** define the truth, and all other docs must
*reference* those contracts instead of redefining them.

## Canonical documents (source of truth)

- `00_overview/glossary.md` — vocabulary and core concepts
- `01_architecture/architecture.md` — boundaries and responsibilities
- `02_pipeline/pipeline_overview.md` — end-to-end data flow
- `03_checkers/checker_contract.md` — how checkers must behave
- `04_schemas/finding_schema.md` — the Finding contract (wire + storage)
- `04_schemas/ids_and_fingerprint.md` — deterministic identity rules
- `02_pipeline/correlation/correlation_contract.md` — correlation semantics + guarantees
- `02_pipeline/correlation/rule_contract.md` — SQL rule output schema contract

If a statement conflicts with a canonical document, the canonical document wins.

## Duplication rules

Allowed duplication:
- examples
- diagrams
- tutorials and “how-to” sequences
- service-specific nuances

Disallowed duplication:
- definitions (go to the glossary)
- schemas/contracts (go to schemas)
- invariants (go to contracts)

## Document header standard

All docs start with:
- `Status: Canonical|Derived`
- `Last reviewed: YYYY-MM-DD`

Canonical docs change rarely and should be reviewed carefully.
Derived docs can evolve quickly, but must not redefine contracts.
