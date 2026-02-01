# Determinism

Status: Canonical  
Last reviewed: 2026-02-01

The platform treats **determinism as a hard requirement**.

## Why

- stable deduplication across runs
- stable fingerprints / issue keys
- reproducible exports (Parquet + JSON)
- CI tests can guard against regressions

## Determinism principles

- Iterate collections in a stable order (sort by ID/name/ARN).
- When serializing JSON (breakdowns/metrics), use stable ordering and formatting.
- Fingerprints are computed from normalized content (see `04_schemas/ids_and_fingerprint.md`).
- Correlation must be order-independent (shuffled inputs produce identical outputs).

## What is not deterministic

When the underlying cloud data changes (new metrics datapoint, new tag, AWS eventually consistent APIs),
outputs can change. Determinism here means:

> identical observed input → identical output.
