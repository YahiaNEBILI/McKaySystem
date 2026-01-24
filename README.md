# FinOps SaaS – Architecture & Pipeline Overview

This repository contains a **SaaS-grade FinOps engine** designed to be:

- infra-native (resource-level first, not CUR-only)
- deterministic and testable
- scalable from local DuckDB to Iceberg/Trino
- production-ready, while remaining hackable

This README reflects the **current state of the system**, including:

- multi-region execution
- correlation engine
- CUR normalization & cost enrichment
- stress-testing and determinism guarantees
- smart export for a Flask UI

---

## High-level architecture

```
┌────────────┐
│  Checkers  │  (infra-native signals)
└─────┬──────┘
      │
      ▼
┌────────────┐
│   Runner   │  (multi-region orchestration)
└─────┬──────┘
      │
      ▼
┌────────────┐
│ Contracts  │  (validation, canonicalization, IDs)
└─────┬──────┘
      │
      ▼
┌────────────┐
│ Parquet IO │  (Arrow-typed, partitioned)
└─────┬──────┘
      │
      ├──────────────┐
      ▼              ▼
┌────────────┐  ┌───────────────┐
│ Correlator │  │ CUR Enrichment│
│ (DuckDB)   │  │ (actual cost) │
└─────┬──────┘  └──────┬────────┘
      │               │
      └──────┬────────┘
             ▼
        ┌──────────┐
        │ DuckDB   │  (analytics layer)
        └────┬─────┘
             ▼
        ┌──────────┐
        │ JSON     │  (smart export)
        └────┬─────┘
             ▼
        ┌──────────┐
        │ Flask UI │
        └──────────┘
```

---

## Repository layout (current)

```
.
├── runner.py                    # Main orchestration entrypoint
├── contracts/                   # Canonical schema & validation
│   ├── schema.py                # Arrow schema (source of truth)
│   ├── finops_contracts.py      # Canonicalization & hashing
│   ├── storage_cast.py          # Wire → Arrow casting
│   └── finops_checker_pattern.py
│
├── checks/                      # FinOps checkers (signals)
│   └── aws/
│       ├── ec2_graviton.py
│       ├── ebs_storage.py
│       ├── rds_snapshots_cleanup.py
│       └── ...
│
├── pipeline/
│   ├── writer_parquet.py        # Typed, partitioned Parquet writer
│   ├── correlation/             # Correlation engine (DuckDB SQL)
│   │   ├── engine.py
│   │   ├── ruleset.py
│   │   └── correlate_findings.py
│   ├── cur/                     # CUR pipeline
│   │   ├── normalize_cur.py     # CUR → cost_facts
│   │   └── cost_enrich.py       # Findings ← actual costs
│   ├── export_json.py           # DuckDB → JSON (smart export)
│   └── __init__.py
│
├── tests/                       # Extensive pytest suite
│   ├── test_writer_parquet.py
│   ├── test_storage_cast.py
│   └── ...
│
├── data/
│   ├── finops_findings/          # Raw findings (Parquet)
│   ├── finops_findings_correlated/
│   ├── finops_findings_enriched/
│   ├── raw_cur/                  # Raw CUR parquet inputs
│   └── cur_facts/                # Normalized cost facts
│
├── webapp_data/                  # Flask-consumable JSON
│   ├── findings.json
│   ├── summary.json
│   ├── top_savings.json
│   ├── correlated_findings.json
│   └── coverage.json
│
├── tools/                       # Extensive pytest suite
│   ├── stress/  
│   │   └── stress_engine.py     # Determinism & scale tests
│
├── README.md
└── pyproject.toml
```

---

## Core design principles

### 1. Infra-native first (not CUR-first)

- Findings are emitted **from infrastructure APIs** (EC2, RDS, S3, …)
- CUR is **enrichment**, not the primary signal
- This avoids CUR latency and missing-resource blind spots

---

### 2. Deterministic identity & reproducibility

Each finding has:

- `fingerprint` → logical identity (same issue, same scope)
- `finding_id` → storage identity (stable / per-run / per-day)

Guarantees:
- idempotent re-runs
- safe correlation
- stress-testing under shuffle / reordering

---

### 3. Wire vs Storage separation

| Layer | Purpose | Characteristics |
|-----|--------|-----------------|
| Wire | Runtime objects | permissive, strings |
| Storage | Parquet | strict Arrow schema |

Every finding **must** pass contract validation and storage casting before persistence.

---

## Correlation engine

The correlation engine:

- runs **after** raw findings are written
- uses DuckDB SQL rules
- emits **meta-findings** (still first-class findings)

Characteristics:
- deterministic SQL validation
- rule-scoped prefiltering
- source fingerprint tracking
- correlation findings can be enriched with cost later

Correlation output:
```
data/finops_findings_correlated/
```

---

## CUR pipeline (actual cost attribution)

### 1. Raw CUR input

Expected location:
```
data/raw_cur/**/*.parquet
```

Files may be:
- Athena CTAS outputs
- Glue job outputs
- any Parquet with standard CUR columns

---

### 2. Normalization (`normalize_cur.py`)

Transforms CUR into a stable analytical table:

```
cur_facts
  - tenant_id
  - account_id
  - region
  - service
  - resource_id
  - usage_start
  - cost_primary
  - tags (MAP)
```

Output:
```
data/cur_facts/
```

Schema drift tolerant, partitioned, deterministic.

---

### 3. Cost enrichment (`cost_enrich.py`)

Enriches findings with:
- `actual.cost_7d / 30d / mtd / prev_month`
- attribution method & confidence

Matching tiers:
1. Exact resource match (high confidence)
2. Scoped roll-up (fallback)

Output:
```
data/finops_findings_enriched/
```

CUR is **optional**: the pipeline never fails if CUR is missing.

---

## Stress testing & determinism

The test suite validates:

- deterministic outputs under input shuffle
- Arrow schema merge safety
- large dataset behavior
- correlation id stability

This ensures the engine behaves correctly under SaaS-scale workloads.
To run the stress test : 

```bash
python tools.stress.stress_engine --n 200000 --workdir .stress --clean
```

---

## Export layer (Flask-ready)

`export_json.py`:

- reads Parquet via DuckDB
- **auto-selects enriched dataset if present**
- exports:
  - findings.json
  - summary.json
  - top_savings.json
  - correlated_findings.json
  - coverage.json (cost availability)

This fully decouples backend evolution from the UI.

---

## Typical end-to-end run

```bash
python runner.py --tenant acme --workspace prod
python export_findings.py
```

If CUR data exists, costs appear automatically. If not, the UI degrades gracefully.
Flow is :
data/raw_cur/**/*.parquet
        ↓ normalize
data/cur_facts/**/*.parquet
        ↓ enrich
data/finops_findings_enriched/**/*.parquet

---

## Why this architecture scales

- Arrow + Parquet → analytics-grade
- DuckDB → fast local compute
- Deterministic IDs → SaaS lifecycle tracking
- CUR as enrichment → accurate but optional
- Modular pipeline → Iceberg / Trino ready

---