# FinOps Engine – Deterministic Cloud Cost & Governance Analysis

This repository contains a **FinOps-grade analysis engine** designed to detect,
correlate, and attribute cloud cost and governance inefficiencies across AWS
environments.

The system is intentionally:
- **infra-native first** (resource-level signals before billing data)
- **deterministic and testable by design**
- **scalable** from local DuckDB to Iceberg / Trino backends
- **production-ready**, while remaining hackable and inspectable

This README provides a **system-level orientation**.
Authoritative design contracts and deep dives live under `docs/`.

## Getting started

- New here? Read `docs/00_overview/introduction.md`.
- Want the detailed architecture? Start with `docs/01_architecture/architecture.md`
  and `docs/02_pipeline/pipeline_overview.md`.

Quick commands:

```bash
pip install -e ".[dev]"
pytest
python -m apps.worker.runner --tenant acme --workspace prod
python -m apps.worker.export_findings
```

Note: `python -m apps.worker.export_findings` writes `run_manifest.json`. DB ingestion reads Parquet via `run_manifest.json`.
Migrations: run `python -m apps.backend.db_migrate` (or `mckay migrate`) before first ingest.

Monorepo separation:
- Backend/API: `apps/flask_api/` + `apps/backend/` (deployment docs: `deploy/backend/`)
- Worker/Scanner: `apps/worker/` + engine paths (deployment docs: `deploy/worker/`)
- Layout guard: `python tools/repo/check_layout.py`
- Release tracks:
  - `make ci-backend` (or GitHub workflow: `.github/workflows/backend-ci.yml`)
  - `make ci-worker` (or GitHub workflow: `.github/workflows/worker-ci.yml`)

CloudShell worker sparse checkout:

```bash
bash tools/cloudshell/sparse_checkout_worker.sh .
```

CloudShell sparse clone bootstrap:

```bash
bash tools/cloudshell/bootstrap_sparse_clone.sh <repo-url> <target-dir> worker
```

RBAC scope bootstrap (first admin, no manual SQL):

```bash
export MCKAY_BOOTSTRAP_PASSWORD="<strong-password>"
mckay bootstrap-scope --tenant acme --workspace prod --user-id u_admin --email admin@acme.io
```

---

## Documentation map

Start here depending on your goal:

- **Architecture & mental model**
  - `docs/01_architecture/architecture.md`
  - `docs/02_pipeline/pipeline_overview.md`

- **Checker philosophy & contracts**
  - `docs/03_checkers/checker_contract.md`

- **Data contracts & schemas**
  - `docs/04_schemas/finding_schema.md`

- **Running & operations**
  - `docs/05_operations/running.md`
  - `docs/05_operations/permissions.md`

Canonical definitions live in `docs/00_overview/glossary.md`.

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
├── apps/worker/runner.py        # Main orchestration entrypoint
├── contracts/                   # Canonical schema & validation
│   ├── schema.py                # Arrow schema (source of truth)
│   ├── finops_contracts.py      # Canonicalization & hashing
│   ├── storage_cast.py          # Wire → Arrow casting
│   └── finops_checker_pattern.py
│
├── checks/                      # FinOps checkers (signals)
│   └── aws/
│       ├── ebs_storage.py
│       ├── rds_snapshots_cleanup.py
│       └── ...
│
├── docs/                       # Contains project documentation
├
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
├── services/                       
│   ├── pricing_services.py      # Provide pricing API for checkers
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
python -m apps.worker.runner --tenant acme --workspace prod
python -m apps.worker.export_findings
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

