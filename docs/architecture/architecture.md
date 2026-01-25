# Architecture

This document describes the **SaaS-grade FinOps engine architecture** implemented in this repository.
It focuses on:
- boundaries and responsibilities
- data flow and representations
- extensibility points (new checkers, CUR attribution, KPIs)
- operational considerations (multi-tenant, reprocessing, testing)

> Design principle: **be liberal at the edges, strict at the core.**

---

## 1. System overview

At a high level, the system runs **checkers** that emit **wire-format findings**, validates them against a strict contract, then persists them as a **typed Parquet dataset**. DuckDB reads Parquet to export JSON payloads for the web app.

```
          +-------------------+
          |     Checkers      |
          | (AWS inventory /  |
          |  heuristics)      |
          +---------+---------+
                    |
                    | FindingDraft (wire)
                    v
          +-------------------+
          | Contract layer    |
          | - required fields |
          | - enums/coherence |
          | - fingerprint/id  |
          +---------+---------+
                    |
                    | wire records (JSON-friendly)
                    v
          +-------------------+
          | Storage boundary  |
          | cast_for_storage  |
          | (Arrow schema)    |
          +---------+---------+
                    |
                    | storage records (Decimal/datetime)
                    v
          +-------------------+
          | Parquet dataset   |
          | finops_findings   |
          | partitioned       |
          +---------+---------+
                    |
                    | SQL
                    v
          +-------------------+
          | DuckDB analytics  |
          | queries / export  |
          +---------+---------+
                    |
                    | JSON files
                    v
          +-------------------+
          | Flask webapp      |
          +-------------------+
```

---

## 2. Repository boundaries

### 2.1 `checks/` (Detection)

Checkers implement business logic and talk to cloud APIs.

Rules:
- must only emit **wire format**
- must not write Parquet
- must not depend on DuckDB
- should not manage credentials
- should remain fast and safe (timeouts, error handling)
- checker module must register itself in the checker registry at import time.

```python
@register_checker("checks.aws.s3_lifecycle_missing:S3LifecycleMissingChecker")
def _factory(ctx, bootstrap):
    ...
```

Example: `S3LifecycleMissingChecker`

---

### 2.2 `contracts/` (Data contract & determinism)

This folder defines the **canonical contract** for findings.

Key responsibilities:
- canonicalization of input records
- required field validation
- enum validation
- coherence validation
- deterministic identity generation:
  - `fingerprint` (logical id)
  - `finding_id` (storage id)

Important files:
- `schema.py`: Arrow schema for storage
- `finops_contracts.py`: validation + id generation
- `storage_cast.py`: wire -> storage casting

---

### 2.3 `pipeline/` (Persistence & export)

Pipeline code is responsible for:
- writing datasets (Parquet)
- querying datasets (DuckDB)
- exporting JSON for the UI

Key rule:
> The pipeline owns the storage boundary.
> No checker should perform Arrow casting.

Important files:
- `writer_parquet.py`
- `export_json.py`

---

### 2.4 `runner.py` (Orchestration)

Runner builds and wires:
- `RunContext` (immutable run metadata)
- `Services` container (AWS clients)
- checker instances
- writer config

Runner is the only place where you should load SDK config and instantiate cloud clients.

### 2.5 Checker discovery model

Runner does not maintain a hardcoded list of checkers.
Instead:
Runner imports **all modules under** checks/
Module imports trigger **checker registration**
Runner reads the registry to determine what to run

This ensures:

zero runner changes when adding checkers

deterministic and auditable checker sets

SaaS-safe defaults (“run everything”)

---

## 3. Data flow & representations

### 3.1 Wire format (JSON-friendly)

Wire format is used everywhere **before** the storage boundary.

Characteristics:
- JSON compatible dictionaries
- empty strings allowed for optional fields
- timestamps may be ISO strings
- numeric/money may be strings

This keeps checkers simple and outputs portable.

---

### 3.2 Storage format (Arrow-typed)

Storage format is used only at persistence time.

Characteristics:
- strict Arrow schema
- `Decimal` for monetary fields
- timezone-aware `datetime` for timestamps
- `None` instead of empty strings for non-string fields

This ensures analytics correctness and long-term stability.

---

### 3.3 The mandatory storage boundary

All records must pass through:

```
wire_record -> cast_for_storage(schema) -> storage_record -> Parquet
```

This boundary is what prevents “migration pain” later.

---

## 4. Identity model

### 4.1 Fingerprint

A fingerprint answers:
> Is this the same issue as before?

It is stable across runs and derived from:
- `check_id`
- resource identity (`scope.*`)
- `issue_key`

Use cases:
- dedupe across runs
- lifecycle tracking (snooze/resolve)
- time-series history

---

### 4.2 Finding ID

A finding_id is a storage identifier. Depending on salting:
- stable across runs (for dedupe)
- per-run (for append-only history)
- per-day (hybrid)

---

## 5. Storage layout

### 5.1 finops_findings Parquet dataset

Partitioning strategy:

```
data/finops_findings/
  tenant_id=<tenant>/
    run_date=<YYYY-MM-DD>/
      part-<uuid>.parquet
```

Properties:
- append-only
- partition pruning by tenant/date
- schema enforcement via Arrow

---

## 6. Analytics and export

### 6.1 DuckDB as query engine

DuckDB reads Parquet directly:
- fast local analytics
- portable testing
- simple SQL-based KPI generation

Current MVP usage:
- export JSON for Flask UI

Future usage:
- KPI materialization (“gold tables”)
- attribution joins (findings x CUR)

---

### 6.2 JSON export

The JSON exporter generates UI-friendly payloads:
- `findings.json`
- `summary.json`
- `top_savings.json`

These files can be:
- served statically
- loaded by Flask endpoints
- produced by scheduled jobs (cron/EventBridge)

---

## 7. Extensibility roadmap

### 7.1 Add a new checker

To add a checker:
1. create a new module in `checks/`
2. implement `run(ctx)` yielding `FindingDraft` with `checker_id`
3. ensure correct `scope` and `issue_key`
4. register it using `register_checker(...)` or `register_class(...)`

---

### 7.2 CUR attribution (actual costs)

Goal:
- enrich findings with real costs from CUR

Approach:
- join `scope.resource_id` / ARN to CUR resource identifiers
- compute `actual.cost_7d`, `actual.cost_30d`, etc.
- fill `actual.attribution.*`

Output:
- either overwrite via new dataset `finops_findings_enriched`
- or write a separate attribution table and join at query time

---

### 7.3 KPI gold tables

To keep UI fast, materialize pre-aggregated Parquet tables:
- findings counts by status/severity/category
- top savings
- costs by service / account / region

Stored as:
```
data/finops_kpi_gold/tenant_id=.../period=.../part-...parquet
```

---

## 8. Operational considerations

### 8.1 Multi-tenant

Tenant is a first-class partition key:
- all datasets are partitioned by `tenant_id`
- API/UI always filter by tenant

---

### 8.2 Reprocessing

Because datasets are append-only:
- you can re-run checkers safely
- you can re-cast/re-write without mutating originals
- you can rebuild KPI tables from Parquet

---

### 8.3 Testing strategy

Unit tests validate:
- contract validation + deterministic IDs
- storage cast correctness vs schema
- writer correctness (partitioning, Parquet readability)

Recommended additions:
- integration test in CloudShell against a dev AWS account
- “golden record” tests for schema evolution

### 8.4 Deterministic rule execution

Because : checker discovery is explicit / ordering is deterministic / identity is stable

The system guarantees : reproducible runs / safe reprocessing / consistent lifecycle tracking

---

### 9. Runtime bootstrap model

Some checkers require runtime information (e.g. AWS account ID).

Runner provides a small, explicit bootstrap dictionary to factories:

```python
bootstrap = {
    "aws_account_id": "...",
    "aws_billing_account_id": "...",
}
```

Guidelines:
bootstrap is immutable
bootstrap contains facts, not clients
shared SDK clients belong in ctx.services
This keeps factories pure and testable.

## 10. Guiding principles (summary)

1. **Checkers stay dumb about storage**
2. **Contracts stay strict**
3. **Storage boundary is explicit**
4. **Parquet is the system of record**
5. **DuckDB powers MVP analytics**
6. **Everything is testable**

---

## Appendix: Useful commands

### Run a checker

```bash
python3 runner.py   --tenant acme   --workspace prod   --checker checks.aws.s3_lifecycle_missing:S3LifecycleMissingChecker   --out data/finops_findings
```

### Query Parquet with DuckDB

```bash
python3 - <<'EOF'
import duckdb
duckdb.sql("""
SELECT check_id, status, count(*)
FROM read_parquet('data/finops_findings/**/*.parquet')
GROUP BY 1,2
""").show()
EOF
```

### Export JSON

```bash
python3 - <<'EOF'
from pipeline.export_json import ExportConfig, run_export
run_export(ExportConfig(
  findings_glob='data/finops_findings/**/*.parquet',
  tenant_id='acme',
  out_dir='webapp_data'
))
EOF
```

