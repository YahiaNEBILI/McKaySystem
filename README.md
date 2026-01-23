# FinOps SaaS – Prototype Architecture

This repository contains a **SaaS-grade FinOps prototype** designed to:
- run FinOps checks on cloud resources
- generate deterministic findings
- store results in Parquet (Arrow-compatible)
- query results with DuckDB
- export JSON files for a Flask web application

The project is intentionally **modular, testable, and scalable**, while remaining simple enough for fast iteration.

---

## High-level architecture

```
Checkers
   |
   v
Runner
   |
   v
Contract validation + IDs
   |
   v
Storage cast (Arrow types)
   |
   v
Parquet (finops_findings)
   |
   v
DuckDB
   |
   v
JSON export
   |
   v
Flask WebApp
```

---

## Repository layout

```
.
├── runner.py                  # Main entrypoint
├── contracts/                 # Data contracts & validation
│   ├── finops_contracts.py    # Canonicalization, hashing, validation
│   ├── schema.py              # PyArrow canonical schema
│   ├── storage_cast.py        # Wire → Arrow storage casting
│   ├── finops_checker_pattern.py
│   └── __init__.py
│
├── checks/                    # FinOps checkers
│   └── aws/
│       └── ec2_graviton.py    # Example checker
│
├── pipeline/
│   ├── writer_parquet.py      # Parquet writer (partitioned, typed)
│   ├── export_json.py         # DuckDB → JSON exporter
│   └── __init__.py
│
├── tests/                     # Pytest suite
│   ├── test_storage_cast.py
│   └── test_writer_parquet.py
│
├── data/
│   └── finops_findings/       # Generated Parquet data
│
├── webapp_data/               # Generated JSON files for Flask
│   ├── findings.json
│   ├── summary.json
│   └── top_savings.json
│
├── pytest.ini
├── pyproject.toml
└── README.md
```

---

## Core concepts

### Wire vs Storage format

The system uses **two explicit representations**:

| Layer | Purpose | Types |
|-----|--------|------|
| Wire | Internal processing, JSON | strings, empty strings allowed |
| Storage | Parquet / analytics | Decimal, datetime, date, None |

Before writing Parquet, every record **must be cast** using the Arrow schema.

---

### Deterministic identity

Each finding has:
- **fingerprint** → logical identity (same issue, same resource)
- **finding_id** → storage identity (salted or stable)

This enables:
- deduplication
- lifecycle tracking
- safe reprocessing

---

## Running the pipeline

### 1. Run a checker

```powershell
python runner.py ^
  --tenant acme ^
  --workspace prod ^
  --checker checks.aws.ec2_graviton:EC2GravitonChecker ^
  --out data/finops_findings
```

This generates Parquet files under:

```
data/finops_findings/
  tenant_id=acme/
    run_date=YYYY-MM-DD/
      part-*.parquet
```

---

### 2. Export JSON for the web app

```powershell
python -c "
from pipeline.export_json import ExportConfig, run_export
cfg = ExportConfig(
    findings_glob='data/finops_findings/**/*.parquet',
    tenant_id='acme',
    out_dir='webapp_data'
)
run_export(cfg)
"
```

This produces:

```
webapp_data/
  findings.json
  summary.json
  top_savings.json
```

---

## Testing

Run all tests:

```powershell
python -m pytest -q
```

The tests validate:
- contract enforcement
- Arrow schema compatibility
- Parquet writing correctness

---

## Why this architecture works

- **Strict contracts** prevent data corruption
- **Arrow + Parquet** ensure scalability
- **DuckDB** enables fast local analytics
- **JSON export** decouples backend from UI
- **Deterministic IDs** enable SaaS features (lifecycle, history)

This architecture scales naturally to:
- CUR attribution
- KPI gold tables
- live APIs
- Iceberg / Trino backends

---

## Next steps

Planned evolutions:
- CUR attribution (actual cost)
- KPI materialization (gold tables)
- Flask / FastAPI API
- lifecycle state persistence
- multi-tenant scheduling

---

## Philosophy

> **Be liberal at the edges, strict at the core.**

Fast iteration for developers, strong guarantees for data.

---

## License

Internal prototype – all rights reserved.
