
# FinOps SaaS – Pipeline Overview

## 1. Purpose

This document describes the **end-to-end data pipeline** of the FinOps SaaS platform.

It explains:
- how data flows through the system
- where contracts apply
- which components are stateful vs stateless

---

## 2. High-Level Flow

```
        +------------------+
        |  Cloud APIs      |
        |  (AWS/Azure/GCP) |
        +--------+---------+
                 |
                 v
        +------------------+
        |   Inventory &    |
        |   Metrics Fetch  |
        +--------+---------+
                 |
                 v
        +------------------+
        |    Checkers      |
        | (Business Logic) |
        +--------+---------+
                 |
                 v
        +-----------------------------+
        |  Contract Layer             |
        |  - canonicalization         |
        |  - fingerprint / finding_id |
        |  - validation               |
        +--------+--------------------+
                 |
                 v
        +-----------------------------+
        |  Raw Findings (Parquet)     |
        |  finops_findings            |
        +--------+--------------------+
                 |
        +--------+---------+
        |                  |
        v                  v
+----------------+   +------------------+
| CUR Attribution |   | KPI Aggregation |
| (DuckDB jobs)  |   | (DuckDB jobs)   |
+--------+-------+   +--------+---------+
         |                    |
         v                    v
+----------------------+  +----------------------+
| Enriched Findings    |  | KPI Gold Tables      |
| (actual cost)        |  | finops_kpi_*         |
+----------+-----------+  +----------+-----------+
           |                         |
           +------------+------------+
                        v
               +------------------+
               |   API / Flask    |
               |   JSON Serving   |
               +------------------+
```

---

## 3. Pipeline Stages

### 3.1 Inventory & Metrics

- Stateless collectors
- Cloud-native APIs
- No business logic
- No persistence guarantees

---

### 3.2 Checkers

Responsibilities:
- apply FinOps rules
- detect waste, risks, opportunities
- produce **FindingDraft** objects

Rules:
- no persistence
- no CUR access
- no hashing or IDs

---

### 3.3 Contract Layer

Responsibilities:
- canonicalize data
- compute fingerprint and finding_id
- validate required fields and enums

This layer guarantees **schema and identity consistency**.

Failures here indicate **data quality issues**, not business logic errors.

---

### 3.4 Raw Storage (Parquet)

- append-only
- partitioned by `tenant_id` and `run_date`
- compressed (ZSTD)

Acts as:
- system of record
- replayable source
- audit trail

---

### 3.5 CUR Attribution

- batch jobs (DuckDB / SQL)
- joins findings with CUR Parquet
- applies attribution rules
- produces explainable cost evidence

Output:
- updated `actual.*` fields
- optional `finops_cost_attribution` table

---

### 3.6 KPI Aggregation

- batch materialization
- monthly / daily aggregates
- no business logic

Examples:
- cost by service
- savings by category
- open findings by severity

---

### 3.7 API / Serving Layer

- Flask (or FastAPI)
- reads only **gold tables**
- no CUR scans at request time
- low latency, predictable cost

---

## 4. Stateless vs Stateful Components

| Component | Type |
|--------|------|
| Checkers | Stateless |
| Contract Layer | Stateless |
| Writers | Stateful |
| CUR Attribution | Stateful |
| KPI Aggregation | Stateful |
| API | Stateless |

---

## 5. Failure Domains

- Checker failure → partial results, safe retry
- Contract failure → invalid finding rejected
- CUR attribution failure → findings remain estimated
- KPI failure → stale dashboards, no data loss

---

## 6. Design Principles

- Clear separation of concerns
- Append-only raw data
- Deterministic identity
- Materialized views for performance
- Auditability by design

---

## 7. Summary

This pipeline allows:
- fast prototyping
- safe scaling to enterprise workloads
- future migration to Iceberg / Trino
- explainable, finance-grade FinOps analytics
