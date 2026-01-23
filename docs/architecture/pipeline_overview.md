
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
# FinOps SaaS – Pipeline Overview

## 1. Purpose

This document describes the **end-to-end FinOps SaaS pipeline**, with a focus on:
- data contracts
- responsibility boundaries
- format transitions

---

## 2. High-Level Flow

```
Checkers (wire dicts)
        |
        v
Contract Validation
        |
        v
Canonical Wire Records
        |
        v
CAST FOR STORAGE  <--- STRICT BOUNDARY
        |
        v
Parquet / Arrow Storage
        |
        +--> CUR Attribution Jobs
        |
        +--> KPI Aggregation Jobs
        |
        v
API / Dashboards
```

---

## 3. Responsibility Boundaries

### 3.1 Checkers

- Produce **wire-format** records only
- No Arrow, no Decimal, no datetime coercion
- Focus on business logic

---

### 3.2 Contract Layer

- Canonicalization
- fingerprint / finding_id generation
- Required field validation
- Enum and coherence validation

Works exclusively on **wire format**.

---

### 3.3 Storage Boundary (Critical)

The **storage boundary** is the only place where:

- wire records are cast to Arrow-compatible types
- type errors are surfaced
- schema mismatches are detected

This boundary:
- prevents schema drift
- isolates migration risks
- keeps checkers simple

---

### 3.4 Storage & Analytics

- Parquet is the system of record
- DuckDB / Spark / Trino read only storage-format data
- No wire-format data leaks into analytics

---

## 4. Failure Semantics

| Stage | Failure Impact |
|----|----------------|
| Checker | Partial findings |
| Contract validation | Invalid finding dropped |
| Storage cast | Hard failure (schema violation) |
| CUR attribution | Missing actual costs |
| KPI aggregation | Stale dashboards |

---

## 5. Design Principle

> **Be liberal at the edges, strict at the core.**

Wire format enables speed.
Storage format enforces correctness.

---

## 6. Summary

- Two representations are intentional
- Casting is explicit and mandatory
- Arrow schema is the final authority

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
