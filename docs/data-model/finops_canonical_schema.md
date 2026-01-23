
# FinOps SaaS – Canonical Data Model (PyArrow / Parquet)

## 1. Overview

This document describes the **canonical data model** for a scalable FinOps SaaS platform.

The model is designed to be:

- 📦 **Scalable**: supports millions of records and multi-tenant workloads
- 💰 **Finance-grade**: real costs, attribution, auditability
- 🔍 **Analytics-ready**: optimized for DuckDB / Polars / Spark
- 🧩 **Extensible**: new clouds, new rules, new KPIs without schema churn
- 🔒 **Tenant-isolated**: partitioning and storage-level RBAC friendly

The architecture follows a **lakehouse-inspired 3-layer model**:

| Layer | Purpose |
|------|--------|
| `finops_findings` | Output of the FinOps engine (recommendations, issues) |
| `finops_cost_attribution` | Evidence and explainability of CUR cost attribution |
| `finops_kpi_*` | Pre-aggregated “gold” KPI tables for fast serving |

---

## 2. Main Table: `finops_findings`

### Description

- **1 row = 1 FinOps finding**
- A finding represents a **recommendation**, **waste**, **risk**, or **optimization**
- Targets can be:
  - a single resource (EC2 instance, RDS DB, bucket…)
  - a logical scope (service, account, region)
- Findings can be enriched asynchronously with **real costs from CUR**

---

### 2.1 Identity & Multi-Tenancy

| Field | Type | Description |
|-----|-----|------------|
| `tenant_id` | string | Customer identifier (required) |
| `workspace_id` | string | Logical environment (BU, prod/dev, team) |
| `finding_id` | string | Unique identifier (UUID or deterministic hash) |
| `fingerprint` | string | Stable signature to track the same issue over time |
| `run_id` | string | Engine execution run ID |
| `run_ts` | timestamp (UTC) | Engine execution time |
| `ingested_ts` | timestamp (UTC) | Ingestion time |

---

### 2.2 Engine Metadata

| Field | Type | Description |
|-----|-----|------------|
| `engine_name` | string | Engine name |
| `engine_version` | string | Engine semantic version |
| `rulepack_version` | string | Ruleset version |

---

### 2.3 Scope (Target Definition)

`scope` (struct):

| Field | Type | Description |
|-----|-----|------------|
| `cloud` | string | aws / azure / gcp |
| `provider_partition` | string | aws / aws-cn / aws-us-gov |
| `organization_id` | string | Organization / management group |
| `billing_account_id` | string | Payer / billing root |
| `account_id` | string | Linked account / subscription |
| `region` | string | Region |
| `availability_zone` | string | AZ (if applicable) |
| `service` | string | Cloud service (EC2, S3…) |
| `resource_type` | string | Logical resource type |
| `resource_id` | string | Resource identifier |
| `resource_arn` | string | ARN (AWS, optional) |

---

### 2.4 Check Identity

| Field | Type | Description |
|-----|-----|------------|
| `check_id` | string | Stable machine-readable ID |
| `check_name` | string | Human-readable name |
| `category` | string | rightsizing, waste, governance… |
| `sub_category` | string | Optional |
| `frameworks` | list<string> | FinOps, CIS, internal frameworks |

---

### 2.5 Result & Severity

| Field | Type | Description |
|-----|-----|------------|
| `status` | string | pass / fail / info / unknown |

**Severity (struct)**

| Field | Type |
|-----|-----|
| `level` | string |
| `score` | uint16 |

---

### 2.6 Human-Facing Content

| Field | Type | Description |
|-----|-----|------------|
| `title` | string | Short title |
| `message` | string | Detailed description |
| `recommendation` | string | Recommended action |
| `remediation` | string | Step-by-step guidance |
| `links` | list<struct> | Console, docs, tickets |

---

### 2.7 Estimated Economic Impact

`estimated` (struct):

| Field | Type | Description |
|-----|-----|------------|
| `monthly_savings` | decimal(18,6) | Potential monthly savings |
| `monthly_cost` | decimal(18,6) | Estimated monthly cost |
| `one_time_savings` | decimal(18,6) | One-off savings |
| `confidence` | uint8 | Estimate confidence (0–100) |
| `notes` | string | Notes |

---

### 2.8 Actual Cost Impact (CUR)

`actual` (struct):

| Field | Type | Description |
|-----|-----|------------|
| `cost_7d` | decimal(18,6) | Real cost last 7 days |
| `cost_30d` | decimal(18,6) | Real cost last 30 days |
| `cost_mtd` | decimal(18,6) | Month-to-date |
| `cost_prev_month` | decimal(18,6) | Previous month |
| `savings_7d` | decimal(18,6) | Realized savings |
| `savings_30d` | decimal(18,6) | Realized savings |
| `model` | struct | Unblended / Amortized / Net |
| `attribution` | struct | Attribution method + confidence |

---

### 2.9 Lifecycle (SaaS State)

| Field | Type |
|-----|-----|
| `status` | string |
| `first_seen_ts` | timestamp |
| `last_seen_ts` | timestamp |
| `resolved_ts` | timestamp |
| `snooze_until_ts` | timestamp |

---

### 2.10 Tags, Dimensions & Extensions

| Field | Type | Purpose |
|-----|-----|--------|
| `tags` | map<string,string> | Cloud provider tags |
| `labels` | map<string,string> | Internal labels |
| `dimensions` | map<string,string> | Normalized dimensions |
| `metrics` | map<string,decimal> | Numeric metrics |
| `metadata_json` | string | Free-form extension |

---

### 2.11 Lineage & Data Quality

`source` (struct):

| Field | Type |
|-----|-----|
| `source_type` | string |
| `source_ref` | string |
| `schema_version` | uint16 |

---

## 3. Cost Attribution Table: `finops_cost_attribution`

### Description

- **1 row = 1 attributed slice of CUR cost**
- Enables:
  - auditability
  - explainability
  - billing traceability

| Field | Type | Description |
|-----|-----|------------|
| `tenant_id` | string | Customer |
| `finding_id` | string | Related finding |
| `period_start` | date | Period start |
| `period_end` | date | Period end |
| `cost_model` | string | unblended / amortized |
| `method` | string | exact / tag / heuristic |
| `confidence` | uint8 | 0–100 |
| `cost_amount` | decimal(18,6) | Attributed cost |

---

## 4. KPI Tables (`finops_kpi_*`)

### Description

- Pre-aggregated **gold tables**
- Optimized for API / dashboard consumption
- No CUR scanning at request time

**Generic schema:**

| Field | Type |
|-----|-----|
| `tenant_id` | string |
| `period` | string |
| `kpi_name` | string |
| `dimensions` | map<string,string> |
| `value` | decimal(18,6) |
| `currency` | string |
| `computed_ts` | timestamp |

---

## 5. Technical Conventions

### Partitioning
- `finops_findings`: `tenant_id`, `run_date`
- `finops_cost_attribution`: `tenant_id`, `month`
- `finops_kpi_*`: `tenant_id`, `month`

### Best Practices
- Avoid partitioning by `resource_id`
- Batch writes (≥ 50k rows)
- Use Parquet + ZSTD compression
- Track schema evolution via `schema_version`

---

## 6. Why This Model Is SaaS-Competitive

- ✅ Multi-cloud ready
- ✅ CUR-compatible with explainable cost attribution
- ✅ Scales from MVP to enterprise workloads
- ✅ Lakehouse-ready (Iceberg / Delta / Trino)
- ✅ Clean separation between engine, data, and product

---

