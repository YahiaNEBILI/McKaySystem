# CUR pipeline (Cost & Usage Report)

This document explains **how CUR data is integrated** into the FinOps engine:

- where to put raw CUR Parquet files
- how normalization works
- how cost enrichment behaves
- how to interpret cost coverage

The CUR pipeline is **optional by design**: the system must always work even when CUR is missing or delayed.

---

## Design philosophy

> **Signals first, costs second.**

- FinOps findings are emitted from **infrastructure APIs** (EC2, RDS, S3, …)
- CUR is used only to **enrich findings with actual costs**
- Missing or late CUR data must never break the pipeline

This avoids:
- CUR latency issues
- blind spots when CUR lacks resource-level granularity
- coupling the engine lifecycle to billing exports

---

## 1. Raw CUR input

### Expected location

Raw CUR **must be provided as Parquet files** under:

```
data/raw_cur/**/*.parquet
```

There is **no fixed filename** (no `cur.parquet`). Any Parquet file matching the glob is accepted.

### Recommended layout

```
data/
  raw_cur/
    tenant=acme/
      2025-01/
        cur-0001.parquet
        cur-0002.parquet
      2025-02/
        cur-0001.parquet
```

Why this layout works well:
- easy pruning by month
- compatible with Athena / Glue outputs
- Iceberg-friendly later

### Accepted sources

Raw CUR Parquet can come from:
- Athena CTAS (CSV → Parquet)
- AWS Glue jobs
- any external conversion pipeline

The system performs **schema discovery**, so minor column drift is tolerated.

---

## 2. CUR normalization (`normalize_cur.py`)

### Purpose

Normalize raw CUR exports into a **stable analytical table** called `cost_facts`.

This step:
- hides CUR schema complexity
- provides a deterministic join surface for enrichment
- makes cost queries fast and predictable

### Output location

```
data/cur_facts/
  tenant_id=acme/
    billing_period=2025-01/
      account_id=123456789012/
        part-0000.parquet
```

(Exact partitions depend on configuration flags.)

### Normalized schema (simplified)

| Column | Description |
|------|-------------|
| tenant_id | Tenant identifier |
| account_id | Linked AWS account |
| region | AWS region (derived if needed) |
| service | AWS service code/name |
| resource_id | CUR resource identifier (when available) |
| usage_start | Usage timestamp |
| cost_primary | Selected cost metric |
| cost_unblended / cost_net / cost_amortized | Raw cost variants |
| currency | Billing currency |
| tags | `MAP<VARCHAR,VARCHAR>` of resource tags |

### Cost model selection

The normalizer supports:
- `unblended` (default)
- `net`
- `amortized`

The chosen model populates `cost_primary`, while preserving the others for audit/debug.

---

## 3. Cost enrichment (`cost_enrich.py`)

### Purpose

Join **FinOps findings** with **normalized cost facts** to populate:

- `actual.cost_7d`
- `actual.cost_30d`
- `actual.cost_mtd`
- `actual.cost_prev_month`

Enrichment is **best-effort** and never mandatory.

### Matching strategy

The enrichment uses **tiered attribution**:

#### Tier A — exact resource match (high confidence)

Join on:
- `account_id`
- `resource_id` (or ARN)
- optional region/service match

Attribution:
- `method = exact_resource_id`
- `confidence ≈ 95`

#### Tier C — scoped rollup (fallback)

Join on:
- `account_id`
- optional region/service

Attribution:
- `method = heuristic`
- `confidence ≈ 20`

(Tag-based Tier B matching may be added later.)

### Output location

```
data/finops_findings_enriched/
```

This dataset has the **same schema as raw findings**, with additional `actual.*` fields populated.

---

## 4. Optional by design

The pipeline behaves safely in all scenarios:

| Situation | Behavior |
|--------|----------|
| No raw CUR present | Normalization + enrichment skipped |
| CUR present but partial | Partial enrichment |
| CUR delayed today | Previous enriched data still usable |
| CUR schema drift | Normalization adapts (best-effort) |

The runner and exporter **never fail** due to missing CUR.

---

## 5. Cost coverage

### What coverage means

Cost coverage answers:

> *What percentage of findings have an actual cost attributed?*

Coverage depends on:
- CUR resource granularity
- availability of `line_item_resource_id`
- tagging hygiene
- service-specific behavior

### Exported coverage metrics

The JSON export produces:

```
webapp_data/coverage.json
```

Example:
```json
{
  "tenant_id": "acme",
  "dataset": "enriched",
  "findings_total": 420,
  "findings_with_actual_cost": 263,
  "actual_cost_coverage_pct": 62.6
}
```

Interpretation:
- **0%** → CUR missing or no join possible
- **30–50%** → typical infra-native baseline
- **60–90%** → good tagging + strong CUR linkage

Low coverage is **not a failure**; it is a signal for where attribution can be improved.

---

## 6. Common pitfalls

- CUR still in CSV (must be Parquet)
- Raw CUR stored outside `data/raw_cur/`
- Mismatched `tenant_id` between findings and CUR
- Services without resource-level CUR data (expected)

---

## Summary

- CUR is an **enrichment layer**, not a dependency
- Normalization creates a stable `cost_facts` table
- Enrichment is deterministic and best-effort
- Coverage is a diagnostic signal, not an error

This design keeps the FinOps engine **accurate, resilient, and SaaS-ready**.

