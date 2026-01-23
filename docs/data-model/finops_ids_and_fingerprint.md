
# FinOps IDs & Fingerprint Specification

## 1. Purpose

This document defines the **official contract** for identifiers used in the FinOps SaaS platform.

Goals:
- Ensure **deterministic identification** of findings
- Enable **deduplication across runs**
- Support **long-lived lifecycle tracking**
- Allow **safe aggregation and enrichment** (CUR attribution, KPIs)

This document is **contractual**: changing these rules may break data compatibility.

---

## 2. Key Concepts

### 2.1 Fingerprint

A **fingerprint** identifies **the same issue on the same target**, regardless of execution time.

It is:
- deterministic
- stable across runs
- independent of execution date

**Rule**  
> If two findings describe the same problem on the same resource,  
> **they MUST share the same fingerprint**.

---

### 2.2 Finding ID

A **finding_id** identifies a **finding record** in storage.

It may be:
- stable across time (recommended default)
- or intentionally vary per run or per day (configurable)

The finding_id is always derived from the fingerprint.

---

## 3. Canonical Inputs

### 3.1 Scope Key

The scope key defines **what is being targeted**.

Fields (canonical order):

- `cloud`
- `billing_account_id`
- `account_id`
- `region`
- `service`
- `resource_type`
- `resource_id`
- `resource_arn`

Normalization rules:
- trim whitespace
- lowercase logical dimensions (cloud, service, region, resource_type)
- keep original casing for provider IDs (resource_id, ARN)

---

### 3.2 Issue Key

The issue key disambiguates **why** the finding exists.

Examples:
- recommended instance family
- idle threshold
- lifecycle policy age

Rules:
- flat key/value structure only
- keys are lowercased strings
- values are stringified
- order does not matter (sorted during canonicalization)

Example:
```json
{
  "recommended_arch": "arm64",
  "recommended_families": "m7g,c7g,r7g"
}
```

---

## 4. Fingerprint Definition

The fingerprint is computed as:

```
fingerprint = SHA256_HEX(
  canonical_json({
    tenant_id,
    check_id,
    scope,
    issue_key
  })
)
```

Properties:
- SHA-256
- hex encoded
- canonical JSON (sorted keys, no whitespace)

---

## 5. Finding ID Definition

The finding_id is derived from the fingerprint.

```
finding_id = SHA256_HEX(
  canonical_json({
    tenant_id,
    fingerprint,
    salt
  })
)
```

### 5.1 Salt Modes

| Mode | Salt | Behavior |
|----|----|---------|
| `stable` (default) | empty | One ID across time |
| `per_run` | run_id | New ID each execution |
| `per_day` | YYYY-MM-DD | New ID per day |

**Recommendation**:  
Use `stable` unless you explicitly need per-run history at the ID level.

---

## 6. Deduplication Semantics

- **Primary deduplication key**: `fingerprint`
- **Storage key**: `finding_id`
- **Current state**: one row per fingerprint
- **History** (optional): append-only per run

---

## 7. Required Fields for Valid Finding

A finding record is considered valid only if it contains:

- `tenant_id`
- `finding_id`
- `fingerprint`
- `run_id`
- `run_ts`
- `check_id`
- `status`
- `severity.level`
- `scope.cloud`
- `scope.account_id`
- `scope.service`
- `source.schema_version`

---

## 8. Design Rationale

Why fingerprint ≠ finding_id:
- fingerprint tracks **identity of the issue**
- finding_id tracks **storage representation**

Why hashing:
- deterministic
- compact
- safe for multi-tenant environments
- avoids composite primary keys

---

## 9. Compatibility & Versioning

- Hash algorithm: **SHA-256**
- Encoding: **hex**
- Canonical JSON rules are frozen
- Any change requires:
  - new schema_version
  - explicit migration plan

---

## 10. Summary

| Concept | Stable | Purpose |
|------|-------|--------|
| fingerprint | ✅ | Identify the same issue |
| finding_id | ⚠️ configurable | Identify a stored record |

This contract enables safe evolution of the FinOps SaaS data platform.
