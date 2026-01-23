# FinOps SaaS – Documentation & Glossary

This document provides the **shared vocabulary and conceptual model** for the FinOps SaaS engine.
It is intended for:
- developers
- FinOps engineers
- reviewers / auditors
- future contributors

---

## Purpose of this document

FinOps systems fail more often due to **conceptual ambiguity** than technical issues.

This glossary:
- defines **precise meanings**
- removes ambiguity between similar terms
- acts as a **contract** between engine, data, and UI layers

If a term is not defined here, it should not be relied upon as stable.

---

## Core concepts

### Finding

A **Finding** is a detected condition on a cloud resource that:
- violates a rule
- represents a risk
- or exposes an optimization opportunity

Examples:
- S3 bucket without lifecycle policy
- EC2 instance oversized
- Unused load balancer

A finding is **immutable** once written.

---

### Checker

A **Checker** is a unit of logic that:
- inspects cloud resources
- evaluates one specific rule
- emits zero or more findings

Checkers:
- do not store data
- do not know about Parquet, Arrow, or DuckDB
- do not manage AWS credentials

---

### Run

A **Run** represents a single execution of the engine.

A run has:
- a `run_id`
- a `run_ts`
- a fixed configuration and engine version

Multiple runs may produce findings for the same resource.

---

### RunContext

The **RunContext** is an immutable object injected into all checkers.

It contains:
- tenant identity
- run metadata
- engine and schema versions
- runtime services (AWS clients)

It never contains:
- resource inventories
- mutable state
- credentials logic

---

## Identity & determinism

### Fingerprint

A **Fingerprint** is the logical identity of a finding.

It answers the question:
> “Is this the same problem as before?”

Fingerprints are derived from:
- check_id
- resource identity
- issue_key

Fingerprints are **stable across runs**.

---

### Finding ID

A **Finding ID** is the storage identity of a finding record.

It may change depending on:
- run
- salting strategy

Finding IDs allow:
- storage deduplication
- append-only datasets

---

### Issue Key

The **Issue Key** is a structured dictionary used to:
- differentiate variants of the same issue
- control fingerprint stability

Example:
```json
{
  "lifecycle": "missing"
}
```

---

## Data representations

### Wire format

The **Wire format** is the internal representation used between:
- checkers
- validators
- runners

Characteristics:
- JSON-compatible
- strings allowed for numeric values
- empty strings allowed

This format optimizes developer ergonomics.

---

### Storage format

The **Storage format** is the persisted representation written to Parquet.

Characteristics:
- strict Arrow types
- Decimal for money
- datetime for timestamps
- no empty strings for non-string fields

All records **must** be cast before storage.

---

## Severity model

### Severity

Severity describes the **importance** of a finding.

It is composed of:
- `level`: human-readable (low, medium, high, critical)
- `score`: numeric (0–100)

Severity is **not cost**.

---

## Cost concepts

### Estimated cost

**Estimated cost / savings**:
- comes from heuristics
- is approximate
- may be empty

Used for:
- early prioritization
- UI sorting

---

### Actual cost

**Actual cost**:
- comes from billing data (CUR)
- is authoritative
- time-windowed (7d / 30d)

Used for:
- reporting
- savings validation

---

### Cost attribution

Cost attribution is the process of:
- linking a finding to real spend
- attaching confidence and method

Examples:
- exact resource match
- tag-based attribution
- proportional allocation

---

## Storage & analytics

### Parquet dataset

A **Parquet dataset** is:
- append-only
- partitioned by tenant and date
- immutable once written

Used as the system of record.

---

### DuckDB

DuckDB is used as:
- local analytical engine
- query layer
- JSON export backend

It is not a long-term state store.

---

## Lifecycle & state

### Lifecycle state

Lifecycle state represents **user interaction** with findings.

Examples:
- open
- acknowledged
- snoozed
- resolved

Lifecycle state is **not stored in findings**.
It is stored separately and joined at read time.

---

## Design principles

### Immutability

- Findings are immutable
- State is additive
- Corrections happen via new runs

---

### Determinism

Given:
- same inputs
- same engine version

The system produces:
- same fingerprints
- same findings

---

### Separation of concerns

| Layer | Responsibility |
|-----|----------------|
| Checker | Detection |
| Contract | Validation |
| Runner | Orchestration |
| Storage | Persistence |
| Analytics | Aggregation |
| UI | Presentation |

---

## Non-goals

This engine intentionally does **not**:
- manage credentials UI
- enforce remediation
- mutate cloud resources

---

## Final note

This glossary is a **living contract**.

Any change to definitions here must be:
- explicit
- versioned
- backward-compatible where possible
