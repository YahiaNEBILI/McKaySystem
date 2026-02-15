# Glossary

Status: Canonical  
Last reviewed: 2026-02-01

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

A **Finding** is a deterministic, run-scoped observation about a cloud resource that indicates:

- a policy violation,
- a risk,
- or an optimization opportunity.

A finding describes **what is true**, not what should be done.

It is factual, measurable, and derived solely from observed infrastructure state, metrics, and rules defined in the system.

#### Examples

- “S3 bucket has no lifecycle policy.”
- “EC2 instance CPU p95 is 12% over the last 30 days.”
- “Load balancer has processed 0 requests for 30 days.”
- “RDS allocated storage is 500GB, used storage is 120GB.”

#### Immutability Rule

A finding is **immutable within a given run**.

- Its content (rule result, metrics, computed values) cannot be modified once written.
- Any user actions (ignore, snooze, resolve, owner assignment, notes) are stored in a separate lifecycle overlay keyed by the finding fingerprint.
- If infrastructure state changes, a new run generates a new finding record.

This guarantees:
- Determinism
- Auditability
- Reproducibility
- Clean separation between detection and workflow state


---

### Recommendation

A **Recommendation** is a derived, strategic proposal associated with a finding that suggests a specific action to improve cost efficiency, reduce risk, or correct a violation.

A recommendation describes **what should be done**, based on the finding.

It is prescriptive and may evolve as:
- pricing models change,
- optimization strategies improve,
- risk tolerance shifts,
- or new business logic is introduced.

#### Examples

- “Downsize from m5.2xlarge to m5.xlarge — estimated savings $3,200/year.”
- “Reduce allocated RDS storage from 500GB to 200GB.”
- “Delete idle NAT Gateway — estimated savings $380/month.”
- “Purchase 1-year Reserved Instance for m5 family based on steady usage.”

#### Key Properties

- A recommendation is derived from a finding.
- It includes cost impact estimates.
- It includes confidence or risk indicators.
- It may vary depending on optimization strategy (e.g., conservative vs aggressive).
- It does not exist independently of findings.

A finding represents the **diagnosis**.  
A recommendation represents the **treatment plan**.

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

confidence normalization : 
0 = unknown / not estimated

10–30 = heuristic / missing key inputs (e.g., size unknown → cost default 0)

40–70 = based on resource attributes (size/type/age) with fixed public price defaults

80–90 = based on exact metering inputs (GB, hours, class) but still no CUR

95+ = CUR-enriched (later)

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
