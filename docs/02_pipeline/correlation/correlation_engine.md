# Correlation engine

Status: Canonical  
Last reviewed: 2026-02-01

## Purpose

The correlation engine enriches raw FinOps findings by **combining multiple independent signals**
into higher-confidence, higher-value **meta-findings**.

Instead of treating each checker output in isolation, correlation allows the system to answer
questions like:

- “Is this backup vault risky *in practice*, not just misconfigured?”
- “Do multiple weak signals together represent a strong FinOps issue?”
- “Should severity increase because several problems co-exist on the same resource?”

Correlation is **additive**:
- Raw findings are never modified or deleted
- Correlation emits new findings that reference existing ones
- All results remain auditable and explainable

---

## Where Correlation Fits in the Pipeline

The FinOps pipeline is intentionally split into **pure stages**:

```
Runner
  → Checkers
    → Raw Findings (Parquet)
      → Correlation Engine
        → Correlated Findings (Parquet)
          → DuckDB
            → JSON / UI / API
```

Correlation happens **after raw findings are written to Parquet** and **before JSON export**.

Why here:
- Parquet is columnar, scalable, and queryable
- DuckDB can efficiently correlate large datasets
- JSON is presentation-only and not suitable for large joins

---

## Design Principles

### 1. Correlation is Set-Based (Not Python Loops)

Correlation operates on **entire datasets**, not individual findings.

- Uses DuckDB SQL
- Benefits from predicate pushdown and column projection
- Scales to large runs and historical reprocessing

Python is used only to:
- orchestrate rules
- stream results
- write Parquet output

---

### 2. Correlation Emits Meta-Findings

Correlation never mutates existing findings.

Instead, it emits **new findings** with:
- their own `check_id`
- their own severity
- their own scope
- references to the source findings

Example:

```
Raw findings:
  - aws.backup.vaults.no_lifecycle
  - aws.backup.recovery_points.stale

Correlated finding:
  - aws.backup.correlation.vault_risk
```

This preserves:
- auditability
- explainability
- long-term trust

---

### 3. Rules Are Declarative

Correlation logic is expressed as **SQL rules**, not Python `if/else`.

Each rule declares:
- which check_ids it depends on
- the SQL used to correlate them

This makes rules:
- reviewable
- testable
- diff-friendly
- easy to extend

---

## Code Structure

```
pipeline/
  correlation/
    engine.py        # Core correlation engine (library)
    ruleset.py       # Rule registry (declarative)
    rules/
      *.sql          # Individual correlation rules
  correlate_findings.py  # Pipeline entrypoint (orchestration)
```

---

## engine.py — The Correlation Engine

`engine.py` is a **pure library**.

It:
- knows how to run correlation
- does NOT know where data comes from
- does NOT parse CLI args
- does NOT read bootstrap config

Responsibilities:
- Load findings from Parquet into DuckDB
- Apply correlation rules
- Stream resulting meta-findings
- Write them back to Parquet

This separation allows:
- re-running correlation without re-running checkers
- testing correlation independently
- future scheduling / orchestration (Airflow, Step Functions, etc.)

---

## ruleset.py — Rule Registry

`ruleset.py` declares **which correlation rules exist**.

Example:
```python
CorrelationRule(
  rule_id="aws.backup.correlation.vault_risk",
  name="AWS Backup vault risk (correlated)",
  required_check_ids=[
    "aws.backup.vaults.no_lifecycle",
    "aws.backup.recovery_points.stale",
  ],
  sql=load_rule_sql("aws_backup_vault_risk.sql"),
)
```

Why this matters:
- The engine can **pre-filter findings** by `check_id`
- DuckDB avoids scanning unrelated Parquet row groups
- Correlation remains fast even with many findings

---

## SQL Rules

Each SQL rule:
- runs against a DuckDB view called `rule_input`
- returns **one row = one meta-finding**
- must return a valid `scope` struct
- should return `source_fingerprints` for deterministic deduplication

Rules are free to:
- join findings
- aggregate costs
- escalate severity
- enrich messages

Rules must NOT:
- modify raw findings
- assume ordering
- rely on Python state

---

## correlate_findings.py — Pipeline Entry Point

This is the **orchestration layer**.

It:
- reads bootstrap / config
- decides which runs to correlate
- instantiates the engine
- executes correlation
- logs stats

Example flow:

```python
engine = CorrelationEngine(build_rules())
engine.run(CorrelationConfig(...))
```

This mirrors other pipeline steps like `export_json.py`.

---

## Why Correlation Is Not Inside engine.py

Putting orchestration inside `engine.py` would:
- tightly couple logic to execution
- make reprocessing difficult
- complicate testing
- block future workflows

By keeping `engine.py` pure:
- correlation can be run multiple times
- rules can evolve independently
- historical data can be re-correlated

---

## Deterministic Identity & Deduplication

Correlated findings build their identity from:
- the correlation rule ID
- the fingerprints of the source findings

This ensures:
- the same correlation produces the same finding
- no duplication across runs
- compatibility with future state tracking

---

## Performance Considerations

Correlation is designed to scale because:
- Parquet is columnar
- DuckDB pushes filters into scans
- Each rule scans only required check_ids
- Results are streamed and batched

If needed later:
- rules can be partition-aware
- an index Parquet can be introduced
- correlation can run per account / per region

---

## Summary

The correlation engine:
- transforms isolated findings into actionable insight
- preserves auditability
- scales with data volume
- fits cleanly into the existing FinOps pipeline

It is intentionally:
- **additive**
- **declarative**
- **set-based**
- **future-proof**

This design allows the system to grow from “checker output”
into a true **decision-grade FinOps intelligence engine**.
