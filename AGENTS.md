# AGENTS.md

## Core principles

- Postgres is the **source of truth**.
- Everything is scoped by `tenant_id` + `workspace`.
- System must remain:
  - deterministic
  - idempotent
  - multi-tenant safe
  - reproducible in production

---

# Database rules (strict)

- All queries MUST include `tenant_id` AND `workspace`.
- Never modify a primary key without a migration.
- Never add/remove a column without a migration plan.
- Never perform silent DDL in runtime code.
- Lifecycle precedence is defined ONLY in `finding_current` view.

Lifecycle priority:


Do not reimplement lifecycle logic in Python.

---

# Ingestion rules

- Ingestion must be idempotent per `run_id`.
- Use `INSERT ... ON CONFLICT`.
- Update `runs` table last.
- No partial inconsistent commits.
- Code must remain compatible with future:


---

# Checker rules

- Deterministic output.
- Stable fingerprint.
- No randomness.
- No timestamp inside fingerprint.
- Must not crash on malformed AWS data.
- Must handle empty inputs.
- Must include unit tests.

---

# API rules

- Only query `finding_current` for findings.
- No `SELECT *`.
- Always filter by tenant/workspace.
- Avoid full table scans.
- Avoid N+1 queries.
- Use indexed columns in filters.

---

# Code quality (mandatory)

- Code must pass `pylint` with no new warnings.
- Do not disable pylint rules without strong justification.
- No broad `except Exception` unless strictly required.
- No unused imports.
- No dead code.
- Functions must have clear responsibilities.
- Prefer explicit typing.
- Avoid overly complex functions (refactor if needed).
- No hardcoded values.
- Write docstring for all functions.
- Use 'mypy' for type checking.
- use 'ruff' for litting.
- No `print()` statements in production code. Use logging.

Before committing:


Both must pass.

---

# Testing requirements

Every change must:

- Be deterministic.
- Be idempotent.
- Preserve tenant isolation.
- Not break empty DB behavior.
- Include/update tests if behavior changes.

Do not merge code that reduces test coverage.

---

# Forbidden changes

- Removing tenant/workspace scoping.
- Changing fingerprint format silently.
- Moving lifecycle logic outside DB.
- Adding hidden state.
- Introducing non-determinism.
- Runtime schema mutation without migration.

---

# Deployment safety

- DB schema must be version-aligned with code.
- Code must fail fast if schema mismatch is detected.
- No production-only logic branches.
- No environment-specific hacks.

---

This file defines non-negotiable production constraints.
If unsure, choose:
- determinism
- isolation
- explicitness
- migration-first approach

- test coverage define strict production constraints for codebase. Here's a summary of the key requirements:

1. **Database Ingestion Rules**:
   - Must be idempotent per run_id
   - Use INSERT ... ON CONFLICT
   - Update runs table last
   - No partial inconsistent commits

2. **Checker Requirements**:
   - Deterministic output
   - Stable fingerprint
   - No randomness or timestamps in fingerprints
   - Must handle malformed data and empty inputs

3. **API Guidelines**:
   - Only query finding_current for findings
   - No SELECT *
   - Always filter by tenant/workspace
   - Avoid full table scans and N+1 queries

4. **Code Quality Standards**:
   - Must pass pylint with no new warnings
   - No broad exception handling
   - Proper typing and documentation
   - No dead code or unused imports
   - Must use mypy and ruff

5. **Testing Requirements**:
   - All changes must be deterministic and idempotent
   - Must preserve tenant isolation
   - Must include tests for behavior changes
   - Cannot reduce test coverage

6. **Forbidden Changes**:
   - No tenant