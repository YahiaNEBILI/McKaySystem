# Repository Structure Policy

Status: Canonical
Last reviewed: 2026-02-14

## Purpose

This policy keeps the monorepo operable while hosting:
- backend API/SaaS code
- worker/scanner/pipeline code

## Boundaries

### Backend
- Owned path: `apps/flask_api/`
- Deployment docs: `deploy/backend/`
- Must not contain cloud-scanner execution logic.

### Worker
- Owned implementation paths:
  - `apps/worker/` (entrypoint implementations)
  - `checks/`, `contracts/`, `pipeline/`, `infra/`, `services/`
- Deployment docs: `deploy/worker/`

## Root-Level Rules

Root should only contain:
- DB and project entrypoints (`db_migrate.py`, `db.py`)
- project metadata/config (`pyproject.toml`, `pytest.ini`, `README.md`, `LICENSE`)
- top-level owned directories (`apps/`, `docs/`, `checks/`, `pipeline/`, etc.)

Do not add new feature modules directly in root.

## Enforcement

Use:

```bash
python tools/repo/check_layout.py
```

This check fails when unknown root-level entries appear.

## CloudShell Sparse Workflows

Worker-focused sparse checkout:

```bash
bash tools/cloudshell/sparse_checkout_worker.sh .
```

Backend-focused sparse checkout:

```bash
bash tools/cloudshell/sparse_checkout_backend.sh .
```
