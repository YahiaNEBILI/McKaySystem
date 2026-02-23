.PHONY: help check-layout api-dev migrate worker-run worker-run-all test-api test-worker sparse-worker sparse-backend ci-backend ci-worker production-gate pylint-ratchet

TENANT ?= default
WORKSPACE ?= default
OUT ?= data/finops_findings

help:
	@echo "Targets:"
	@echo "  make check-layout               - Enforce root structure policy"
	@echo "  make api-dev                    - Run Flask API locally"
	@echo "  make migrate                    - Apply DB migrations"
	@echo "  make worker-run TENANT=... WORKSPACE=..."
	@echo "  make worker-run-all TENANT=... WORKSPACE=... [OUT=...]"
	@echo "  make test-api                   - Run API-focused tests"
	@echo "  make test-worker                - Run worker/core tests"
	@echo "  make ci-backend                 - Run backend release checks"
	@echo "  make ci-worker                  - Run worker release checks"
	@echo "  make production-gate            - Run install/import/ruff/guardrail tests/pylint ratchet"
	@echo "  make pylint-ratchet             - Ensure pylint total/symbol/path debt does not regress"
	@echo "  make sparse-worker              - Apply CloudShell sparse checkout profile (worker)"
	@echo "  make sparse-backend             - Apply CloudShell sparse checkout profile (backend)"

check-layout:
	python tools/repo/check_layout.py

api-dev:
	python -m flask --app apps/flask_api/flask_app.py run --host 0.0.0.0 --port 5000

migrate:
	python -m apps.backend.db_migrate

worker-run:
	python -m apps.worker.runner --tenant "$(TENANT)" --workspace "$(WORKSPACE)" --out "$(OUT)"

worker-run-all:
	python -m apps.worker.cli run-all --tenant "$(TENANT)" --workspace "$(WORKSPACE)" --out "$(OUT)"

test-api:
	python -m pytest -q tests/api tests/test_db_migrate.py

test-worker:
	python -m pytest -q tests -k "not api"

ci-backend:
	bash deploy/backend/release_check.sh

ci-worker:
	bash deploy/worker/release_check.sh

pylint-ratchet:
	python tools/ci/pylint_ratchet.py

production-gate:
	python -m pip install --upgrade pip
	python -m pip install -e ".[dev]"
	python -m ruff check apps checks services pipeline infra contracts
	python -m pytest -q tests/test_repo_layout_policy.py tests/test_db_migrate.py tests/test_determinism_findings_output.py tests/test_determinism_correlation_output.py tests/api/test_flask_read_model_guardrails.py
	python tools/ci/pylint_ratchet.py

sparse-worker:
	bash tools/cloudshell/sparse_checkout_worker.sh .

sparse-backend:
	bash tools/cloudshell/sparse_checkout_backend.sh .
