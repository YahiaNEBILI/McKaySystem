.PHONY: help check-layout api-dev migrate worker-run worker-run-all test-api test-worker sparse-worker sparse-backend ci-backend ci-worker

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
	@echo "  make sparse-worker              - Apply CloudShell sparse checkout profile (worker)"
	@echo "  make sparse-backend             - Apply CloudShell sparse checkout profile (backend)"

check-layout:
	python tools/repo/check_layout.py

api-dev:
	python -m flask --app apps/flask_api/flask_app.py run --host 0.0.0.0 --port 5000

migrate:
	python db_migrate.py

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

sparse-worker:
	bash tools/cloudshell/sparse_checkout_worker.sh .

sparse-backend:
	bash tools/cloudshell/sparse_checkout_backend.sh .
