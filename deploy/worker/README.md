# Worker Deployment

Deploy target:
- scan/checker and pipeline runtime (`apps/worker/`, `pipeline/`, `checks/`).

Typical runtime:
- AWS CloudShell
- cron/EventBridge/Step Functions runner host

Required env (depends on command):
- AWS credentials/role
- `TENANT_ID`, `WORKSPACE` (or command args)
- `DB_URL` only for ingest/migrate paths
- `PRICING_VERSION`, `PRICING_SOURCE` only when you want to override auto-derived pricing metadata

Recommended runner job pattern:

```bash
export TENANT_ID=acme
export WORKSPACE=prod
export PRICING_VERSION=aws_2026_02_01
export PRICING_SOURCE=snapshot

mckay run-all --db-url "$DB_URL" --out data/finops_findings
```

Alternative (explicit flags on scheduler command):

```bash
mckay run-all \
  --tenant acme \
  --workspace prod \
  --pricing-version aws_2026_02_01 \
  --pricing-source snapshot \
  --db-url "$DB_URL" \
  --out data/finops_findings
```

Release check:
- `bash deploy/worker/release_check.sh`

CI workflow:
- `.github/workflows/worker-ci.yml` (path-scoped worker checks)

Do not couple worker release cadence to backend API deployment.
