# RBAC Scope Bootstrap Runbook

Status: Canonical  
Last reviewed: 2026-02-22

This runbook defines the standard operator flow to initialize RBAC access for one `(tenant_id, workspace)` scope without manual SQL.

## What this does

`mckay bootstrap-scope` performs:
- RBAC scope seeding from `default/default` templates
- user create/update (idempotent)
- workspace role assignment (idempotent)
- optional API key issuance (new key material, non-idempotent by nature)

## Prerequisites

- `DB_URL` set to the target Postgres
- migrations applied (`mckay migrate`)
- target role exists in template scope (for default flow: `admin`)

## Recommended secure usage

Prefer environment variable password input over command-line literals:

```bash
export DB_URL="<postgres-url>"
export MCKAY_BOOTSTRAP_PASSWORD="<strong-password>"

mckay bootstrap-scope \
  --tenant acme \
  --workspace prod \
  --user-id u_admin \
  --email admin@acme.io \
  --full-name "Acme Admin"
```

Notes:
- Password is read from `MCKAY_BOOTSTRAP_PASSWORD` by default.
- The command normalizes email to lowercase.
- Output is JSON for scripting/automation.

## Optional API key issuance

```bash
mckay bootstrap-scope \
  --tenant acme \
  --workspace prod \
  --user-id u_admin \
  --email admin@acme.io \
  --create-api-key \
  --api-key-name "bootstrap-cli"
```

Important:
- Raw `api_key` appears once in command output.
- Treat command output as sensitive when `--create-api-key` is used.
- Re-running with `--create-api-key` creates another active key.

## Superadmin flag

Set `users.is_superadmin=true` for the bootstrapped user:

```bash
mckay bootstrap-scope \
  --tenant acme \
  --workspace prod \
  --user-id u_platform \
  --email platform-admin@company.io \
  --superadmin
```

Use sparingly. Prefer scoped roles unless global bypass is explicitly required.

## Validation checklist

1. Login:
```bash
curl -sS -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"acme\",
    \"workspace\": \"prod\",
    \"email\": \"admin@acme.io\",
    \"password\": \"<strong-password>\"
  }"
```
2. Confirm role:
```bash
curl -sS "$BASE_URL/api/users/u_admin/role?tenant_id=acme&workspace=prod" \
  -b /tmp/mck_cookies.txt
```
3. Confirm permissions include expected admin capabilities.

## Failure modes

- `role not found after bootstrap: <role_id>`:
  - template role missing from `default/default`
  - verify migrations and seeded templates
- missing password error:
  - set `MCKAY_BOOTSTRAP_PASSWORD` or pass `--password`
- DB connectivity errors:
  - verify `DB_URL` and migration alignment

## When SQL is still acceptable

Only break-glass scenarios where CLI cannot run.  
For normal operations, use this runbook command to keep onboarding deterministic and auditable.
