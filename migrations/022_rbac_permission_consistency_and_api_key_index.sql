-- Migration 022: RBAC permission consistency + scoped API key hash index.
-- - Normalize legacy runs:view permission ids to runs:read.
-- - Ensure runs:read uses canonical action/name values.
-- - Add scoped active API key hash index for tenant/workspace-safe lookups.

-- Backfill runs:read when legacy runs:view exists.
INSERT INTO permissions (
    tenant_id,
    workspace,
    permission_id,
    name,
    resource,
    action,
    description,
    created_at
)
SELECT
    p.tenant_id,
    p.workspace,
    'runs:read',
    'read_runs',
    'runs',
    'read',
    COALESCE(p.description, 'View run history'),
    p.created_at
FROM permissions p
WHERE p.permission_id = 'runs:view'
  AND NOT EXISTS (
      SELECT 1
      FROM permissions p2
      WHERE p2.tenant_id = p.tenant_id
        AND p2.workspace = p.workspace
        AND p2.permission_id = 'runs:read'
  );

-- Ensure canonical runs:read metadata.
UPDATE permissions
SET
    name = 'read_runs',
    resource = 'runs',
    action = 'read'
WHERE permission_id = 'runs:read'
  AND (name <> 'read_runs' OR resource <> 'runs' OR action <> 'read');

-- Re-map role permissions from legacy runs:view to runs:read.
INSERT INTO role_permissions (
    tenant_id,
    workspace,
    role_id,
    permission_id,
    created_at
)
SELECT
    rp.tenant_id,
    rp.workspace,
    rp.role_id,
    'runs:read',
    rp.created_at
FROM role_permissions rp
JOIN permissions p
  ON p.tenant_id = rp.tenant_id
 AND p.workspace = rp.workspace
 AND p.permission_id = 'runs:read'
WHERE rp.permission_id = 'runs:view'
ON CONFLICT (tenant_id, workspace, role_id, permission_id) DO NOTHING;

DELETE FROM role_permissions
WHERE permission_id = 'runs:view';

DELETE FROM permissions
WHERE permission_id = 'runs:view';

-- Scope API key hash lookups to tenant/workspace (plus active filter).
CREATE INDEX IF NOT EXISTS idx_api_keys_scope_hash_active
    ON api_keys (tenant_id, workspace, key_hash)
    WHERE is_active = TRUE;
