-- Migration 023: RBAC tenant/workspace bootstrap seeding.
-- Copies system RBAC templates from default/default into all discovered scopes.
-- Idempotent by design via ON CONFLICT DO NOTHING.

WITH scopes AS (
    SELECT tenant_id, workspace FROM users
    UNION
    SELECT tenant_id, workspace FROM api_keys
    UNION
    SELECT tenant_id, workspace FROM user_sessions
    UNION
    SELECT tenant_id, workspace FROM user_workspace_roles
    UNION
    SELECT tenant_id, workspace FROM roles
    UNION
    SELECT tenant_id, workspace FROM permissions
    UNION
    SELECT tenant_id, workspace FROM role_permissions
)
INSERT INTO roles (
    tenant_id,
    workspace,
    role_id,
    name,
    description,
    is_system
)
SELECT
    s.tenant_id,
    s.workspace,
    src.role_id,
    src.name,
    src.description,
    src.is_system
FROM scopes s
JOIN roles src
  ON src.tenant_id = 'default'
 AND src.workspace = 'default'
WHERE NOT (s.tenant_id = 'default' AND s.workspace = 'default')
ON CONFLICT (tenant_id, workspace, role_id) DO NOTHING;

WITH scopes AS (
    SELECT tenant_id, workspace FROM users
    UNION
    SELECT tenant_id, workspace FROM api_keys
    UNION
    SELECT tenant_id, workspace FROM user_sessions
    UNION
    SELECT tenant_id, workspace FROM user_workspace_roles
    UNION
    SELECT tenant_id, workspace FROM roles
    UNION
    SELECT tenant_id, workspace FROM permissions
    UNION
    SELECT tenant_id, workspace FROM role_permissions
)
INSERT INTO permissions (
    tenant_id,
    workspace,
    permission_id,
    name,
    resource,
    action,
    description
)
SELECT
    s.tenant_id,
    s.workspace,
    src.permission_id,
    src.name,
    src.resource,
    src.action,
    src.description
FROM scopes s
JOIN permissions src
  ON src.tenant_id = 'default'
 AND src.workspace = 'default'
WHERE NOT (s.tenant_id = 'default' AND s.workspace = 'default')
ON CONFLICT (tenant_id, workspace, permission_id) DO NOTHING;

WITH scopes AS (
    SELECT tenant_id, workspace FROM users
    UNION
    SELECT tenant_id, workspace FROM api_keys
    UNION
    SELECT tenant_id, workspace FROM user_sessions
    UNION
    SELECT tenant_id, workspace FROM user_workspace_roles
    UNION
    SELECT tenant_id, workspace FROM roles
    UNION
    SELECT tenant_id, workspace FROM permissions
    UNION
    SELECT tenant_id, workspace FROM role_permissions
)
INSERT INTO role_permissions (
    tenant_id,
    workspace,
    role_id,
    permission_id
)
SELECT
    s.tenant_id,
    s.workspace,
    src.role_id,
    src.permission_id
FROM scopes s
JOIN role_permissions src
  ON src.tenant_id = 'default'
 AND src.workspace = 'default'
JOIN roles r
  ON r.tenant_id = s.tenant_id
 AND r.workspace = s.workspace
 AND r.role_id = src.role_id
JOIN permissions p
  ON p.tenant_id = s.tenant_id
 AND p.workspace = s.workspace
 AND p.permission_id = src.permission_id
WHERE NOT (s.tenant_id = 'default' AND s.workspace = 'default')
ON CONFLICT (tenant_id, workspace, role_id, permission_id) DO NOTHING;
