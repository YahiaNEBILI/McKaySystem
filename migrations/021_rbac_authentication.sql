-- Migration 021: RBAC authentication and authorization foundation.
-- Adds users, roles, permissions, role_permissions, user_workspace_roles, api_keys, user_sessions.

CREATE TABLE IF NOT EXISTS users (
    tenant_id TEXT NOT NULL,
    workspace TEXT NOT NULL,
    user_id TEXT NOT NULL,
    email TEXT NOT NULL,
    password_hash TEXT NULL,
    full_name TEXT NULL,
    external_id TEXT NULL,
    auth_provider TEXT NOT NULL DEFAULT 'local',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_superadmin BOOLEAN NOT NULL DEFAULT FALSE,
    last_login_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace, user_id),
    CONSTRAINT uk_users_email UNIQUE (tenant_id, workspace, email)
);

CREATE TABLE IF NOT EXISTS roles (
    tenant_id TEXT NOT NULL,
    workspace TEXT NOT NULL,
    role_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NULL,
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace, role_id),
    CONSTRAINT uk_roles_name UNIQUE (tenant_id, workspace, name)
);

CREATE TABLE IF NOT EXISTS permissions (
    tenant_id TEXT NOT NULL,
    workspace TEXT NOT NULL,
    permission_id TEXT NOT NULL,
    name TEXT NOT NULL,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    description TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace, permission_id),
    CONSTRAINT uk_permissions_name UNIQUE (tenant_id, workspace, name)
);

CREATE TABLE IF NOT EXISTS role_permissions (
    tenant_id TEXT NOT NULL,
    workspace TEXT NOT NULL,
    role_id TEXT NOT NULL,
    permission_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace, role_id, permission_id),
    FOREIGN KEY (tenant_id, workspace, role_id)
      REFERENCES roles(tenant_id, workspace, role_id)
      ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, workspace, permission_id)
      REFERENCES permissions(tenant_id, workspace, permission_id)
      ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_workspace_roles (
    tenant_id TEXT NOT NULL,
    workspace TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    granted_by TEXT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace, user_id),
    FOREIGN KEY (tenant_id, workspace, user_id)
      REFERENCES users(tenant_id, workspace, user_id)
      ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, workspace, role_id)
      REFERENCES roles(tenant_id, workspace, role_id)
      ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS api_keys (
    tenant_id TEXT NOT NULL,
    workspace TEXT NOT NULL,
    key_id TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    key_type TEXT NOT NULL DEFAULT 'secret',
    name TEXT NOT NULL,
    description TEXT NULL,
    user_id TEXT NULL,
    last_used_at TIMESTAMPTZ NULL,
    expires_at TIMESTAMPTZ NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace, key_id),
    FOREIGN KEY (tenant_id, workspace, user_id)
      REFERENCES users(tenant_id, workspace, user_id)
      ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS user_sessions (
    tenant_id TEXT NOT NULL,
    workspace TEXT NOT NULL,
    session_id TEXT NOT NULL,
    session_token_hash TEXT NOT NULL,
    user_id TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace, session_id),
    CONSTRAINT uk_user_sessions_token_hash UNIQUE (tenant_id, workspace, session_token_hash),
    FOREIGN KEY (tenant_id, workspace, user_id)
      REFERENCES users(tenant_id, workspace, user_id)
      ON DELETE CASCADE
);

INSERT INTO roles (tenant_id, workspace, role_id, name, description, is_system)
VALUES
    ('default', 'default', 'admin', 'Administrator', 'Full access to all operations', TRUE),
    ('default', 'default', 'editor', 'Editor', 'Can view and modify findings', TRUE),
    ('default', 'default', 'viewer', 'Viewer', 'Read-only access', TRUE)
ON CONFLICT (tenant_id, workspace, role_id) DO NOTHING;

INSERT INTO permissions (
    tenant_id, workspace, permission_id, name, resource, action, description
)
VALUES
    ('default', 'default', 'findings:read', 'read_findings', 'findings', 'read', 'View findings and details'),
    (
        'default',
        'default',
        'findings:update',
        'update_findings',
        'findings',
        'update',
        'Update finding state'
    ),
    ('default', 'default', 'findings:delete', 'delete_findings', 'findings', 'delete', 'Delete findings'),
    ('default', 'default', 'runs:read', 'read_runs', 'runs', 'read', 'View run history'),
    ('default', 'default', 'runs:create', 'create_runs', 'runs', 'create', 'Trigger new runs'),
    ('default', 'default', 'runs:delete', 'delete_runs', 'runs', 'delete', 'Delete run data'),
    ('default', 'default', 'teams:read', 'read_teams', 'teams', 'read', 'View teams'),
    ('default', 'default', 'teams:create', 'create_teams', 'teams', 'create', 'Create teams'),
    ('default', 'default', 'teams:update', 'update_teams', 'teams', 'update', 'Update teams'),
    ('default', 'default', 'teams:delete', 'delete_teams', 'teams', 'delete', 'Delete teams'),
    (
        'default',
        'default',
        'teams:manage_members',
        'manage_team_members',
        'teams',
        'manage',
        'Manage team members'
    ),
    ('default', 'default', 'sla:read', 'read_sla', 'sla_policies', 'read', 'View SLA policies'),
    ('default', 'default', 'sla:create', 'create_sla', 'sla_policies', 'create', 'Create SLA policies'),
    ('default', 'default', 'sla:update', 'update_sla', 'sla_policies', 'update', 'Update SLA policies'),
    ('default', 'default', 'sla:delete', 'delete_sla', 'sla_policies', 'delete', 'Delete SLA policies'),
    ('default', 'default', 'users:read', 'read_users', 'users', 'read', 'View users'),
    ('default', 'default', 'users:create', 'create_users', 'users', 'create', 'Create users'),
    ('default', 'default', 'users:update', 'update_users', 'users', 'update', 'Update users'),
    ('default', 'default', 'users:delete', 'delete_users', 'users', 'delete', 'Delete users'),
    (
        'default',
        'default',
        'users:manage_roles',
        'manage_user_roles',
        'users',
        'manage_roles',
        'Assign user roles'
    ),
    ('default', 'default', 'api_keys:read', 'read_api_keys', 'api_keys', 'read', 'View API keys'),
    ('default', 'default', 'api_keys:create', 'create_api_keys', 'api_keys', 'create', 'Create API keys'),
    (
        'default',
        'default',
        'api_keys:revoke',
        'revoke_api_keys',
        'api_keys',
        'revoke',
        'Revoke API keys'
    ),
    ('default', 'default', 'admin:full', 'full_admin', 'admin', 'full', 'Full administrative access')
ON CONFLICT (tenant_id, workspace, permission_id) DO NOTHING;

INSERT INTO role_permissions (tenant_id, workspace, role_id, permission_id)
SELECT 'default', 'default', 'admin', p.permission_id
FROM permissions p
WHERE p.tenant_id = 'default' AND p.workspace = 'default'
ON CONFLICT (tenant_id, workspace, role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (tenant_id, workspace, role_id, permission_id)
SELECT 'default', 'default', 'editor', p.permission_id
FROM permissions p
WHERE p.tenant_id = 'default'
  AND p.workspace = 'default'
  AND p.permission_id NOT IN (
      'users:create',
      'users:delete',
      'users:manage_roles',
      'api_keys:create',
      'api_keys:revoke',
      'admin:full'
  )
ON CONFLICT (tenant_id, workspace, role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (tenant_id, workspace, role_id, permission_id)
SELECT 'default', 'default', 'viewer', p.permission_id
FROM permissions p
WHERE p.tenant_id = 'default'
  AND p.workspace = 'default'
  AND p.permission_id IN ('findings:read', 'runs:read', 'teams:read', 'sla:read')
ON CONFLICT (tenant_id, workspace, role_id, permission_id) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_users_scope_email
    ON users (tenant_id, workspace, email);
CREATE INDEX IF NOT EXISTS idx_users_scope_active
    ON users (tenant_id, workspace, is_active);
CREATE INDEX IF NOT EXISTS idx_user_workspace_roles_scope_user
    ON user_workspace_roles (tenant_id, workspace, user_id);
CREATE INDEX IF NOT EXISTS idx_user_workspace_roles_scope_role
    ON user_workspace_roles (tenant_id, workspace, role_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_active_hash
    ON api_keys (key_hash) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_api_keys_scope_user
    ON api_keys (tenant_id, workspace, user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_scope_expires
    ON user_sessions (tenant_id, workspace, expires_at);
