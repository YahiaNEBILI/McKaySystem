-- Migration 008: Governance Layer - Team Management
-- Adds tables for team hierarchy, members, and auto-assignment rules

-- Teams table (hierarchical support)
CREATE TABLE IF NOT EXISTS teams (
    tenant_id TEXT NOT NULL,
    workspace TEXT NOT NULL,
    team_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NULL,
    parent_team_id TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace, team_id)
);

-- Team members
CREATE TABLE IF NOT EXISTS team_members (
    tenant_id TEXT NOT NULL,
    workspace TEXT NOT NULL,
    team_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    user_email TEXT NOT NULL,
    user_name TEXT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace, team_id, user_id),
    FOREIGN KEY (tenant_id, workspace, team_id) 
        REFERENCES teams(tenant_id, workspace, team_id) ON DELETE CASCADE
);

-- Auto-assignment rules (account → team)
CREATE TABLE IF NOT EXISTS team_auto_assign_account (
    tenant_id TEXT NOT NULL,
    workspace TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    account_id_pattern TEXT NOT NULL,
    team_id TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace, rule_id),
    FOREIGN KEY (tenant_id, workspace, team_id) 
        REFERENCES teams(tenant_id, workspace, team_id) ON DELETE CASCADE
);

-- Auto-assignment rules (OU → team)
CREATE TABLE IF NOT EXISTS team_auto_assign_ou (
    tenant_id TEXT NOT NULL,
    workspace TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    ou_name_pattern TEXT NOT NULL,
    team_id TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace, rule_id),
    FOREIGN KEY (tenant_id, workspace, team_id) 
        REFERENCES teams(tenant_id, workspace, team_id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_teams_tenant_workspace ON teams (tenant_id, workspace);
CREATE INDEX IF NOT EXISTS idx_team_members_tenant_workspace_user ON team_members (tenant_id, workspace, user_id);
CREATE INDEX IF NOT EXISTS idx_team_members_tenant_workspace_team ON team_members (tenant_id, workspace, team_id);
CREATE INDEX IF NOT EXISTS idx_team_auto_assign_account ON team_auto_assign_account (tenant_id, workspace, account_id_pattern);
CREATE INDEX IF NOT EXISTS idx_team_auto_assign_ou ON team_auto_assign_ou (tenant_id, workspace, ou_name_pattern);

-- Record migration
INSERT INTO schema_migrations (version) VALUES ('008') ON CONFLICT (version) DO NOTHING;
