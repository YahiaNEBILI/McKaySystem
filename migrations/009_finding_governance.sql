-- Migration 009: Governance Layer - Finding Governance State
-- Adds finding_governance table for ownership, aging, and SLA tracking

-- Extended finding governance state
CREATE TABLE IF NOT EXISTS finding_governance (
    tenant_id TEXT NOT NULL,
    workspace TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    
    -- Two-clock aging model
    first_detected_at TIMESTAMPTZ NOT NULL,
    first_opened_at TIMESTAMPTZ NULL,
    
    -- Ownership
    owner_id TEXT NULL,
    owner_email TEXT NULL,
    owner_name TEXT NULL,
    team_id TEXT NULL,
    
    -- SLA tracking
    sla_deadline TIMESTAMPTZ NULL,
    sla_breached_at TIMESTAMPTZ NULL,
    sla_extended_count INTEGER NOT NULL DEFAULT 0,
    sla_extension_reason TEXT NULL,
    
    -- Manual override flags
    resolution_override BOOLEAN NOT NULL DEFAULT FALSE,
    resolution_override_reason TEXT NULL,
    
    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    PRIMARY KEY (tenant_id, workspace, fingerprint),
    
    FOREIGN KEY (tenant_id, workspace, team_id) 
        REFERENCES teams(tenant_id, workspace, team_id) ON DELETE SET NULL
);

-- Add first_detected_at and first_opened_at to existing finding_state_current
ALTER TABLE finding_state_current 
    ADD COLUMN IF NOT EXISTS first_detected_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS first_opened_at TIMESTAMPTZ NULL;

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_finding_governance_tenant_workspace_team ON finding_governance (tenant_id, workspace, team_id);
CREATE INDEX IF NOT EXISTS idx_finding_governance_tenant_workspace_owner ON finding_governance (tenant_id, workspace, owner_id);
CREATE INDEX IF NOT EXISTS idx_finding_governance_tenant_workspace_sla_breached ON finding_governance (tenant_id, workspace, sla_breached_at);
CREATE INDEX IF NOT EXISTS idx_finding_governance_tenant_workspace_sla_deadline ON finding_governance (tenant_id, workspace, sla_deadline);

-- Record migration
INSERT INTO schema_migrations (version) VALUES ('009') ON CONFLICT (version) DO NOTHING;
