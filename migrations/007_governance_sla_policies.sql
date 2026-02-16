-- Migration 007: Governance Layer - SLA Policies
-- Adds SLA policy tables for category-based SLA management with check-level overrides

-- SLA policy by category (primary SLA definition)
CREATE TABLE IF NOT EXISTS sla_policy_category (
    tenant_id TEXT NOT NULL,
    workspace TEXT NOT NULL,
    category TEXT NOT NULL,
    sla_days INTEGER NOT NULL,
    description TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace, category)
);

-- SLA override by specific check_id
CREATE TABLE IF NOT EXISTS sla_policy_check_override (
    tenant_id TEXT NOT NULL,
    workspace TEXT NOT NULL,
    check_id TEXT NOT NULL,
    sla_days INTEGER NOT NULL,
    reason TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace, check_id)
);

-- Indexes for efficient SLA lookup
CREATE INDEX IF NOT EXISTS idx_sla_policy_category ON sla_policy_category (tenant_id, workspace);
CREATE INDEX IF NOT EXISTS idx_sla_policy_check_override ON sla_policy_check_override (tenant_id, workspace, check_id);

-- Record migration
INSERT INTO schema_migrations (version) VALUES ('007') ON CONFLICT (version) DO NOTHING;
