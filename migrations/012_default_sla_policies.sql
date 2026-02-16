-- Migration 012: Governance Layer - Default SLA Policies
-- Insert default SLA policies for common categories

-- Default SLA policies by category
-- These can be customized per tenant/workspace after initial setup
INSERT INTO sla_policy_category (tenant_id, workspace, category, sla_days, description) VALUES
    ('default', 'default', 'security', 7, 'Critical security findings require immediate attention'),
    ('default', 'default', 'governance', 30, 'General governance and compliance findings'),
    ('default', 'default', 'cost', 14, 'Cost optimization opportunities should be addressed quickly'),
    ('default', 'default', 'waste', 21, 'Idle/unused resources should be cleaned up'),
    ('default', 'default', 'inventory', 45, 'Asset inventory findings have longer resolution time'),
    ('default', 'default', 'backup.governance', 14, 'Backup compliance findings')
ON CONFLICT (tenant_id, workspace, category) DO NOTHING;

-- Example check-specific overrides (can be enabled per tenant)
-- Uncomment and customize as needed:
-- INSERT INTO sla_policy_check_override (tenant_id, workspace, check_id, sla_days, reason) VALUES
--     ('default', 'default', 'aws.ec2.underutilized', 10, 'EC2 rightsizing is high impact'),
--     ('default', 'default', 'aws.nat.orphaned', 7, 'Orphaned NAT gateways are costly')
-- ON CONFLICT (tenant_id, workspace, check_id) DO NOTHING;

-- Record migration
INSERT INTO schema_migrations (version) VALUES ('012') ON CONFLICT (version) DO NOTHING;
