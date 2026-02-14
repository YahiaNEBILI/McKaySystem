-- rule_id: aws.backup.correlation.vault.risk
-- name: AWS Backup vault risk (correlated)
-- enabled: true
-- required_check_ids: aws.backup.vaults.no.lifecycle, aws.backup.vaults.access.policy.misconfig, aws.backup.recovery.points.stale, aws.backup.rules.no.lifecycle, aws.backup.plans.no.selections

-- pipeline/correlation/rules/aws_backup_vault_risk.sql
--
-- Correlation: AWS Backup "Vault Risk" meta finding
-- -------------------------------------------------
-- Uses findings emitted by:
--   - checks/aws/backup_vaults_audit.py
--   - checks/aws/backup_plans_audit.py
--
-- Expected input: view "rule_input" created by CorrelationEngine (subset of findings_base).
--
-- NOTE ABOUT JOIN KEYS:
-- This rule assumes "vault-centric" findings use scope.resource_type='backup_vault'
-- and scope.resource_id=<BackupVaultName>.
-- If your stale recovery point check uses scope.resource_type='recovery_point', ensure
-- it still includes the vault name in `dimensions['vault_name']` (or adjust below).
--
-- REQUIRED CHECK IDS for this rule:
--   aws.backup.vaults.no.lifecycle
--   aws.backup.vaults.access.policy.misconfig
--   aws.backup.recovery.points.stale
--   aws.backup.rules.no.lifecycle
--   aws.backup.plans.no.selections

WITH
-- 1) Anchor vaults: any vault with at least one relevant vault-level finding
vault_anchors AS (
  SELECT
    tenant_id,
    workspace_id,
    run_id,
    run_ts,
    engine_name,
    engine_version,
    rulepack_version,
    scope,
    fingerprint,
    check_id,
    status,
    severity
  FROM rule_input
  WHERE status = 'fail'
    AND check_id IN (
      'aws.backup.vaults.no.lifecycle',
      'aws.backup.vaults.access.policy.misconfig'
    )
    AND scope.resource_type = 'backup_vault'
),

-- 2) Vault signal counts from vault-level checks
vault_signals AS (
  SELECT
    tenant_id,
    workspace_id,
    run_id,
    scope.account_id          AS account_id,
    scope.region              AS region,
    scope.resource_id         AS vault_name,
    scope.resource_arn        AS vault_arn,

    -- Presence signals
    MAX(CASE WHEN check_id = 'aws.backup.vaults.no.lifecycle' THEN 1 ELSE 0 END)          AS sig_no_guardrail,
    MAX(CASE WHEN check_id = 'aws.backup.vaults.access.policy.misconfig' THEN 1 ELSE 0 END) AS sig_policy_misconfig,

    -- Worst severity among vault-level findings (score)
    MAX(COALESCE(severity.score, 0)) AS vault_max_sev_score,

    -- Collect fingerprints for deterministic correlation identity
    LIST(DISTINCT fingerprint) AS vault_source_fps
  FROM vault_anchors
  GROUP BY ALL
),

-- 3) Stale recovery points signal (joined by vault)
--    We try two approaches:
--      (A) vault-centric scope (scope.resource_type='backup_vault' and resource_id=vault_name)
--      (B) if stale recovery points are scoped to 'recovery_point', we read vault_name from dimensions['vault_name']
stale_rp_by_vault AS (
  SELECT
    tenant_id,
    workspace_id,
    run_id,
    scope.account_id AS account_id,
    scope.region     AS region,

    CASE
      WHEN scope.resource_type = 'backup_vault' THEN scope.resource_id
      ELSE COALESCE(dimensions['vault_name'], '')
    END AS vault_name,

    COUNT(*) AS stale_rp_count,

    -- Sum of monthly cost estimates (may be NULL)
    SUM(COALESCE(estimated.monthly_cost, 0)) AS stale_rp_monthly_cost_sum,

    LIST(DISTINCT fingerprint) AS stale_source_fps
  FROM rule_input
  WHERE status = 'fail'
    AND check_id = 'aws.backup.recovery.points.stale'
  GROUP BY ALL
),

-- 4) Plan rules missing lifecycle, grouped by target vault if present
--    Assumes your plan checker places vault name in dimensions under one of these keys:
--      - target_vault
--      - target_vault_name
--      - backup_vault
--    (Adjust if your checker uses different key.)
rules_no_lifecycle_by_vault AS (
  SELECT
    tenant_id,
    workspace_id,
    run_id,
    scope.account_id AS account_id,
    scope.region     AS region,
    COALESCE(
      dimensions['target_vault_name'],
      dimensions['target_vault'],
      dimensions['backup_vault'],
      ''
    ) AS vault_name,

    COUNT(*) AS rules_no_lifecycle_count,
    LIST(DISTINCT fingerprint) AS rules_source_fps
  FROM rule_input
  WHERE status = 'fail'
    AND check_id = 'aws.backup.rules.no.lifecycle'
  GROUP BY ALL
),

-- 5) Optional: plans with no selections (weak supporting signal; not joined to vault)
--    Kept as tenant/run-level info for message context only.
plans_no_selections AS (
  SELECT
    tenant_id,
    workspace_id,
    run_id,
    COUNT(*) AS plans_no_selections_count
  FROM rule_input
  WHERE status = 'fail'
    AND check_id = 'aws.backup.plans.no.selections'
  GROUP BY ALL
),

-- 6) Combine signals per vault
combined AS (
  SELECT
    v.tenant_id,
    v.workspace_id,
    v.run_id,
    v.account_id,
    v.region,
    v.vault_name,
    v.vault_arn,

    v.sig_no_guardrail,
    v.sig_policy_misconfig,

    COALESCE(s.stale_rp_count, 0) AS stale_rp_count,
    COALESCE(s.stale_rp_monthly_cost_sum, 0) AS stale_rp_monthly_cost_sum,

    COALESCE(r.rules_no_lifecycle_count, 0) AS rules_no_lifecycle_count,

    -- Signal score for emission thresholding
    (v.sig_no_guardrail
     + v.sig_policy_misconfig
     + CASE WHEN COALESCE(s.stale_rp_count, 0) > 0 THEN 1 ELSE 0 END
     + CASE WHEN COALESCE(r.rules_no_lifecycle_count, 0) > 0 THEN 1 ELSE 0 END
    ) AS signal_count,

    v.vault_max_sev_score,

    -- Source fingerprints for deterministic meta finding identity
    LIST_CONCAT(
      v.vault_source_fps,
      COALESCE(s.stale_source_fps, []),
      COALESCE(r.rules_source_fps, [])
    ) AS source_fingerprints
  FROM vault_signals v
  LEFT JOIN stale_rp_by_vault s
    ON v.tenant_id = s.tenant_id
   AND v.workspace_id = s.workspace_id
   AND v.run_id = s.run_id
   AND v.account_id = s.account_id
   AND v.region = s.region
   AND v.vault_name = s.vault_name
  LEFT JOIN rules_no_lifecycle_by_vault r
    ON v.tenant_id = r.tenant_id
   AND v.workspace_id = r.workspace_id
   AND v.run_id = r.run_id
   AND v.account_id = r.account_id
   AND v.region = r.region
   AND v.vault_name = r.vault_name
)

-- 7) Emit meta findings
SELECT
  c.tenant_id,
  c.workspace_id,
  c.run_id,
  -- Use the same run_ts as anchors; if multiple, we take MAX
  (SELECT MAX(run_ts) FROM rule_input WHERE tenant_id=c.tenant_id AND workspace_id=c.workspace_id AND run_id=c.run_id) AS run_ts,

  -- Engine metadata (carry through)
  (SELECT ANY_VALUE(engine_name) FROM rule_input WHERE tenant_id=c.tenant_id AND workspace_id=c.workspace_id AND run_id=c.run_id) AS engine_name,
  (SELECT ANY_VALUE(engine_version) FROM rule_input WHERE tenant_id=c.tenant_id AND workspace_id=c.workspace_id AND run_id=c.run_id) AS engine_version,
  (SELECT ANY_VALUE(rulepack_version) FROM rule_input WHERE tenant_id=c.tenant_id AND workspace_id=c.workspace_id AND run_id=c.run_id) AS rulepack_version,

  -- Anchor scope: vault
  struct_pack(
    cloud := (SELECT ANY_VALUE(scope.cloud) FROM vault_anchors va
              WHERE va.tenant_id=c.tenant_id AND va.workspace_id=c.workspace_id AND va.run_id=c.run_id
                AND va.scope.account_id=c.account_id AND va.scope.region=c.region AND va.scope.resource_id=c.vault_name
              LIMIT 1),
    provider_partition := (SELECT ANY_VALUE(scope.provider_partition) FROM vault_anchors va
                           WHERE va.tenant_id=c.tenant_id AND va.workspace_id=c.workspace_id AND va.run_id=c.run_id
                             AND va.scope.account_id=c.account_id AND va.scope.region=c.region AND va.scope.resource_id=c.vault_name
                           LIMIT 1),
    billing_account_id := (SELECT ANY_VALUE(scope.billing_account_id) FROM vault_anchors va
                           WHERE va.tenant_id=c.tenant_id AND va.workspace_id=c.workspace_id AND va.run_id=c.run_id
                             AND va.scope.account_id=c.account_id AND va.scope.region=c.region AND va.scope.resource_id=c.vault_name
                           LIMIT 1),
    account_id := c.account_id,
    region := c.region,
    service := 'AWSBackup',
    resource_type := 'backup_vault',
    resource_id := c.vault_name,
    resource_arn := c.vault_arn
  ) AS scope,

  -- Meta check identity
  'aws.backup.correlation.vault.risk' AS check_id,
  'AWS Backup vault risk (correlated)' AS check_name,
  'governance' AS category,
  '' AS sub_category,
  ['FinOps'] AS frameworks,

  'fail' AS status,

  -- Severity: escalate based on signal_count and presence of stale recovery points
  CASE
    WHEN c.signal_count >= 3 THEN struct_pack(level:='high', score:=900)
    WHEN c.signal_count = 2 AND c.stale_rp_count > 0 THEN struct_pack(level:='high', score:=850)
    ELSE struct_pack(level:='medium', score:=750)
  END AS severity,

  0 AS priority,

  'Backup vault has correlated retention / governance risks' AS title,

  -- Message includes signal breakdown
  (
    'Vault "' || c.vault_name || '" has ' || CAST(c.signal_count AS VARCHAR) || ' correlated risk signals. '
    || 'Signals: '
    || CASE WHEN c.sig_no_guardrail = 1 THEN '[no_retention_guardrail] ' ELSE '' END
    || CASE WHEN c.sig_policy_misconfig = 1 THEN '[access_policy_misconfig] ' ELSE '' END
    || CASE WHEN c.stale_rp_count > 0 THEN ('[stale_recovery_points=' || CAST(c.stale_rp_count AS VARCHAR) || '] ') ELSE '' END
    || CASE WHEN c.rules_no_lifecycle_count > 0 THEN ('[rules_missing_lifecycle=' || CAST(c.rules_no_lifecycle_count AS VARCHAR) || '] ') ELSE '' END
    || COALESCE(
         (
           SELECT
             CASE
               WHEN p.plans_no_selections_count > 0
               THEN (' Additional context: ' || CAST(p.plans_no_selections_count AS VARCHAR) || ' backup plan(s) have no selections.')
               ELSE ''
             END
           FROM plans_no_selections p
           WHERE p.tenant_id=c.tenant_id AND p.workspace_id=c.workspace_id AND p.run_id=c.run_id
         ),
         ''
       )
  ) AS message,

  'Ensure Vault Lock guardrails and plan rule lifecycle are enforced; tighten vault access policy; prune stale recovery points according to policy.' AS recommendation,

  '' AS remediation,
  [] AS links,

  -- Estimated rollup (primarily cost signal from stale recovery points)
  struct_pack(
    monthly_savings := NULL,
    monthly_cost := CASE WHEN c.stale_rp_monthly_cost_sum > 0 THEN c.stale_rp_monthly_cost_sum ELSE NULL END,
    one_time_savings := NULL,
    confidence := CASE WHEN c.stale_rp_monthly_cost_sum > 0 THEN 50 ELSE 10 END,
    notes := CASE
      WHEN c.stale_rp_monthly_cost_sum > 0
      THEN 'monthly_cost is sum of stale recovery point estimates for this vault.'
      ELSE 'No cost rollup available; correlated governance signal.'
    END
  ) AS estimated,

  NULL AS actual,
  NULL AS lifecycle,
  map([],[]) AS tags,
  map([],[]) AS labels,
  -- Dimensions (for UI filters)
  map(
    ['vault_name','vault_arn','signal_count','stale_rp_count','rules_no_lifecycle_count'],
    [c.vault_name, COALESCE(c.vault_arn,''), CAST(c.signal_count AS VARCHAR), CAST(c.stale_rp_count AS VARCHAR), CAST(c.rules_no_lifecycle_count AS VARCHAR)]
  ) AS dimensions,
  map([],[]) AS metrics,
  -- Optional metadata_json for debugging/audit
  ('{"correlation_rule":"vault_risk","signal_count":' || CAST(c.signal_count AS VARCHAR) || '}') AS metadata_json,

  -- Provide source fingerprints for deterministic identity in engine.py
  c.source_fingerprints AS source_fingerprints

FROM combined c
WHERE c.signal_count >= 2
