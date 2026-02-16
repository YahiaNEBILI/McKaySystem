-- rule_id: aws.rds.correlation.s3.backup.lifecycle
-- name: RDS + S3 backup lifecycle correlation
-- enabled: true
-- required_check_ids: aws.rds.instances.stopped.storage, aws.rds.storage.overprovisioned, aws.backup.vaults.no.lifecycle, aws.backup.recovery.points.stale, aws.s3.bucket.lifecycle.missing

-- pipeline/correlation/rules/aws_rds_s3_backup_lifecycle.sql
--
-- Correlation: RDS backups created but not lifecycle-managed in S3
-- ---------------------------------------------------------------
-- Identifies RDS instances where:
--   1) Backups are enabled but stored in S3 buckets without lifecycle policies
--   2) Recovery points exist but are not being cleaned up (stale backups)
--   3) S3 buckets used for backups lack lifecycle management
--
-- Uses findings emitted by:
--   - checks/aws/rds_instances_optimizations.py (RDS instance findings)
--   - checks/aws/backup_vaults_audit.py (AWS Backup vault findings)
--   - checks/aws/s3_storage.py (S3 bucket findings)
--
-- Expected input: view "rule_input" created by CorrelationEngine.

WITH
-- 1) RDS instances that are stopped or have storage issues (potential backup candidates)
rds_signals AS (
  SELECT
    tenant_id,
    workspace_id,
    run_id,
    scope.account_id          AS account_id,
    scope.region              AS region,
    scope.resource_id         AS db_instance_identifier,
    scope.resource_arn        AS db_instance_arn,
    check_id,
    status,
    severity,
    fingerprint,
    estimated.monthly_cost    AS rds_monthly_cost
  FROM rule_input
  WHERE status IN ('fail', 'warn')
    AND check_id IN (
      'aws.rds.instances.stopped.storage',
      'aws.rds.storage.overprovisioned'
    )
    AND scope.resource_type = 'db_instance'
),

-- 2) AWS Backup vaults with no lifecycle (retention not configured)
backup_vault_signals AS (
  SELECT
    tenant_id,
    workspace_id,
    run_id,
    scope.account_id          AS account_id,
    scope.region              AS region,
    scope.resource_id         AS vault_name,
    scope.resource_arn        AS vault_arn,
    check_id,
    status,
    severity,
    fingerprint,
    estimated.monthly_cost    AS vault_monthly_cost
  FROM rule_input
  WHERE status = 'fail'
    AND check_id IN (
      'aws.backup.vaults.no.lifecycle',
      'aws.backup.recovery.points.stale'
    )
    AND scope.resource_type = 'backup_vault'
),

-- 3) S3 buckets without lifecycle policies (potential backup targets)
s3_lifecycle_signals AS (
  SELECT
    tenant_id,
    workspace_id,
    run_id,
    scope.account_id          AS account_id,
    scope.region              AS region,
    scope.resource_id         AS bucket_name,
    scope.resource_arn        AS bucket_arn,
    check_id,
    status,
    severity,
    fingerprint,
    estimated.monthly_cost    AS s3_monthly_cost
  FROM rule_input
  WHERE status = 'fail'
    AND check_id = 'aws.s3.bucket.lifecycle.missing'
    AND scope.resource_type = 'bucket'
),

-- 4) Aggregate signals per account/region
rds_backup_correlation AS (
  SELECT
    r.tenant_id,
    r.workspace_id,
    r.run_id,
    r.account_id,
    r.region,

    COUNT(DISTINCT r.db_instance_identifier) AS rds_instance_count,
    SUM(COALESCE(r.rds_monthly_cost, 0)) AS rds_cost_sum,

    -- Backup vault signals
    COUNT(DISTINCT v.vault_name) AS backup_vaults_no_lifecycle,
    COUNT(DISTINCT CASE WHEN v.check_id = 'aws.backup.recovery.points.stale' THEN v.vault_name END) AS vaults_with_stale_rp,
    SUM(COALESCE(v.vault_monthly_cost, 0)) AS backup_cost_sum,

    -- S3 lifecycle signals
    COUNT(DISTINCT s.bucket_name) AS s3_buckets_no_lifecycle,
    SUM(COALESCE(s.s3_monthly_cost, 0)) AS s3_cost_sum,

    -- Combined cost
    SUM(COALESCE(r.rds_monthly_cost, 0)) + SUM(COALESCE(v.vault_monthly_cost, 0)) + SUM(COALESCE(s.s3_monthly_cost, 0)) AS total_monthly_cost,

    -- Source fingerprints
    LIST(DISTINCT r.fingerprint) AS rds_fingerprints,
    LIST(DISTINCT v.fingerprint) AS backup_fingerprints,
    LIST(DISTINCT s.fingerprint) AS s3_fingerprints,

    -- Severity
    GREATEST(
      MAX(COALESCE(r.severity.score, 0)),
      MAX(COALESCE(v.severity.score, 0)),
      MAX(COALESCE(s.severity.score, 0))
    ) AS max_sev_score

  FROM rds_signals r
  LEFT JOIN backup_vault_signals v
    ON r.tenant_id = v.tenant_id
    AND r.workspace_id = v.workspace_id
    AND r.run_id = v.run_id
    AND r.account_id = v.account_id
    AND r.region = v.region
  LEFT JOIN s3_lifecycle_signals s
    ON r.tenant_id = s.tenant_id
    AND r.workspace_id = s.workspace_id
    AND r.run_id = s.run_id
    AND r.account_id = s.account_id
    AND r.region = s.region
  GROUP BY r.tenant_id, r.workspace_id, r.run_id, r.account_id, r.region
)

SELECT
  s.tenant_id,
  s.workspace_id,
  s.run_id,
  (SELECT MAX(run_ts) FROM rule_input WHERE tenant_id=s.tenant_id AND workspace_id=s.workspace_id AND run_id=s.run_id) AS run_ts,
  (SELECT ANY_VALUE(engine_name) FROM rule_input WHERE tenant_id=s.tenant_id AND workspace_id=s.workspace_id AND run_id=s.run_id) AS engine_name,
  (SELECT ANY_VALUE(engine_version) FROM rule_input WHERE tenant_id=s.tenant_id AND workspace_id=s.workspace_id AND run_id=s.run_id) AS engine_version,
  (SELECT ANY_VALUE(rulepack_version) FROM rule_input WHERE tenant_id=s.tenant_id AND workspace_id=s.workspace_id AND run_id=s.run_id) AS rulepack_version,

  struct_pack(
    cloud := (SELECT ANY_VALUE(scope.cloud) FROM rule_input WHERE tenant_id=s.tenant_id AND workspace_id=s.workspace_id AND run_id=s.run_id LIMIT 1),
    provider_partition := (SELECT ANY_VALUE(scope.provider_partition) FROM rule_input WHERE tenant_id=s.tenant_id AND workspace_id=s.workspace_id AND run_id=s.run_id LIMIT 1),
    billing_account_id := (SELECT ANY_VALUE(scope.billing_account_id) FROM rule_input WHERE tenant_id=s.tenant_id AND workspace_id=s.workspace_id AND run_id=s.run_id LIMIT 1),
    account_id := s.account_id,
    region := s.region,
    service := 'AmazonRDS',
    resource_type := 'account',
    resource_id := s.account_id,
    resource_arn := ''
  ) AS scope,

  'aws.rds.correlation.s3.backup.lifecycle' AS check_id,
  'RDS + S3 backup lifecycle correlation' AS check_name,
  'waste' AS category,
  'backup' AS sub_category,
  ['FinOps'] AS frameworks,

  CASE
    WHEN s.s3_buckets_no_lifecycle >= 3 AND s.backup_vaults_no_lifecycle >= 2 THEN 'fail'
    WHEN s.s3_buckets_no_lifecycle >= 1 OR s.backup_vaults_no_lifecycle >= 1 THEN 'warn'
    ELSE 'info'
  END AS status,

  CASE
    WHEN s.s3_buckets_no_lifecycle >= 5 OR s.vaults_with_stale_rp >= 3
    THEN struct_pack(level:='high', score:=850)
    WHEN s.s3_buckets_no_lifecycle >= 2 OR s.backup_vaults_no_lifecycle >= 2
    THEN struct_pack(level:='medium', score:=700)
    ELSE struct_pack(level:='low', score:=500)
  END AS severity,

  0 AS priority,

  'RDS backups stored in S3 without lifecycle management' AS title,

  (
    'Found ' || CAST(s.rds_instance_count AS VARCHAR) || ' RDS instance(s) with backup-related issues in region ' || s.region || '. '
    || 'Correlated findings: ' || CAST(s.backup_vaults_no_lifecycle AS VARCHAR) || ' backup vault(s) without lifecycle, '
    || CAST(s.s3_buckets_no_lifecycle AS VARCHAR) || ' S3 bucket(s) without lifecycle policy. '
    || CAST(s.vaults_with_stale_rp AS VARCHAR) || ' vault(s) have stale recovery points. '
    || CASE
         WHEN s.total_monthly_cost > 0
         THEN ('Estimated monthly backup cost ≈ $' || CAST(ROUND(s.total_monthly_cost, 2) AS VARCHAR) || '/month. ')
         ELSE ''
       END
    || 'Configure lifecycle policies on backup vaults to automatically expire old backups S3 buckets and.'
  ) AS message,

  'Implement lifecycle policies for RDS backups stored in S3. Configure retention rules on AWS Backup vaults and enable automatic cleanup of stale recovery points.' AS recommendation,

  '' AS remediation,
  [] AS links,

  struct_pack(
    monthly_savings := s.total_monthly_cost * 0.4,
    monthly_cost := s.total_monthly_cost,
    one_time_savings := NULL,
    confidence := 45,
    notes := 'Estimated savings assumes 40% of backup storage costs can be reduced by implementing lifecycle policies to expire old backups.'
  ) AS estimated,

  NULL AS actual,
  NULL AS lifecycle,
  map([],[]) AS tags,
  map([],[]) AS labels,
  map(
    ['rds_instance_count', 'backup_vaults_no_lifecycle', 's3_buckets_no_lifecycle', 'vaults_with_stale_rp', 'region'],
    [CAST(s.rds_instance_count AS VARCHAR), CAST(s.backup_vaults_no_lifecycle AS VARCHAR), CAST(s.s3_buckets_no_lifecycle AS VARCHAR), CAST(s.vaults_with_stale_rp AS VARCHAR), s.region]
  ) AS dimensions,
  map([],[]) AS metrics,
  ('{"correlation_rule":"rds_s3_backup_lifecycle","rds_instance_count":' || CAST(s.rds_instance_count AS VARCHAR) || ',"backup_vaults_no_lifecycle":' || CAST(s.backup_vaults_no_lifecycle AS VARCHAR) || ',"s3_buckets_no_lifecycle":' || CAST(s.s3_buckets_no_lifecycle AS VARCHAR) || ',"vaults_with_stale_rp":' || CAST(s.vaults_with_stale_rp AS VARCHAR) || ',"total_monthly_cost":' || CAST(ROUND(s.total_monthly_cost, 2) AS VARCHAR) || '}') AS metadata_json,

  s.rds_fingerprints || s.backup_fingerprints || s.s3_fingerprints AS source_fingerprints

FROM rds_backup_correlation s
WHERE s.rds_instance_count >= 1;
