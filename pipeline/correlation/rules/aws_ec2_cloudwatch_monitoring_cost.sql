-- rule_id: aws.ec2.correlation.cloudwatch.monitoring.cost
-- name: EC2 + CloudWatch monitoring cost correlation
-- enabled: true
-- required_check_ids: aws.ec2.instances.underutilized, aws.ec2.instances.stopped.long, aws.logs.log.groups.retention.missing, aws.cloudwatch.alarms.high.count

-- pipeline/correlation/rules/aws_ec2_cloudwatch_monitoring_cost.sql
--
-- Correlation: EC2 instances paying for unused CloudWatch monitoring
-- ---------------------------------------------------------
-- Identifies EC2 instances that have CloudWatch metrics enabled but are either:
--   1) Stopped/idle (paying for detailed monitoring on unused instances)
--   2) Underutilized (paying for metrics on resources that don't need them)
--
-- Uses findings emitted by:
--   - checks/aws/ec2_instances.py (EC2 instance findings)
--   - checks/aws/cloudwatch_metrics_logs_cost.py (CloudWatch Logs/Metrics findings)
--
-- Expected input: view "rule_input" created by CorrelationEngine.

WITH
-- 1) EC2 instances that are stopped or underutilized
ec2_signals AS (
  SELECT
    tenant_id,
    workspace_id,
    run_id,
    scope.account_id          AS account_id,
    scope.region              AS region,
    scope.resource_id         AS instance_id,
    scope.resource_arn        AS instance_arn,
    check_id,
    status,
    severity,
    fingerprint,
    estimated.monthly_cost    AS instance_monthly_cost
  FROM rule_input
  WHERE status IN ('fail', 'warn')
    AND check_id IN (
      'aws.ec2.instances.underutilized',
      'aws.ec2.instances.stopped.long'
    )
    AND scope.resource_type = 'instance'
),

-- 2) CloudWatch log groups with no retention (potential cost waste)
cw_logs_signals AS (
  SELECT
    tenant_id,
    workspace_id,
    run_id,
    scope.account_id          AS account_id,
    scope.region              AS region,
    scope.resource_id         AS log_group_name,
    check_id,
    status,
    fingerprint,
    estimated.monthly_cost    AS log_group_monthly_cost
  FROM rule_input
  WHERE status = 'warn'
    AND check_id = 'aws.logs.log.groups.retention.missing'
    AND scope.resource_type = 'log_group'
),

-- 3) CloudWatch alarms count per account/region
cw_alarms_signals AS (
  SELECT
    tenant_id,
    workspace_id,
    run_id,
    scope.account_id          AS account_id,
    scope.region              AS region,
    MAX(CAST(dimensions['alarm_count'] AS INTEGER)) AS alarm_count,
    SUM(COALESCE(estimated.monthly_cost, 0)) AS alarms_monthly_cost,
    COUNT(DISTINCT fingerprint) AS alarm_fingerprints
  FROM rule_input
  WHERE status = 'warn'
    AND check_id = 'aws.cloudwatch.alarms.high.count'
    AND scope.resource_type = 'account'
  GROUP BY tenant_id, workspace_id, run_id, scope.account_id, scope.region
),

-- 4) Aggregate EC2 instances with CloudWatch signals per account/region
ec2_with_cw AS (
  SELECT
    e.tenant_id,
    e.workspace_id,
    e.run_id,
    e.account_id,
    e.region,

    COUNT(DISTINCT e.instance_id) AS ec2_instance_count,

    -- EC2 costs
    SUM(COALESCE(e.instance_monthly_cost, 0)) AS ec2_cost_sum,

    -- CW log groups without retention (correlated by account/region)
    COUNT(DISTINCT l.log_group_name) AS cw_log_groups_no_retention,
    SUM(COALESCE(l.log_group_monthly_cost, 0)) AS cw_logs_cost_sum,

    -- CW alarms
    COALESCE(a.alarm_count, 0) AS cw_alarm_count,
    COALESCE(a.alarms_monthly_cost, 0) AS cw_alarms_cost_sum,

    -- Source fingerprints
    LIST(DISTINCT e.fingerprint) AS ec2_fingerprints,

    -- Severity
    MAX(COALESCE(e.severity.score, 0)) AS max_sev_score

  FROM ec2_signals e
  LEFT JOIN cw_logs_signals l
    ON e.tenant_id = l.tenant_id
    AND e.workspace_id = l.workspace_id
    AND e.run_id = l.run_id
    AND e.account_id = l.account_id
    AND e.region = l.region
  LEFT JOIN cw_alarms_signals a
    ON e.tenant_id = a.tenant_id
    AND e.workspace_id = a.workspace_id
    AND e.run_id = a.run_id
    AND e.account_id = a.account_id
    AND e.region = a.region
  GROUP BY e.tenant_id, e.workspace_id, e.run_id, e.account_id, e.region, a.alarm_count, a.alarms_monthly_cost
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
    service := 'AmazonEC2',
    resource_type := 'account',
    resource_id := s.account_id,
    resource_arn := ''
  ) AS scope,

  'aws.ec2.correlation.cloudwatch.monitoring.cost' AS check_id,
  'EC2 + CloudWatch monitoring cost correlation' AS check_name,
  'waste' AS category,
  'cost_optimization' AS sub_category,
  ['FinOps'] AS frameworks,

  CASE
    WHEN s.ec2_instance_count >= 10 AND (s.cw_logs_cost_sum > 50 OR s.cw_alarms_cost_sum > 50) THEN 'fail'
    WHEN s.ec2_instance_count >= 5 OR s.cw_log_groups_no_retention >= 10 THEN 'warn'
    ELSE 'info'
  END AS status,

  CASE
    WHEN s.ec2_instance_count >= 20 OR (s.cw_logs_cost_sum + s.cw_alarms_cost_sum) >= 200
    THEN struct_pack(level:='high', score:=850)
    WHEN s.ec2_instance_count >= 10 OR s.cw_log_groups_no_retention >= 20
    THEN struct_pack(level:='medium', score:=700)
    ELSE struct_pack(level:='low', score:=500)
  END AS severity,

  0 AS priority,

  'EC2 instances with unused CloudWatch monitoring cost' AS title,

  (
    'Found ' || CAST(s.ec2_instance_count AS VARCHAR) || ' stopped/underutilized EC2 instance(s) in region ' || s.region || '. '
    || 'Correlated CloudWatch data: ' || CAST(s.cw_log_groups_no_retention AS VARCHAR) || ' log group(s) without retention, '
    || CAST(s.cw_alarm_count AS VARCHAR) || ' alarm(s). '
    || CASE
         WHEN (s.cw_logs_cost_sum + s.cw_alarms_cost_sum) > 0
         THEN ('Estimated CloudWatch cost ≈ $' || CAST(ROUND(s.cw_logs_cost_sum + s.cw_alarms_cost_sum, 2) AS VARCHAR) || '/month. ')
         ELSE ''
       END
    || 'Consider disabling detailed monitoring for stopped instances and removing unused log groups.'
  ) AS message,

  'Review CloudWatch monitoring costs for stopped/underutilized EC2 instances. Disable detailed monitoring for idle instances, set retention policies on log groups, and remove unused alarms.' AS recommendation,

  '' AS remediation,
  [] AS links,

  struct_pack(
    monthly_savings := GREATEST(s.cw_logs_cost_sum, s.cw_alarms_cost_sum) * 0.3,
    monthly_cost := s.cw_logs_cost_sum + s.cw_alarms_cost_sum,
    one_time_savings := NULL,
    confidence := 40,
    notes := 'Estimated savings assumes 30% of CloudWatch costs can be eliminated by optimizing monitoring on idle EC2 instances.'
  ) AS estimated,

  NULL AS actual,
  NULL AS lifecycle,
  map([],[]) AS tags,
  map([],[]) AS labels,
  map(
    ['ec2_instance_count', 'cw_log_groups_no_retention', 'cw_alarm_count', 'region'],
    [CAST(s.ec2_instance_count AS VARCHAR), CAST(s.cw_log_groups_no_retention AS VARCHAR), CAST(s.cw_alarm_count AS VARCHAR), s.region]
  ) AS dimensions,
  map([],[]) AS metrics,
  ('{"correlation_rule":"ec2_cloudwatch_monitoring_cost","ec2_instance_count":' || CAST(s.ec2_instance_count AS VARCHAR) || ',"cw_log_groups_no_retention":' || CAST(s.cw_log_groups_no_retention AS VARCHAR) || ',"cw_alarm_count":' || CAST(s.cw_alarm_count AS VARCHAR) || ',"total_monthly_cost":' || CAST(ROUND(s.cw_logs_cost_sum + s.cw_alarms_cost_sum, 2) AS VARCHAR) || '}') AS metadata_json,

  s.ec2_fingerprints AS source_fingerprints

FROM ec2_with_cw s
WHERE s.ec2_instance_count >= 1;
