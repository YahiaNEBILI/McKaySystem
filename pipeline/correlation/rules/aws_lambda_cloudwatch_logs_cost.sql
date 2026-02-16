-- rule_id: aws.lambda.correlation.cloudwatch.logs.cost
-- name: Lambda + CloudWatch Logs cost correlation
-- enabled: true
-- required_check_ids: aws.logs.log.groups.retention.missing, aws.lambda.functions.unused, aws.cloudwatch.alarms.high.count

-- pipeline/correlation/rules/aws_lambda_cloudwatch_logs_cost.sql
--
-- Correlation: Lambda functions paying for CloudWatch Logs they never read
-- -----------------------------------------------------------------------
-- Identifies Lambda functions where:
--   1) CloudWatch Logs are generated but have no retention policy
--   2) Log groups exist without being actively monitored
--   3) High alarm counts suggest potential misconfiguration
--
-- Uses findings emitted by:
--   - checks/aws/cloudwatch_metrics_logs_cost.py (CloudWatch Logs/Metrics findings)
--   - Any Lambda checker that emits unused/invoked findings
--
-- NOTE: This rule correlates CloudWatch Logs signals with Lambda functions.
-- If no Lambda-specific checker exists, it uses CloudWatch Logs signals
-- filtered by Lambda-appropriate log group patterns (/aws/lambda/).
--
-- Expected input: view "rule_input" created by CorrelationEngine.

WITH
-- 1) CloudWatch Log groups without retention (potential Lambda log waste)
lambda_log_groups AS (
  SELECT
    tenant_id,
    workspace_id,
    run_id,
    scope.account_id          AS account_id,
    scope.region              AS region,
    scope.resource_id         AS log_group_name,
    scope.resource_arn        AS log_group_arn,
    check_id,
    status,
    severity,
    fingerprint,
    estimated.monthly_cost    AS log_monthly_cost,
    dimensions
  FROM rule_input
  WHERE status = 'warn'
    AND check_id = 'aws.logs.log.groups.retention.missing'
    AND scope.resource_type = 'log_group'
),

-- 2) Identify Lambda-related log groups (pattern: /aws/lambda/)
lambda_logs AS (
  SELECT
    l.tenant_id,
    l.workspace_id,
    l.run_id,
    l.account_id,
    l.region,
    l.log_group_name,
    l.log_group_arn,
    l.check_id,
    l.status,
    l.severity,
    l.fingerprint,
    l.log_monthly_cost
  FROM lambda_log_groups l
  WHERE l.log_group_name LIKE '/aws/lambda/%'
     OR l.log_group_name LIKE '/aws/lambda/%%'
),

-- 3) Lambda function signals (if Lambda checker exists)
lambda_signals AS (
  SELECT
    tenant_id,
    workspace_id,
    run_id,
    scope.account_id          AS account_id,
    scope.region              AS region,
    scope.resource_id         AS function_name,
    scope.resource_arn        AS function_arn,
    check_id,
    status,
    severity,
    fingerprint,
    estimated.monthly_cost    AS lambda_monthly_cost
  FROM rule_input
  WHERE status IN ('fail', 'warn')
    AND check_id LIKE 'aws.lambda.%'
    AND scope.resource_type = 'function'
),

-- 4) CloudWatch alarms that might relate to Lambda
lambda_alarms AS (
  SELECT
    tenant_id,
    workspace_id,
    run_id,
    scope.account_id          AS account_id,
    scope.region              AS region,
    MAX(CAST(dimensions['alarm_count'] AS INTEGER)) AS alarm_count,
    SUM(COALESCE(estimated.monthly_cost, 0)) AS alarms_cost
  FROM rule_input
  WHERE status = 'warn'
    AND check_id = 'aws.cloudwatch.alarms.high.count'
    AND scope.resource_type = 'account'
  GROUP BY tenant_id, workspace_id, run_id, scope.account_id, scope.region
),

-- 5) Aggregate Lambda + CloudWatch Logs correlation
lambda_logs_correlation AS (
  SELECT
    l.tenant_id,
    l.workspace_id,
    l.run_id,
    l.account_id,
    l.region,

    -- Lambda log group counts
    COUNT(DISTINCT l.log_group_name) AS lambda_log_groups_count,
    SUM(COALESCE(l.log_monthly_cost, 0)) AS lambda_logs_cost_sum,

    -- Lambda function counts (if available)
    COUNT(DISTINCT fn.function_name) AS lambda_functions_count,
    SUM(COALESCE(fn.lambda_monthly_cost, 0)) AS lambda_cost_sum,

    -- Alarms
    COALESCE(a.alarm_count, 0) AS alarm_count,
    COALESCE(a.alarms_cost, 0) AS alarms_cost_sum,

    -- Combined monthly cost
    SUM(COALESCE(l.log_monthly_cost, 0)) + COALESCE(a.alarms_cost, 0) AS total_monthly_cost,

    -- Source fingerprints
    LIST(DISTINCT l.fingerprint) AS log_fingerprints,

    -- Severity
    MAX(COALESCE(l.severity.score, 0)) AS max_sev_score

  FROM lambda_logs l
  LEFT JOIN lambda_signals fn
    ON l.tenant_id = fn.tenant_id
    AND l.workspace_id = fn.workspace_id
    AND l.run_id = fn.run_id
    AND l.account_id = fn.account_id
    AND l.region = fn.region
  LEFT JOIN lambda_alarms a
    ON l.tenant_id = a.tenant_id
    AND l.workspace_id = a.workspace_id
    AND l.run_id = a.run_id
    AND l.account_id = a.account_id
    AND l.region = a.region
  GROUP BY l.tenant_id, l.workspace_id, l.run_id, l.account_id, l.region, a.alarm_count, a.alarms_cost
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
    service := 'AWSLambda',
    resource_type := 'account',
    resource_id := s.account_id,
    resource_arn := ''
  ) AS scope,

  'aws.lambda.correlation.cloudwatch.logs.cost' AS check_id,
  'Lambda + CloudWatch Logs cost correlation' AS check_name,
  'waste' AS category,
  'observability' AS sub_category,
  ['FinOps'] AS frameworks,

  CASE
    WHEN s.lambda_log_groups_count >= 20 AND s.total_monthly_cost >= 100 THEN 'fail'
    WHEN s.lambda_log_groups_count >= 10 OR s.alarm_count >= 50 THEN 'warn'
    ELSE 'info'
  END AS status,

  CASE
    WHEN s.lambda_log_groups_count >= 50 OR s.total_monthly_cost >= 200
    THEN struct_pack(level:='high', score:=850)
    WHEN s.lambda_log_groups_count >= 20 OR s.alarm_count >= 100
    THEN struct_pack(level:='medium', score:=700)
    ELSE struct_pack(level:='low', score:=500)
  END AS severity,

  0 AS priority,

  'Lambda functions paying for unused CloudWatch Logs' AS title,

  (
    'Found ' || CAST(s.lambda_log_groups_count AS VARCHAR) || ' Lambda log group(s) without retention policy in region ' || s.region || '. '
    || 'These log groups may be generating costs for logs that are never read or analyzed. '
    || CASE
         WHEN s.lambda_functions_count > 0
         THEN (CAST(s.lambda_functions_count AS VARCHAR) || ' Lambda function(s) also detected. ')
         ELSE ''
       END
    || CASE
         WHEN s.total_monthly_cost > 0
         THEN ('Estimated CloudWatch Logs cost ≈ $' || CAST(ROUND(s.total_monthly_cost, 2) AS VARCHAR) || '/month. ')
         ELSE ''
       END
    || 'Set retention policies on Lambda log groups and consider using CloudWatch Logs Insights queries or S3 archiving for long-term storage.'
  ) AS message,

  'Implement CloudWatch Logs retention policies for Lambda functions. Evaluate log usage patterns and consider cost-effective alternatives like S3 archiving or third-party logging services for infrequently accessed logs.' AS recommendation,

  '' AS remediation,
  [] AS links,

  struct_pack(
    monthly_savings := s.total_monthly_cost * 0.5,
    monthly_cost := s.total_monthly_cost,
    one_time_savings := NULL,
    confidence := 35,
    notes := 'Estimated savings assumes 50% reduction by implementing proper log retention policies and archiving unused logs to lower-cost storage.'
  ) AS estimated,

  NULL AS actual,
  NULL AS lifecycle,
  map([],[]) AS tags,
  map([],[]) AS labels,
  map(
    ['lambda_log_groups_count', 'lambda_functions_count', 'alarm_count', 'region'],
    [CAST(s.lambda_log_groups_count AS VARCHAR), CAST(s.lambda_functions_count AS VARCHAR), CAST(s.alarm_count AS VARCHAR), s.region]
  ) AS dimensions,
  map([],[]) AS metrics,
  ('{"correlation_rule":"lambda_cloudwatch_logs_cost","lambda_log_groups_count":' || CAST(s.lambda_log_groups_count AS VARCHAR) || ',"lambda_functions_count":' || CAST(s.lambda_functions_count AS VARCHAR) || ',"alarm_count":' || CAST(s.alarm_count AS VARCHAR) || ',"total_monthly_cost":' || CAST(ROUND(s.total_monthly_cost, 2) AS VARCHAR) || '}') AS metadata_json,

  s.log_fingerprints AS source_fingerprints

FROM lambda_logs_correlation s
WHERE s.lambda_log_groups_count >= 1;
