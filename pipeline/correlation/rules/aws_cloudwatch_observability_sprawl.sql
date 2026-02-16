-- rule_id: aws.cloudwatch.correlation.observability.sprawl
-- name: CloudWatch observability sprawl (correlated)
-- enabled: true
-- required_check_ids: aws.cloudwatch.alarms.high.count, aws.cloudwatch.custom.metrics.from.log.filters

-- Combines "high alarm count" with "custom metrics from log filters" to surface observability sprawl.
--
-- Signals:
--   - aws.cloudwatch.alarms.high.count (already thresholded by checker)
--   - aws.cloudwatch.custom.metrics.from.log.filters (per custom metric)
--
-- Emits a single meta finding per tenant/workspace/run/account/region when BOTH signals are present.

WITH
alarms AS (
  SELECT
    tenant_id,
    workspace_id,
    run_id,
    scope.account_id AS account_id,
    scope.region     AS region,
    MAX(COALESCE(dimensions['alarm_count'], '0')) AS alarm_count_str,
    LIST(DISTINCT fingerprint) AS alarm_source_fps
  FROM rule_input
  WHERE status = 'info'
    AND check_id = 'aws.cloudwatch.alarms.high.count'
    AND scope.resource_type = 'account'
  GROUP BY ALL
),

metrics AS (
  SELECT
    tenant_id,
    workspace_id,
    run_id,
    scope.account_id AS account_id,
    scope.region     AS region,
    COUNT(*) AS custom_metric_count,
    SUM(COALESCE(estimated.monthly_cost, 0)) AS monthly_cost_sum,
    LIST(DISTINCT COALESCE(dimensions['namespace'], '')) AS namespaces,
    LIST(DISTINCT fingerprint) AS metric_source_fps
  FROM rule_input
  WHERE status = 'info'
    AND check_id = 'aws.cloudwatch.custom.metrics.from.log.filters'
    AND scope.resource_type = 'custom_metric'
  GROUP BY ALL
),

combined AS (
  SELECT
    a.tenant_id,
    a.workspace_id,
    a.run_id,
    a.account_id,
    a.region,
    TRY_CAST(a.alarm_count_str AS INTEGER) AS alarm_count,
    m.custom_metric_count,
    m.monthly_cost_sum,
    m.namespaces,
    LIST_CONCAT(a.alarm_source_fps, m.metric_source_fps) AS source_fingerprints
  FROM alarms a
  INNER JOIN metrics m
    ON a.tenant_id = m.tenant_id
   AND a.workspace_id = m.workspace_id
   AND a.run_id = m.run_id
   AND a.account_id = m.account_id
   AND a.region = m.region
)

SELECT
  c.tenant_id,
  c.workspace_id,
  c.run_id,
  (SELECT MAX(run_ts) FROM rule_input WHERE tenant_id=c.tenant_id AND workspace_id=c.workspace_id AND run_id=c.run_id) AS run_ts,
  (SELECT ANY_VALUE(engine_name) FROM rule_input WHERE tenant_id=c.tenant_id AND workspace_id=c.workspace_id AND run_id=c.run_id) AS engine_name,
  (SELECT ANY_VALUE(engine_version) FROM rule_input WHERE tenant_id=c.tenant_id AND workspace_id=c.workspace_id AND run_id=c.run_id) AS engine_version,
  (SELECT ANY_VALUE(rulepack_version) FROM rule_input WHERE tenant_id=c.tenant_id AND workspace_id=c.workspace_id AND run_id=c.run_id) AS rulepack_version,

  struct_pack(
    cloud := (SELECT ANY_VALUE(scope.cloud) FROM rule_input WHERE tenant_id=c.tenant_id AND workspace_id=c.workspace_id AND run_id=c.run_id LIMIT 1),
    provider_partition := (SELECT ANY_VALUE(scope.provider_partition) FROM rule_input WHERE tenant_id=c.tenant_id AND workspace_id=c.workspace_id AND run_id=c.run_id LIMIT 1),
    billing_account_id := (SELECT ANY_VALUE(scope.billing_account_id) FROM rule_input WHERE tenant_id=c.tenant_id AND workspace_id=c.workspace_id AND run_id=c.run_id LIMIT 1),
    account_id := c.account_id,
    region := c.region,
    service := 'AmazonCloudWatch',
    resource_type := 'account',
    resource_id := c.account_id,
    resource_arn := ''
  ) AS scope,

  'aws.cloudwatch.correlation.observability.sprawl' AS check_id,
  'CloudWatch observability sprawl (correlated)' AS check_name,
  'waste' AS category,
  'observability' AS sub_category,
  ['FinOps'] AS frameworks,

  'fail' AS status,

  CASE
    WHEN COALESCE(c.alarm_count, 0) >= 500 OR c.custom_metric_count >= 500 OR c.monthly_cost_sum >= 500 THEN struct_pack(level:='high', score:=920)
    WHEN COALESCE(c.alarm_count, 0) >= 200 OR c.custom_metric_count >= 200 OR c.monthly_cost_sum >= 200 THEN struct_pack(level:='high', score:=880)
    ELSE struct_pack(level:='medium', score:=760)
  END AS severity,

  0 AS priority,

  'CloudWatch alarms and custom metrics indicate observability sprawl' AS title,

  (
    'Region ' || c.region || ' has a high number of CloudWatch alarms and custom metrics created by log filters. '
    || 'Alarms=' || CAST(COALESCE(c.alarm_count, 0) AS VARCHAR)
    || ', custom_metrics=' || CAST(c.custom_metric_count AS VARCHAR)
    || CASE WHEN c.monthly_cost_sum > 0 THEN (', estimated_recurring_cost≈$' || CAST(ROUND(c.monthly_cost_sum, 2) AS VARCHAR) || '/month') ELSE '' END
    || '. Consolidate monitoring, delete unused alarms/metric filters, and avoid metric cardinality explosions. '
    || 'Example namespaces: ' || COALESCE(array_to_string(list_slice(c.namespaces, 1, 5), ', '), '')
    || CASE WHEN c.custom_metric_count > 5 THEN ' …' ELSE '' END
  ) AS message,

  'Run an observability hygiene review: remove unused alarms/metric filters, consolidate dashboards, enforce retention, and prefer fewer standard metrics over many custom metrics.' AS recommendation,

  '' AS remediation,
  [] AS links,

  struct_pack(
    monthly_savings := CASE WHEN c.monthly_cost_sum > 0 THEN c.monthly_cost_sum ELSE NULL END,
    monthly_cost := CASE WHEN c.monthly_cost_sum > 0 THEN c.monthly_cost_sum ELSE NULL END,
    one_time_savings := NULL,
    confidence := CASE WHEN c.monthly_cost_sum > 0 THEN 55 ELSE 20 END,
    notes := CASE
      WHEN c.monthly_cost_sum > 0
      THEN 'monthly_cost is the sum of source custom-metric estimates (best-effort). Alarm costs are not rolled up here.'
      ELSE 'No cost rollup available; correlated sprawl signal.'
    END
  ) AS estimated,

  NULL AS actual,
  NULL AS lifecycle,
  map([],[]) AS tags,
  map([],[]) AS labels,
  map(
    ['alarm_count','custom_metric_count','region'],
    [CAST(COALESCE(c.alarm_count, 0) AS VARCHAR), CAST(c.custom_metric_count AS VARCHAR), c.region]
  ) AS dimensions,
  map([],[]) AS metrics,
  ('{"correlation_rule":"observability_sprawl"}') AS metadata_json,

  c.source_fingerprints AS source_fingerprints

FROM combined c
WHERE c.custom_metric_count >= 20;
