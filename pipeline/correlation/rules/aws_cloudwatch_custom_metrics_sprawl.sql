-- rule_id: aws.cloudwatch.correlation.custom_metrics_sprawl
-- name: CloudWatch custom metrics sprawl (correlated)
-- enabled: true
-- required_check_ids: aws.cloudwatch.custom_metrics.from_log_filters

-- Correlates per-metric "custom metric from log filters" signals into an account/region meta finding.
--
-- Source signal:
--   - aws.cloudwatch.custom_metrics.from_log_filters
--
-- Emission model:
--   - one meta finding per tenant/workspace/run/account/region
--   - severity scales with metric_count and estimated monthly cost rollup

WITH
sig AS (
  SELECT
    tenant_id,
    workspace_id,
    run_id,
    scope.account_id AS account_id,
    scope.region     AS region,
    COUNT(*)         AS metric_count,

    -- Roll up estimates if provided by the checker (best-effort)
    SUM(COALESCE(estimated.monthly_cost, 0)) AS monthly_cost_sum,

    -- Capture some representative namespaces/metrics for context
    LIST(DISTINCT COALESCE(dimensions['namespace'], '')) AS namespaces,
    LIST(DISTINCT COALESCE(dimensions['metric_name'], '')) AS metric_names,

    LIST(DISTINCT fingerprint) AS source_fingerprints,
    MAX(COALESCE(severity.score, 0)) AS max_sev_score
  FROM rule_input
  WHERE status = 'info'
    AND check_id = 'aws.cloudwatch.custom_metrics.from_log_filters'
    AND scope.resource_type = 'custom_metric'
  GROUP BY ALL
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
    service := 'AmazonCloudWatch',
    resource_type := 'account',
    resource_id := s.account_id,
    resource_arn := ''
  ) AS scope,

  'aws.cloudwatch.correlation.custom_metrics_sprawl' AS check_id,
  'CloudWatch custom metrics sprawl (correlated)' AS check_name,
  'waste' AS category,
  'observability' AS sub_category,
  ['FinOps'] AS frameworks,

  'fail' AS status,

  CASE
    WHEN s.metric_count >= 200 OR s.monthly_cost_sum >= 200 THEN struct_pack(level:='high', score:=900)
    WHEN s.metric_count >= 50  OR s.monthly_cost_sum >= 50  THEN struct_pack(level:='medium', score:=760)
    ELSE struct_pack(level:='medium', score:=650)
  END AS severity,

  0 AS priority,

  'Custom CloudWatch metrics created by log filters may be stale or excessive' AS title,

  (
    'Found ' || CAST(s.metric_count AS VARCHAR) || ' custom metric(s) created by CloudWatch Logs metric filters in region ' || s.region || '. '
    || CASE
         WHEN s.monthly_cost_sum > 0
         THEN ('Estimated recurring cost ≈ $' || CAST(ROUND(s.monthly_cost_sum, 2) AS VARCHAR) || '/month. ')
         ELSE ''
       END
    || 'Review whether these metrics are still used by dashboards/alarms and remove unused metric filters. '
    || 'Example namespaces: '
    || COALESCE(array_to_string(list_slice(s.namespaces, 1, 5), ', '), '')
    || CASE WHEN s.metric_count > 5 THEN ' …' ELSE '' END
  ) AS message,

  'Audit CloudWatch Logs metric filters and the custom metrics they generate. Remove unused metrics, consolidate where possible, and avoid high-cardinality metric patterns.' AS recommendation,

  '' AS remediation,
  [] AS links,

  struct_pack(
    monthly_savings := CASE WHEN s.monthly_cost_sum > 0 THEN s.monthly_cost_sum ELSE NULL END,
    monthly_cost := CASE WHEN s.monthly_cost_sum > 0 THEN s.monthly_cost_sum ELSE NULL END,
    one_time_savings := NULL,
    confidence := CASE WHEN s.monthly_cost_sum > 0 THEN 55 ELSE 20 END,
    notes := CASE
      WHEN s.monthly_cost_sum > 0
      THEN 'monthly_cost is the sum of source custom-metric estimates (best-effort).'
      ELSE 'No cost rollup available; correlated sprawl signal based on count.'
    END
  ) AS estimated,

  NULL AS actual,
  NULL AS lifecycle,
  map([],[]) AS tags,
  map([],[]) AS labels,
  map(
    ['metric_count','region'],
    [CAST(s.metric_count AS VARCHAR), s.region]
  ) AS dimensions,
  map([],[]) AS metrics,
  ('{"correlation_rule":"custom_metrics_sprawl","metric_count":' || CAST(s.metric_count AS VARCHAR) || ',"monthly_cost_sum":' || CAST(ROUND(s.monthly_cost_sum, 2) AS VARCHAR) || '}') AS metadata_json,

  s.source_fingerprints AS source_fingerprints

FROM sig s
WHERE s.metric_count >= 5;
