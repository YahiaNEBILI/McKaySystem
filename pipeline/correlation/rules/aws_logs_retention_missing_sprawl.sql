-- rule_id: aws.logs.correlation.retention_missing_sprawl
-- name: CloudWatch Logs retention missing (correlated)
-- enabled: true
-- required_check_ids: aws.logs.log_groups.retention_missing

-- Correlates log groups missing a retention policy into an account/region meta finding.
--
-- Source signal:
--   - aws.logs.log_groups.retention_missing
--
-- Emits a single meta finding per tenant/workspace/run/account/region.
--

WITH
sig AS (
  SELECT
    tenant_id,
    workspace_id,
    run_id,
    scope.account_id AS account_id,
    scope.region     AS region,
    COUNT(*)         AS log_groups_missing_retention,
    LIST(DISTINCT scope.resource_id) AS log_group_names,
    LIST(DISTINCT fingerprint) AS source_fingerprints,
    MAX(COALESCE(severity.score, 0)) AS max_sev_score
  FROM rule_input
  WHERE status = 'fail'
    AND check_id = 'aws.logs.log_groups.retention_missing'
    AND scope.resource_type = 'log_group'
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
    service := 'CloudWatchLogs',
    resource_type := 'account',
    resource_id := s.account_id,
    resource_arn := ''
  ) AS scope,

  'aws.logs.correlation.retention_missing_sprawl' AS check_id,
  'CloudWatch Logs retention missing (correlated)' AS check_name,
  'waste' AS category,
  'observability' AS sub_category,
  ['FinOps','Governance'] AS frameworks,

  'fail' AS status,

  CASE
    WHEN s.log_groups_missing_retention >= 50 THEN struct_pack(level:='high', score:=900)
    WHEN s.log_groups_missing_retention >= 10 THEN struct_pack(level:='medium', score:=750)
    ELSE struct_pack(level:='medium', score:=650)
  END AS severity,

  0 AS priority,

  'Many CloudWatch Log Groups have no retention policy' AS title,

  (
    'Found ' || CAST(s.log_groups_missing_retention AS VARCHAR) || ' log group(s) without a retention policy in region ' || s.region || '. '
    || 'These log groups retain data indefinitely ("never expire"), which can lead to unbounded storage costs. '
    || 'Examples: '
    || COALESCE(
         array_to_string(list_slice(s.log_group_names, 1, 5), ', '),
         ''
       )
    || CASE WHEN s.log_groups_missing_retention > 5 THEN ' …' ELSE '' END
  ) AS message,

  'Set retention (e.g., 14/30/90 days) for non-compliance log groups; keep longer retention only where required.' AS recommendation,

  '' AS remediation,
  [] AS links,

  struct_pack(
    monthly_savings := NULL,
    monthly_cost := NULL,
    one_time_savings := NULL,
    confidence := 10,
    notes := 'No direct cost rollup available; this is a governance/cost-growth risk signal.'
  ) AS estimated,

  NULL AS actual,
  NULL AS lifecycle,
  map([],[]) AS tags,
  map([],[]) AS labels,
  map(
    ['log_groups_missing_retention','region'],
    [CAST(s.log_groups_missing_retention AS VARCHAR), s.region]
  ) AS dimensions,
  map([],[]) AS metrics,
  ('{"correlation_rule":"retention_missing_sprawl","count":' || CAST(s.log_groups_missing_retention AS VARCHAR) || '}') AS metadata_json,

  s.source_fingerprints AS source_fingerprints

FROM sig s
WHERE s.log_groups_missing_retention >= 1;
