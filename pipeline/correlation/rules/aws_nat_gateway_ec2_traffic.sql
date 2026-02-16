-- rule_id: aws.nat.correlation.ec2.traffic
-- name: NAT Gateway + EC2 traffic correlation
-- enabled: true
-- required_check_ids: aws.ec2.nat.gateways.idle, aws.ec2.nat.gateways.high.data.processing, aws.ec2.nat.gateways.cross.az, aws.ec2.instances.underutilized

-- pipeline/correlation/rules/aws_nat_gateway_ec2_traffic.sql
--
-- Correlation: NAT Gateway routing through expensive NATs unnecessarily
-- -----------------------------------------------------------------------
-- Identifies patterns where:
--   1) NAT Gateways are idle but EC2 instances exist (unnecessary NAT costs)
--   2) High data processing on NAT Gateways with underutilized EC2 instances
--   3) Cross-AZ NAT Gateway routing (unnecessary data transfer costs)
--
-- Uses findings emitted by:
--   - checks/aws/nat_gateways.py (NAT Gateway findings)
--   - checks/aws/ec2_instances.py (EC2 instance findings)
--
-- Expected input: view "rule_input" created by CorrelationEngine.

WITH
-- 1) NAT Gateway signals
nat_gateway_signals AS (
  SELECT
    tenant_id,
    workspace_id,
    run_id,
    scope.account_id          AS account_id,
    scope.region              AS region,
    scope.resource_id         AS nat_gateway_id,
    scope.resource_arn        AS nat_gateway_arn,
    check_id,
    status,
    severity,
    fingerprint,
    estimated.monthly_cost    AS nat_monthly_cost,
    dimensions
  FROM rule_input
  WHERE status IN ('fail', 'warn')
    AND check_id IN (
      'aws.ec2.nat.gateways.idle',
      'aws.ec2.nat.gateways.high.data.processing',
      'aws.ec2.nat.gateways.cross.az'
    )
    AND scope.resource_type = 'nat_gateway'
),

-- 2) Aggregate NAT Gateway signals by account/region
nat_aggregated AS (
  SELECT
    n.tenant_id,
    n.workspace_id,
    n.run_id,
    n.account_id,
    n.region,

    COUNT(DISTINCT n.nat_gateway_id) AS nat_gateway_count,

    -- NAT Gateway issue signals
    COUNT(DISTINCT CASE WHEN n.check_id = 'aws.ec2.nat.gateways.idle' THEN n.nat_gateway_id END) AS idle_nat_count,
    COUNT(DISTINCT CASE WHEN n.check_id = 'aws.ec2.nat.gateways.high.data.processing' THEN n.nat_gateway_id END) AS high_data_nat_count,
    COUNT(DISTINCT CASE WHEN n.check_id = 'aws.ec2.nat.gateways.cross.az' THEN n.nat_gateway_id END) AS cross_az_nat_count,

    -- Sum of NAT Gateway costs
    SUM(COALESCE(n.nat_monthly_cost, 0)) AS nat_cost_sum,

    -- Source fingerprints
    LIST(DISTINCT n.fingerprint) AS nat_fingerprints,

    -- Max severity
    MAX(COALESCE(n.severity.score, 0)) AS max_sev_score

  FROM nat_gateway_signals n
  GROUP BY n.tenant_id, n.workspace_id, n.run_id, n.account_id, n.region
),

-- 3) EC2 underutilized/idle instances
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
    estimated.monthly_cost    AS ec2_monthly_cost
  FROM rule_input
  WHERE status = 'fail'
    AND check_id = 'aws.ec2.instances.underutilized'
    AND scope.resource_type = 'instance'
),

-- 4) Aggregate EC2 signals by account/region
ec2_aggregated AS (
  SELECT
    e.tenant_id,
    e.workspace_id,
    e.run_id,
    e.account_id,
    e.region,

    COUNT(DISTINCT e.instance_id) AS underutilized_ec2_count,
    SUM(COALESCE(e.ec2_monthly_cost, 0)) AS ec2_cost_sum,

    LIST(DISTINCT e.fingerprint) AS ec2_fingerprints

  FROM ec2_signals e
  GROUP BY e.tenant_id, e.workspace_id, e.run_id, e.account_id, e.region
),

-- 5) Final correlation: NAT Gateway + EC2
nat_ec2_correlation AS (
  SELECT
    n.tenant_id,
    n.workspace_id,
    n.run_id,
    n.account_id,
    n.region,

    n.nat_gateway_count,
    n.idle_nat_count,
    n.high_data_nat_count,
    n.cross_az_nat_count,
    n.nat_cost_sum,
    n.nat_fingerprints,
    n.max_sev_score,

    COALESCE(e.underutilized_ec2_count, 0) AS underutilized_ec2_count,
    COALESCE(e.ec2_cost_sum, 0) AS ec2_cost_sum,
    e.ec2_fingerprints,

    -- Combined cost
    n.nat_cost_sum + COALESCE(e.ec2_cost_sum, 0) AS total_monthly_cost,

    -- Combined fingerprints
    n.nat_fingerprints || COALESCE(e.ec2_fingerprints, []) AS all_fingerprints

  FROM nat_aggregated n
  LEFT JOIN ec2_aggregated e
    ON n.tenant_id = e.tenant_id
    AND n.workspace_id = e.workspace_id
    AND n.run_id = e.run_id
    AND n.account_id = e.account_id
    AND n.region = e.region
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

  'aws.nat.correlation.ec2.traffic' AS check_id,
  'NAT Gateway + EC2 traffic correlation' AS check_name,
  'waste' AS category,
  'networking' AS sub_category,
  ['FinOps'] AS frameworks,

  CASE
    WHEN s.idle_nat_count >= 2 AND s.underutilized_ec2_count >= 5 THEN 'fail'
    WHEN s.high_data_nat_count >= 1 OR s.cross_az_nat_count >= 1 THEN 'warn'
    ELSE 'info'
  END AS status,

  CASE
    WHEN s.nat_gateway_count >= 5 OR s.total_monthly_cost >= 500
    THEN struct_pack(level:='high', score:=850)
    WHEN s.nat_gateway_count >= 3 OR s.idle_nat_count >= 2
    THEN struct_pack(level:='medium', score:=700)
    ELSE struct_pack(level:='low', score:=500)
  END AS severity,

  0 AS priority,

  'Traffic flowing through expensive NAT Gateways unnecessarily' AS title,

  (
    'Found ' || CAST(s.nat_gateway_count AS VARCHAR) || ' NAT Gateway(s) with cost issues in region ' || s.region || '. '
    || 'Details: ' || CAST(s.idle_nat_count AS VARCHAR) || ' idle, '
    || CAST(s.high_data_nat_count AS VARCHAR) || ' high data processing, '
    || CAST(s.cross_az_nat_count AS VARCHAR) || ' cross-AZ routing. '
    || 'Correlated ' || CAST(s.underutilized_ec2_count AS VARCHAR) || ' underutilized EC2 instance(s) that may be using these NAT Gateways. '
    || CASE
         WHEN s.total_monthly_cost > 0
         THEN ('Estimated combined cost ≈ $' || CAST(ROUND(s.total_monthly_cost, 2) AS VARCHAR) || '/month. ')
         ELSE ''
       END
    || 'Consider using NAT Gateway endpoints, VPC endpoints, or consolidating traffic through more cost-effective paths.'
  ) AS message,

  'Review NAT Gateway usage patterns and EC2 instance connectivity. Implement VPC endpoints for AWS services, use NAT Gateways only when necessary, and consider using Instance Connect Endpoint or VPC Reachability Analyzer to optimize routing.' AS recommendation,

  '' AS remediation,
  [] AS links,

  struct_pack(
    monthly_savings := s.total_monthly_cost * 0.35,
    monthly_cost := s.total_monthly_cost,
    one_time_savings := NULL,
    confidence := 40,
    notes := 'Estimated savings assumes 35% reduction by optimizing NAT Gateway routing, using VPC endpoints, and consolidating traffic patterns.'
  ) AS estimated,

  NULL AS actual,
  NULL AS lifecycle,
  map([],[]) AS tags,
  map([],[]) AS labels,
  map(
    ['nat_gateway_count', 'idle_nat_count', 'high_data_nat_count', 'cross_az_nat_count', 'underutilized_ec2_count', 'region'],
    [CAST(s.nat_gateway_count AS VARCHAR), CAST(s.idle_nat_count AS VARCHAR), CAST(s.high_data_nat_count AS VARCHAR), CAST(s.cross_az_nat_count AS VARCHAR), CAST(s.underutilized_ec2_count AS VARCHAR), s.region]
  ) AS dimensions,
  map([],[]) AS metrics,
  ('{"correlation_rule":"nat_gateway_ec2_traffic","nat_gateway_count":' || CAST(s.nat_gateway_count AS VARCHAR) || ',"idle_nat_count":' || CAST(s.idle_nat_count AS VARCHAR) || ',"high_data_nat_count":' || CAST(s.high_data_nat_count AS VARCHAR) || ',"cross_az_nat_count":' || CAST(s.cross_az_nat_count AS VARCHAR) || ',"underutilized_ec2_count":' || CAST(s.underutilized_ec2_count AS VARCHAR) || ',"total_monthly_cost":' || CAST(ROUND(s.total_monthly_cost, 2) AS VARCHAR) || '}') AS metadata_json,

  s.all_fingerprints AS source_fingerprints

FROM nat_ec2_correlation s
WHERE s.nat_gateway_count >= 1;
