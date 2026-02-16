-- rule_id: aws.ec2.correlation.ebs.unattached.unencrypted
-- name: EBS unattached + unencrypted volume (correlated)
-- enabled: true
-- required_check_ids: aws.ec2.ebs.unattached.volume, aws.ec2.ebs.volume.unencrypted

-- Correlates cost + compliance:
--   - aws.ec2.ebs.unattached.volume  (cost/savings signal)
--   - aws.ec2.ebs.volume.unencrypted (governance/compliance signal)
--
-- Emits a meta-finding per volume when BOTH signals are present for the same
-- tenant/workspace/run/account/region/volume_id.
--
-- Expected join key:
--   scope.resource_type='ebs_volume' and scope.resource_id=<VolumeId>

WITH
vol_signals AS (
  SELECT
    tenant_id,
    workspace_id,
    run_id,
    scope.account_id AS account_id,
    scope.region     AS region,
    scope.resource_id AS volume_id,
    scope.resource_arn AS volume_arn,

    MAX(CASE WHEN check_id = 'aws.ec2.ebs.unattached.volume' THEN 1 ELSE 0 END) AS sig_unattached,
    MAX(CASE WHEN check_id = 'aws.ec2.ebs.volume.unencrypted' THEN 1 ELSE 0 END) AS sig_unencrypted,

    -- prefer cost estimate from unattached finding (monthly_cost is same as savings there)
    MAX(CASE WHEN check_id = 'aws.ec2.ebs.unattached.volume' THEN COALESCE(estimated.monthly_cost, 0) ELSE 0 END) AS unattached_monthly_cost,

    LIST(DISTINCT fingerprint) AS source_fingerprints,

    -- helpful dimensions for UI/message
    MAX(CASE WHEN check_id = 'aws.ec2.ebs.unattached.volume' THEN COALESCE(dimensions['volume_type'], '') ELSE '' END) AS volume_type,
    MAX(CASE WHEN check_id = 'aws.ec2.ebs.unattached.volume' THEN COALESCE(dimensions['size_gb'], '') ELSE '' END) AS size_gb,
    MAX(CASE WHEN check_id = 'aws.ec2.ebs.unattached.volume' THEN COALESCE(dimensions['age_days'], '') ELSE '' END) AS age_days
  FROM rule_input
  WHERE status = 'fail'
    AND check_id IN ('aws.ec2.ebs.unattached.volume', 'aws.ec2.ebs.volume.unencrypted')
    AND scope.resource_type = 'ebs_volume'
  GROUP BY ALL
)

SELECT
  v.tenant_id,
  v.workspace_id,
  v.run_id,
  (SELECT MAX(run_ts) FROM rule_input WHERE tenant_id=v.tenant_id AND workspace_id=v.workspace_id AND run_id=v.run_id) AS run_ts,
  (SELECT ANY_VALUE(engine_name) FROM rule_input WHERE tenant_id=v.tenant_id AND workspace_id=v.workspace_id AND run_id=v.run_id) AS engine_name,
  (SELECT ANY_VALUE(engine_version) FROM rule_input WHERE tenant_id=v.tenant_id AND workspace_id=v.workspace_id AND run_id=v.run_id) AS engine_version,
  (SELECT ANY_VALUE(rulepack_version) FROM rule_input WHERE tenant_id=v.tenant_id AND workspace_id=v.workspace_id AND run_id=v.run_id) AS rulepack_version,

  struct_pack(
    cloud := (SELECT ANY_VALUE(scope.cloud) FROM rule_input WHERE tenant_id=v.tenant_id AND workspace_id=v.workspace_id AND run_id=v.run_id LIMIT 1),
    provider_partition := (SELECT ANY_VALUE(scope.provider_partition) FROM rule_input WHERE tenant_id=v.tenant_id AND workspace_id=v.workspace_id AND run_id=v.run_id LIMIT 1),
    billing_account_id := (SELECT ANY_VALUE(scope.billing_account_id) FROM rule_input WHERE tenant_id=v.tenant_id AND workspace_id=v.workspace_id AND run_id=v.run_id LIMIT 1),
    account_id := v.account_id,
    region := v.region,
    service := 'AmazonEC2',
    resource_type := 'ebs_volume',
    resource_id := v.volume_id,
    resource_arn := v.volume_arn
  ) AS scope,

  'aws.ec2.correlation.ebs.unattached.unencrypted' AS check_id,
  'EBS unattached + unencrypted volume (correlated)' AS check_name,
  'governance' AS category,
  'storage' AS sub_category,
  ['FinOps','Security'] AS frameworks,

  'fail' AS status,

  -- High by default because unencrypted; bump score if cost is significant
  CASE
    WHEN v.unattached_monthly_cost >= 50 THEN struct_pack(level:='high', score:=900)
    ELSE struct_pack(level:='high', score:=850)
  END AS severity,

  0 AS priority,

  'Unattached and unencrypted EBS volume' AS title,

  (
    'Volume ' || v.volume_id || ' is both unattached and unencrypted. '
    || CASE WHEN v.size_gb <> '' THEN ('Size=' || v.size_gb || 'GB. ') ELSE '' END
    || CASE WHEN v.volume_type <> '' THEN ('Type=' || v.volume_type || '. ') ELSE '' END
    || CASE WHEN v.age_days <> '' THEN ('Idle ~' || v.age_days || ' days. ') ELSE '' END
    || CASE
         WHEN v.unattached_monthly_cost > 0
         THEN ('Estimated storage cost ≈ $' || CAST(ROUND(v.unattached_monthly_cost, 2) AS VARCHAR) || '/month.')
         ELSE ''
       END
  ) AS message,

  'If unused, snapshot (encrypted) then delete the volume to avoid ongoing costs. If needed, create an encrypted copy and migrate workloads.' AS recommendation,

  '' AS remediation,
  [] AS links,

  struct_pack(
    monthly_savings := CASE WHEN v.unattached_monthly_cost > 0 THEN v.unattached_monthly_cost ELSE NULL END,
    monthly_cost := CASE WHEN v.unattached_monthly_cost > 0 THEN v.unattached_monthly_cost ELSE NULL END,
    one_time_savings := NULL,
    confidence := CASE WHEN v.unattached_monthly_cost > 0 THEN 55 ELSE 30 END,
    notes := CASE
      WHEN v.unattached_monthly_cost > 0
      THEN 'Cost derived from aws.ec2.ebs.unattached.volume estimate.'
      ELSE 'No cost estimate provided by source findings.'
    END
  ) AS estimated,

  NULL AS actual,
  NULL AS lifecycle,
  map([],[]) AS tags,
  map([],[]) AS labels,
  map(
    ['volume_id','volume_arn','volume_type','size_gb','age_days','signals'],
    [v.volume_id, COALESCE(v.volume_arn,''), COALESCE(v.volume_type,''), COALESCE(v.size_gb,''), COALESCE(v.age_days,''), 'unattached,unencrypted']
  ) AS dimensions,
  map([],[]) AS metrics,
  ('{"correlation_rule":"ebs_unattached_unencrypted"}') AS metadata_json,

  v.source_fingerprints AS source_fingerprints

FROM vol_signals v
WHERE v.sig_unattached = 1
  AND v.sig_unencrypted = 1
