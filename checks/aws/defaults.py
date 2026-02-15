"""Centralized default values for AWS checkers.

This module contains non-environment-specific defaults used by checkers.
Keep these values deterministic and stable across runs.
"""

from __future__ import annotations

from typing import Final

# EC2 checker defaults
EC2_UNDERUTILIZED_LOOKBACK_DAYS: Final[int] = 14
EC2_UNDERUTILIZED_CPU_AVG_THRESHOLD: Final[float] = 10.0
EC2_UNDERUTILIZED_NET_AVG_KIB_PER_HOUR_THRESHOLD: Final[float] = 512.0
EC2_STOPPED_LONG_AGE_DAYS: Final[int] = 30
EC2_MAX_FINDINGS_PER_TYPE: Final[int] = 50_000
EC2_T_CREDIT_LOOKBACK_DAYS: Final[int] = 7
EC2_T_CREDIT_BALANCE_MIN_THRESHOLD: Final[float] = 20.0
EC2_REQUIRED_INSTANCE_TAG_KEYS: Final[tuple[str, ...]] = ("ApplicationId", "Environment", "Application")
EC2_RI_UTILIZATION_LOW_THRESHOLD_PCT: Final[float] = 80.0
EC2_RI_MIN_COVERAGE_GAP_INSTANCES: Final[int] = 1
EC2_RI_POTENTIAL_SAVINGS_DISCOUNT_FACTOR: Final[float] = 0.30
EC2_RI_UNUSED_EFFECTIVE_COST_FACTOR: Final[float] = 0.70
EC2_SP_LOW_UTILIZATION_THRESHOLD_PCT: Final[float] = 80.0
EC2_SP_MIN_COVERAGE_GAP_USD_PER_HOUR: Final[float] = 0.05
EC2_SP_POTENTIAL_SAVINGS_DISCOUNT_FACTOR: Final[float] = 0.25
EC2_SP_UNUSED_COMMITMENT_COST_FACTOR: Final[float] = 1.00

# ECS/EKS containers checker defaults
CONTAINERS_MAX_FINDINGS_PER_TYPE: Final[int] = 50_000
CONTAINERS_NONPROD_TAG_KEYS: Final[tuple[str, ...]] = ("env", "environment", "stage", "tier")
CONTAINERS_NONPROD_TAG_VALUES: Final[tuple[str, ...]] = (
    "dev",
    "test",
    "qa",
    "uat",
    "staging",
    "sandbox",
    "nonprod",
    "non-prod",
)
EKS_MIN_SUPPORTED_VERSION: Final[tuple[int, int]] = (1, 28)

# RDS instances optimization checker defaults
RDS_STORAGE_GB_MONTH_PRICE_USD: Final[float] = 0.115
RDS_STORAGE_WINDOW_DAYS: Final[int] = 14
RDS_STORAGE_PERIOD_SECONDS: Final[int] = 86400
RDS_OVERPROV_USED_RATIO_THRESHOLD: Final[float] = 0.40
RDS_OVERPROV_MIN_EXCESS_GB: Final[float] = 20.0
RDS_REPLICA_UNUSED_WINDOW_DAYS: Final[int] = 14
RDS_REPLICA_PERIOD_SECONDS: Final[int] = 86400
RDS_REPLICA_READ_IOPS_P95_THRESHOLD: Final[float] = 0.1
RDS_REPLICA_MIN_DATAPOINTS: Final[int] = 7
RDS_STORAGE_MIN_COVERAGE_RATIO: Final[float] = 0.60
RDS_REPLICA_MIN_COVERAGE_RATIO: Final[float] = 0.60
RDS_MYSQL_BLOCKED_PREFIXES: Final[tuple[str, ...]] = ("5.6", "5.7")
RDS_POSTGRES_MIN_VERSION: Final[tuple[int, int]] = (12, 0)
RDS_MARIADB_MIN_VERSION: Final[tuple[int, int]] = (10, 6)

# FSx checker defaults
FSX_UNUSED_LOOKBACK_DAYS: Final[int] = 14
FSX_THROUGHPUT_LOOKBACK_DAYS: Final[int] = 14
FSX_UNDERUTILIZED_P95_UTIL_THRESHOLD_PCT: Final[float] = 20.0
FSX_LARGE_STORAGE_GIB_THRESHOLD: Final[int] = 4096
FSX_WINDOWS_BACKUP_LOW_RETENTION_DAYS: Final[int] = 7
FSX_REQUIRED_TAG_KEYS: Final[tuple[str, ...]] = ("application", "applicationId", "environment")
FSX_MAX_FINDINGS_PER_TYPE: Final[int] = 50_000

# Backup plans checker defaults
BACKUP_PLANS_STALE_DAYS: Final[int] = 90
BACKUP_PLANS_WARM_GB_MONTH_PRICE_USD: Final[float] = 0.05
BACKUP_PLANS_COLD_GB_MONTH_PRICE_USD: Final[float] = 0.01
BACKUP_PLANS_SKIP_IF_DELETING_WITHIN_DAYS: Final[int] = 14

# Backup vaults checker defaults
BACKUP_VAULTS_WARM_FALLBACK_USD: Final[float] = 0.05
BACKUP_VAULTS_COLD_FALLBACK_USD: Final[float] = 0.01

# CloudWatch metrics/logs checker defaults
CLOUDWATCH_REQUIRE_RETENTION_POLICY: Final[bool] = True
CLOUDWATCH_SUPPRESS_TAG_KEYS: Final[tuple[str, ...]] = (
    "retain",
    "retention",
    "keep",
    "do_not_delete",
    "donotdelete",
    "lifecycle",
)
CLOUDWATCH_SUPPRESS_TAG_VALUES: Final[tuple[str, ...]] = (
    "retain",
    "retained",
    "keep",
    "true",
    "yes",
    "1",
    "permanent",
    "legal-hold",
)
CLOUDWATCH_SUPPRESS_VALUE_PREFIXES: Final[tuple[str, ...]] = (
    "keep",
    "retain",
    "do-not-delete",
    "do_not_delete",
    "donotdelete",
)
CLOUDWATCH_MIN_CUSTOM_METRICS_FOR_SIGNAL: Final[int] = 1
CLOUDWATCH_MAX_CUSTOM_METRIC_FINDINGS: Final[int] = 50_000
CLOUDWATCH_ALARMS_COUNT_WARN_THRESHOLD: Final[int] = 100
CLOUDWATCH_FALLBACK_USD_PER_CUSTOM_METRIC_MONTH: Final[float] = 0.30
CLOUDWATCH_FALLBACK_USD_PER_ALARM_MONTH: Final[float] = 0.10

# Lambda analyzer checker defaults
LAMBDA_LOOKBACK_DAYS: Final[int] = 14
LAMBDA_MIN_DAILY_DATAPOINTS: Final[int] = 7
LAMBDA_IDLE_P95_DAILY_INVOCATIONS_THRESHOLD: Final[float] = 1.0
LAMBDA_MEMORY_OVERPROV_MIN_ALLOCATED_MB: Final[int] = 1024
LAMBDA_MEMORY_OVERPROV_MAX_P95_DURATION_MS: Final[float] = 250.0
LAMBDA_MEMORY_OVERPROV_MAX_DURATION_TO_TIMEOUT_RATIO: Final[float] = 0.20
LAMBDA_MEMORY_OVERPROV_MIN_INVOCATIONS: Final[int] = 100
LAMBDA_MEMORY_OVERPROV_TARGET_MEMORY_RATIO: Final[float] = 0.50
LAMBDA_MEMORY_OVERPROV_DURATION_SLOWDOWN_FACTOR: Final[float] = 1.20
LAMBDA_MAX_FINDINGS_PER_TYPE: Final[int] = 50_000
LAMBDA_FALLBACK_GB_SECOND_USD: Final[float] = 0.0000166667

# EFS checker defaults
EFS_LOOKBACK_DAYS: Final[int] = 14
EFS_MIN_DAILY_DATAPOINTS: Final[int] = 7
EFS_UNUSED_P95_DAILY_IO_BYTES_THRESHOLD: Final[float] = 5 * 1024.0**2
EFS_UNUSED_MAX_CLIENT_CONNECTIONS_THRESHOLD: Final[float] = 0.0
EFS_UNDERUTILIZED_P95_PERCENT_IO_LIMIT_THRESHOLD: Final[float] = 20.0
EFS_PERCENT_IO_LIMIT_PERIOD_SECONDS: Final[int] = 3600
EFS_SUPPRESS_TAG_KEYS: Final[tuple[str, ...]] = ("finops:ignore", "do-not-delete", "keep")
EFS_MAX_FINDINGS_PER_TYPE: Final[int] = 50_000

# NAT checker defaults
NAT_LOOKBACK_DAYS: Final[int] = 14
NAT_IDLE_P95_DAILY_BYTES_THRESHOLD: Final[float] = 1_048_576.0
NAT_MIN_DAILY_DATAPOINTS: Final[int] = 7
NAT_HIGH_DATA_PROCESSING_GIB_MONTH_THRESHOLD: Final[float] = 100.0
NAT_ORPHAN_MIN_AGE_DAYS: Final[int] = 1
NAT_SUPPRESS_TAG_KEYS: Final[tuple[str, ...]] = ("finops:ignore", "do-not-delete", "keep")
NAT_MAX_FINDINGS_PER_TYPE: Final[int] = 50_000
NAT_FALLBACK_HOURLY_USD: Final[float] = 0.045
NAT_FALLBACK_DATA_USD_PER_GB: Final[float] = 0.045

# ELBv2 checker defaults
ELBV2_LOOKBACK_DAYS: Final[int] = 14
ELBV2_MIN_DAILY_DATAPOINTS: Final[int] = 7
ELBV2_IDLE_P95_DAILY_REQUESTS_THRESHOLD: Final[float] = 1.0
ELBV2_IDLE_P95_DAILY_NEW_FLOWS_THRESHOLD: Final[float] = 1.0
ELBV2_MIN_AGE_DAYS: Final[int] = 2
ELBV2_SUPPRESS_TAG_KEYS: Final[tuple[str, ...]] = ("finops:ignore", "do-not-delete", "keep")
ELBV2_MAX_FINDINGS_PER_TYPE: Final[int] = 50_000
ELBV2_FALLBACK_ALB_HOURLY_USD: Final[float] = 0.025
ELBV2_FALLBACK_NLB_HOURLY_USD: Final[float] = 0.0225

# RDS snapshots checker defaults
RDS_SNAPSHOTS_STALE_DAYS: Final[int] = 30
RDS_SNAPSHOTS_GB_MONTH_PRICE_USD: Final[float] = 0.095

# S3 checker defaults
S3_DEFAULT_STORAGE_PRICE_GB_MONTH_USD: Final[float] = 0.023
S3_METRIC_LOOKBACK_DAYS: Final[int] = 3

# EBS checker defaults
EBS_UNATTACHED_MIN_AGE_DAYS: Final[int] = 7
EBS_SNAPSHOT_OLD_AGE_DAYS: Final[int] = 45
EBS_SUPPRESS_TAG_KEYS: Final[tuple[str, ...]] = (
    "retain",
    "retention",
    "keep",
    "do_not_delete",
    "donotdelete",
    "backup",
    "purpose",
    "lifecycle",
)
EBS_SUPPRESS_TAG_VALUES: Final[tuple[str, ...]] = (
    "retain",
    "retained",
    "keep",
    "true",
    "yes",
    "1",
    "permanent",
    "legal-hold",
)
EBS_SUPPRESS_VALUE_PREFIXES: Final[tuple[str, ...]] = (
    "keep",
    "retain",
    "do-not-delete",
    "do_not_delete",
    "donotdelete",
)
EBS_MAX_FINDINGS_PER_TYPE: Final[int] = 50_000

# Cost Explorer Analyzer defaults
# See: cost_explorer_checker_design_v2.md

# Lookback and freshness windows
COST_EXPLORER_LOOKBACK_MONTHS: Final[int] = 12
COST_EXPLORER_CE_FRESHNESS_MONTHS: Final[int] = 3

# Guardrails (threshold-based detection)
COST_EXPLORER_SPIKE_THRESHOLD_PCT: Final[float] = 20.0
COST_EXPLORER_DROP_THRESHOLD_PCT: Final[float] = 20.0
COST_EXPLORER_MIN_COST_ABS: Final[float] = 25.0
COST_EXPLORER_MIN_DELTA_ABS: Final[float] = 50.0

# Moving average / Z-score
COST_EXPLORER_MIN_MONTHS_FOR_MOVING: Final[int] = 2
COST_EXPLORER_MOVING_AVG_WINDOW_MONTHS: Final[int] = 3
COST_EXPLORER_MOVING_AVG_THRESHOLD_PCT: Final[float] = 50.0
COST_EXPLORER_ENABLE_ZSCORE: Final[bool] = True
COST_EXPLORER_ZSCORE_THRESHOLD: Final[float] = 2.0

# Year-over-Year
COST_EXPLORER_ENABLE_YOY: Final[bool] = True
COST_EXPLORER_YOY_THRESHOLD_PCT: Final[float] = 30.0
COST_EXPLORER_YOY_MIN_MONTHS: Final[int] = 12

# Trend (regression-based)
COST_EXPLORER_TREND_MIN_MONTHS: Final[int] = 3
COST_EXPLORER_TREND_WINDOW_MONTHS: Final[int] = 6
COST_EXPLORER_TREND_SLOPE_MIN_ABS: Final[float] = 50.0
COST_EXPLORER_TREND_SLOPE_MIN_PCT: Final[float] = 10.0

# Service discovery
COST_EXPLORER_DISCOVERY_HYSTERESIS_MONTHS: Final[int] = 1

# CUR backfill (optional)
COST_EXPLORER_ENABLE_CUR_BACKFILL: Final[bool] = False
