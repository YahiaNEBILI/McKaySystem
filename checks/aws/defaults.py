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
