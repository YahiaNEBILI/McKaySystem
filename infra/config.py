"""Centralized application configuration with schema validation.

This module is intentionally compatibility-first:
- Supports legacy flat environment names (for example ``DB_URL``).
- Supports nested names (for example ``DB__URL``) for future consistency.
- Optionally reads a local ``.env`` file before process env values.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from threading import Lock

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

_DEFAULT_AWS_REGIONS = [
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "eu-central-1",
]


class DatabaseConfig(BaseModel):
    """Database connection settings."""

    model_config = ConfigDict(frozen=True)

    url: str | None = Field(default=None, description="Postgres connection URL")
    pool_maxconn: int = Field(default=10, ge=1, le=100)
    connect_timeout: int = Field(default=5, ge=1, le=60)


class AWSConfig(BaseModel):
    """AWS client defaults used by service factories."""

    model_config = ConfigDict(frozen=True)

    regions: list[str] = Field(default_factory=lambda: list(_DEFAULT_AWS_REGIONS))
    default_region: str = Field(default="us-east-1")
    max_retries: int = Field(default=10, ge=1, le=25)
    timeout: int = Field(default=60, ge=1, le=300)
    connect_timeout: int = Field(default=5, ge=1, le=60)

    @field_validator("regions", mode="before")
    @classmethod
    def _normalize_regions(cls, value: object) -> list[str]:
        """Accept list or comma-separated string and normalize to unique ordered list."""
        if value is None:
            return list(_DEFAULT_AWS_REGIONS)

        items: list[str]
        if isinstance(value, str):
            items = [part.strip() for part in value.split(",") if part.strip()]
        elif isinstance(value, list):
            items = [str(part).strip() for part in value if str(part).strip()]
        else:
            raise TypeError("aws.regions must be a list[str] or comma-separated string")

        if not items:
            raise ValueError("aws.regions must contain at least one region")

        seen: set[str] = set()
        ordered: list[str] = []
        for region in items:
            if region not in seen:
                seen.add(region)
                ordered.append(region)
        return ordered


class APIConfig(BaseModel):
    """Flask API runtime configuration."""

    model_config = ConfigDict(frozen=True)

    host: str = Field(default="0.0.0.0")
    port: int = Field(default=5000, ge=1, le=65535)
    workers: int = Field(default=4, ge=1)
    version: str = Field(default="v1")
    debug_errors: bool = Field(default=False)
    log_level: str = Field(default="INFO")
    rate_limit_rps: float | None = Field(default=None, gt=0.0)
    rate_limit_burst: float | None = Field(default=None, gt=0.0)
    enforce_schema_gate: bool = Field(default=True)
    bearer_token: str = Field(default="")

    @field_validator("log_level")
    @classmethod
    def _normalize_log_level(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            return text
        return "INFO"

    @field_validator("version")
    @classmethod
    def _normalize_version(cls, value: str) -> str:
        text = str(value or "").strip().lower()
        if re.match(r"^v\d+$", text):
            return text
        return "v1"


class LoggingSettings(BaseModel):
    """Repository-wide logging settings."""

    model_config = ConfigDict(frozen=True)

    level: str = Field(default="INFO")
    json_logs: bool = Field(default=False)
    override_root_handlers: bool = Field(default=False)

    @field_validator("level")
    @classmethod
    def _normalize_level(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            return text
        return "INFO"


class DbMetricsConfig(BaseModel):
    """DB query instrumentation settings."""

    model_config = ConfigDict(frozen=True)

    metrics_enabled: bool = Field(default=True)
    slow_query_threshold_ms: float = Field(default=1000.0, ge=0.0)

    @field_validator("metrics_enabled", mode="before")
    @classmethod
    def _normalize_metrics_enabled(cls, value: object) -> bool:
        if value is None:
            return True
        text = str(value).strip().lower()
        if text == "":
            return True
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off"}:
            return False
        return True

    @field_validator("slow_query_threshold_ms", mode="before")
    @classmethod
    def _normalize_threshold_ms(cls, value: object) -> float:
        if value is None:
            return 1000.0
        text = str(value).strip()
        if text == "":
            return 1000.0
        try:
            parsed = float(text)
        except (TypeError, ValueError):
            return 1000.0
        return max(0.0, parsed)


class WorkerConfig(BaseModel):
    """Worker/CLI runtime defaults."""

    model_config = ConfigDict(frozen=True)

    tenant_id: str = Field(default="")
    workspace: str = Field(default="")
    out_dir: str = Field(default="data/finops_findings")
    manifest_path: str | None = Field(default=None)
    pricing_version: str | None = Field(default=None)
    pricing_source: str | None = Field(default=None)
    run_lock_ttl_seconds: int = Field(default=1800, ge=1)
    ingest_batch_size: int = Field(default=2000, ge=1)
    parquet_batch_size: int = Field(default=10_000, ge=1)
    allow_schema_mismatch: bool = Field(default=False)
    ingest_disable_copy: bool = Field(default=False)

    @field_validator("tenant_id", "workspace", "out_dir", mode="before")
    @classmethod
    def _normalize_required_text(cls, value: object) -> str:
        return str(value or "").strip()

    @field_validator("manifest_path", "pricing_version", "pricing_source", mode="before")
    @classmethod
    def _normalize_optional_text(cls, value: object) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None


class Settings(BaseModel):
    """Top-level settings model."""

    model_config = ConfigDict(frozen=True)

    db: DatabaseConfig = Field(default_factory=DatabaseConfig)
    aws: AWSConfig = Field(default_factory=AWSConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    db_metrics: DbMetricsConfig = Field(default_factory=DbMetricsConfig)
    worker: WorkerConfig = Field(default_factory=WorkerConfig)

    @classmethod
    def from_env(
        cls,
        *,
        env: Mapping[str, str] | None = None,
        env_file: str = ".env",
    ) -> Settings:
        """Build settings from `.env` then environment variables."""
        runtime_env = os.environ if env is None else env
        merged_env = _merge_env(_load_dotenv(Path(env_file)), runtime_env)
        payload = _build_payload(merged_env)
        return cls.model_validate(payload)


def _load_dotenv(path: Path) -> dict[str, str]:
    """Parse a minimal `.env` file format."""
    if not path.exists() or not path.is_file():
        return {}

    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        key_clean = key.strip()
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if key_clean:
            values[key_clean] = value
    return values


def _merge_env(dotenv_values: Mapping[str, str], runtime_env: Mapping[str, str]) -> dict[str, str]:
    """Return env map where process env overrides `.env` values."""
    merged = {str(k): str(v) for k, v in dotenv_values.items()}
    for key, value in runtime_env.items():
        merged[str(key)] = str(value)
    return merged


def _first_non_empty(env: Mapping[str, str], *keys: str) -> str | None:
    """Return the first non-empty value for the provided keys."""
    for key in keys:
        value = str(env.get(key, "")).strip()
        if value:
            return value
    return None


def _build_payload(env: Mapping[str, str]) -> dict[str, object]:
    """Build nested settings payload from env values."""
    db = {
        "url": _first_non_empty(env, "DB__URL", "DB_URL"),
        "pool_maxconn": _first_non_empty(env, "DB__POOL_MAXCONN", "DB_POOL_MAXCONN"),
        "connect_timeout": _first_non_empty(env, "DB__CONNECT_TIMEOUT", "DB_CONNECT_TIMEOUT"),
    }
    aws = {
        "regions": _first_non_empty(env, "AWS__REGIONS", "AWS_REGIONS"),
        "default_region": _first_non_empty(env, "AWS__DEFAULT_REGION", "AWS_DEFAULT_REGION"),
        "max_retries": _first_non_empty(env, "AWS__MAX_RETRIES", "AWS_MAX_RETRIES"),
        "timeout": _first_non_empty(env, "AWS__TIMEOUT", "AWS_TIMEOUT"),
        "connect_timeout": _first_non_empty(env, "AWS__CONNECT_TIMEOUT", "AWS_CONNECT_TIMEOUT"),
    }
    api = {
        "host": _first_non_empty(env, "API__HOST", "API_HOST", "HOST"),
        "port": _first_non_empty(env, "API__PORT", "API_PORT", "PORT"),
        "workers": _first_non_empty(env, "API__WORKERS", "API_WORKERS"),
        "version": _first_non_empty(env, "API__VERSION", "API_VERSION"),
        "debug_errors": _first_non_empty(env, "API__DEBUG_ERRORS", "API_DEBUG_ERRORS"),
        "log_level": _first_non_empty(env, "API__LOG_LEVEL", "API_LOG_LEVEL"),
        "rate_limit_rps": _first_non_empty(env, "API__RATE_LIMIT_RPS", "API_RATE_LIMIT_RPS"),
        "rate_limit_burst": _first_non_empty(env, "API__RATE_LIMIT_BURST", "API_RATE_LIMIT_BURST"),
        "enforce_schema_gate": _first_non_empty(env, "API__ENFORCE_SCHEMA_GATE", "API_ENFORCE_SCHEMA_GATE"),
        "bearer_token": _first_non_empty(env, "API__BEARER_TOKEN", "API_BEARER_TOKEN"),
    }
    logging_settings = {
        "level": _first_non_empty(env, "LOGGING__LEVEL", "MCKAY_LOG_LEVEL"),
        "json_logs": _first_non_empty(env, "LOGGING__JSON_LOGS", "MCKAY_LOG_JSON"),
        "override_root_handlers": _first_non_empty(
            env, "LOGGING__OVERRIDE_ROOT_HANDLERS", "MCKAY_LOG_OVERRIDE"
        ),
    }
    db_metrics = {
        "metrics_enabled": _first_non_empty(env, "DB_METRICS__ENABLED", "DB_QUERY_METRICS_ENABLED"),
        "slow_query_threshold_ms": _first_non_empty(
            env, "DB_METRICS__SLOW_QUERY_THRESHOLD_MS", "DB_SLOW_QUERY_THRESHOLD_MS"
        ),
    }
    worker = {
        "tenant_id": _first_non_empty(env, "WORKER__TENANT_ID", "TENANT_ID"),
        "workspace": _first_non_empty(env, "WORKER__WORKSPACE", "WORKSPACE"),
        "out_dir": _first_non_empty(env, "WORKER__OUT_DIR", "OUT_DIR"),
        "manifest_path": _first_non_empty(env, "WORKER__MANIFEST_PATH", "MANIFEST_PATH"),
        "pricing_version": _first_non_empty(
            env, "WORKER__PRICING_VERSION", "PRICING_VERSION", "FINOPS_PRICING_VERSION"
        ),
        "pricing_source": _first_non_empty(
            env, "WORKER__PRICING_SOURCE", "PRICING_SOURCE", "FINOPS_PRICING_SOURCE"
        ),
        "run_lock_ttl_seconds": _first_non_empty(
            env, "WORKER__RUN_LOCK_TTL_SECONDS", "RUN_LOCK_TTL_SECONDS"
        ),
        "ingest_batch_size": _first_non_empty(env, "WORKER__INGEST_BATCH_SIZE", "INGEST_BATCH_SIZE"),
        "parquet_batch_size": _first_non_empty(env, "WORKER__PARQUET_BATCH_SIZE", "PARQUET_BATCH_SIZE"),
        "allow_schema_mismatch": _first_non_empty(
            env, "WORKER__ALLOW_SCHEMA_MISMATCH", "ALLOW_SCHEMA_MISMATCH"
        ),
        "ingest_disable_copy": _first_non_empty(
            env, "WORKER__INGEST_DISABLE_COPY", "INGEST_DISABLE_COPY"
        ),
    }
    return {
        "db": {k: v for k, v in db.items() if v is not None},
        "aws": {k: v for k, v in aws.items() if v is not None},
        "api": {k: v for k, v in api.items() if v is not None},
        "logging": {k: v for k, v in logging_settings.items() if v is not None},
        "db_metrics": {k: v for k, v in db_metrics.items() if v is not None},
        "worker": {k: v for k, v in worker.items() if v is not None},
    }


_SETTINGS_LOCK = Lock()
_SETTINGS_CACHE: Settings | None = None


def get_settings(*, reload: bool = False) -> Settings:
    """Return cached settings, optionally forcing reload from env."""
    global _SETTINGS_CACHE
    with _SETTINGS_LOCK:
        if reload or _SETTINGS_CACHE is None:
            _SETTINGS_CACHE = Settings.from_env()
        return _SETTINGS_CACHE


def clear_settings_cache() -> None:
    """Clear in-process settings cache."""
    global _SETTINGS_CACHE
    with _SETTINGS_LOCK:
        _SETTINGS_CACHE = None


__all__ = [
    "APIConfig",
    "AWSConfig",
    "DatabaseConfig",
    "DbMetricsConfig",
    "LoggingSettings",
    "Settings",
    "WorkerConfig",
    "get_settings",
    "clear_settings_cache",
    "ValidationError",
]
