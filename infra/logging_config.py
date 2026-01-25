"""Centralized logging configuration.

The repository supports both human-friendly text logs and structured JSON logs.
The runner uses this module to configure logging in a defensive way (so it
doesn't break environments that already configure root handlers).
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Optional


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


def _utc_iso8601() -> str:
    # Example: 2026-01-24T18:03:12.123Z
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class JsonFormatter(logging.Formatter):
    """
    Safe JSON formatter:
      - Always outputs valid JSON (message escaped via json.dumps)
      - Adds common infra fields
      - Includes exception info when present
    """

    def __init__(self, *, extra_fields: Optional[Mapping[str, Any]] = None) -> None:
        super().__init__()
        self._extra_fields = dict(extra_fields or {})

    def format(self, record: logging.LogRecord) -> str:
        base: dict[str, Any] = {
            "timestamp": _utc_iso8601(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
            "process": record.process,
            "thread": record.thread,
        }

        # Optional structured context via `extra={...}`
        # (logging puts extra keys onto the record object)
        for k, v in self._extract_extras(record).items():
            # Avoid overwriting core fields
            if k not in base:
                base[k] = v

        # Add always-on extra fields (eg app=..., env=..., tenant=...)
        for k, v in self._extra_fields.items():
            base.setdefault(k, v)

        if record.exc_info:
            base["exception"] = self.formatException(record.exc_info)

        return json.dumps(base, ensure_ascii=False)

    @staticmethod
    def _extract_extras(record: logging.LogRecord) -> dict[str, Any]:
        # Heuristic: anything not in standard LogRecord attributes is "extra"
        standard = {
            "name", "msg", "args", "levelname", "levelno", "pathname", "filename", "module",
            "exc_info", "exc_text", "stack_info", "lineno", "funcName", "created", "msecs",
            "relativeCreated", "thread", "threadName", "processName", "process",
        }
        extras: dict[str, Any] = {}
        for key, value in record.__dict__.items():
            if key not in standard:
                extras[key] = value
        return extras


class TextFormatter(logging.Formatter):
    """
    Human-friendly logs, but UTC timestamps.
    """
    converter = time.gmtime  # UTC

    def __init__(self) -> None:
        super().__init__("%(asctime)sZ | %(levelname)s | %(name)s | %(message)s")


@dataclass(frozen=True)
class LoggingConfig:
    level: str = "INFO"
    json_logs: bool = False
    override_root_handlers: bool = False
    extra_fields: Optional[Mapping[str, Any]] = None


def setup_logging(
    *,
    level: Optional[str] = None,
    json_logs: Optional[bool] = None,
    override_root_handlers: Optional[bool] = None,
    extra_fields: Optional[Mapping[str, Any]] = None,
) -> None:
    """
    Central logging setup for the repo.

    Env vars:
      - MCKAY_LOG_LEVEL: DEBUG|INFO|WARNING|ERROR (default INFO)
      - MCKAY_LOG_JSON:  1/0 (default 0)
      - MCKAY_LOG_OVERRIDE: 1/0 (default 0)
         If 1, replaces any pre-configured root handlers.
         If 0, only configures logging if root has no handlers.

    Note:
      - Defensive by default (won't break Flask/Gunicorn/Lambda/Jupyter).
      - UTC timestamps for both text and JSON logs.
      - JSON logs are always valid JSON.
    """
    cfg = LoggingConfig(
        level=(level or os.getenv("MCKAY_LOG_LEVEL", "INFO")).upper(),
        json_logs=json_logs if json_logs is not None else _env_bool("MCKAY_LOG_JSON", False),
        override_root_handlers=override_root_handlers
        if override_root_handlers is not None
        else _env_bool("MCKAY_LOG_OVERRIDE", False),
        extra_fields=extra_fields,
    )

    root = logging.getLogger()
    root.setLevel(getattr(logging, cfg.level, logging.INFO))

    handler = logging.StreamHandler(sys.stdout)
    if cfg.json_logs:
        handler.setFormatter(JsonFormatter(extra_fields=cfg.extra_fields))
    else:
        handler.setFormatter(TextFormatter())

    if cfg.override_root_handlers:
        # Explicitly requested: replace existing handlers
        for h in list(root.handlers):
            root.removeHandler(h)
        root.addHandler(handler)
    else:
        # Defensive: only add if nothing configured yet
        if not root.handlers:
            root.addHandler(handler)

    # Common noisy libs (tweak as you like)
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
