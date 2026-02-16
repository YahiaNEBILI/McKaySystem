"""Centralized logging configuration.

The repository supports both human-friendly text logs and structured JSON logs.
The runner uses this module to configure logging in a defensive way (so it
doesn't break environments that already configure root handlers).
"""

from __future__ import annotations

import json
import logging
import sys
import time
from collections.abc import Mapping
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from infra.config import get_settings

# Context that follows requests through the system
# Use set_request_context() to populate, clear_request_context() to reset
request_ctx: ContextVar[dict[str, Any] | None] = ContextVar("request_ctx", default=None)


def set_request_context(**kwargs: Any) -> None:
    """Set context values that will be included in all subsequent log entries."""
    current = request_ctx.get()
    if current is None:
        current = {}
    else:
        current = dict(current)
    current.update(kwargs)
    request_ctx.set(current)


def clear_request_context() -> None:
    """Clear the request context (typically at the start of a new request)."""
    request_ctx.set({})


def get_request_context() -> dict[str, Any]:
    """Get a copy of the current request context."""
    ctx = request_ctx.get()
    return dict(ctx) if ctx else {}


def _utc_iso8601() -> str:
    # Example: 2026-01-24T18:03:12.123Z
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class JsonFormatter(logging.Formatter):
    """
    Safe JSON formatter:
      - Always outputs valid JSON (message escaped via json.dumps)
      - Adds common infra fields
      - Includes exception info when present
    """

    def __init__(self, *, extra_fields: Mapping[str, Any] | None = None) -> None:
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

        # Merge request context if present
        ctx = request_ctx.get()
        if ctx:
            for k, v in ctx.items():
                if k not in base:
                    base[k] = v

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


class StructuredLogger:
    """
    JSON-structured logger with automatic context injection.

    Usage:
        from infra.logging_config import StructuredLogger, set_request_context

        logger = StructuredLogger(__name__)

        # Set context at the start of a request/operation
        set_request_context(tenant_id="abc", workspace="prod", run_id="123")

        # Log events - context is automatically included
        logger.info("finding_ingest_started", fingerprint="abc123")
        # Output: {"timestamp": "...", "level": "INFO", "event": "finding_ingest_started",
        #          "tenant_id": "abc", "workspace": "prod", "run_id": "123",
        #          "fingerprint": "abc123", ...}

        # Clear context when done
        clear_request_context()
    """

    def __init__(self, name: str) -> None:
        self._logger = logging.getLogger(name)

    def _log(self, level: int, event: str, **kwargs: Any) -> None:
        # Build record with request context merged with event data
        # Use extra= to pass structured data to JsonFormatter
        # The event name is passed as part of the record
        extra = {
            "event": event,
            **kwargs,
        }
        # Log with a simple message, structured data goes in extra
        self._logger.log(level, event, extra=extra)

    def debug(self, event: str, **kwargs: Any) -> None:
        self._log(logging.DEBUG, event, **kwargs)

    def info(self, event: str, **kwargs: Any) -> None:
        self._log(logging.INFO, event, **kwargs)

    def warning(self, event: str, **kwargs: Any) -> None:
        self._log(logging.WARNING, event, **kwargs)

    def error(self, event: str, **kwargs: Any) -> None:
        self._log(logging.ERROR, event, **kwargs)

    def critical(self, event: str, **kwargs: Any) -> None:
        self._log(logging.CRITICAL, event, **kwargs)

    def exception(self, event: str, **kwargs: Any) -> None:
        """Log an exception with the current context."""
        self._log(logging.ERROR, event, **kwargs)


@dataclass(frozen=True)
class LoggingConfig:
    level: str = "INFO"
    json_logs: bool = False
    override_root_handlers: bool = False
    extra_fields: Mapping[str, Any] | None = None


def setup_logging(
    *,
    level: str | None = None,
    json_logs: bool | None = None,
    override_root_handlers: bool | None = None,
    extra_fields: Mapping[str, Any] | None = None,
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
    config = get_settings(reload=True).logging

    cfg = LoggingConfig(
        level=(level or config.level).upper(),
        json_logs=json_logs if json_logs is not None else bool(config.json_logs),
        override_root_handlers=override_root_handlers
        if override_root_handlers is not None
        else bool(config.override_root_handlers),
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
