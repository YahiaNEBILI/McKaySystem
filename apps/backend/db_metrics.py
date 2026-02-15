"""
db_metrics.py

Shared query-timing helpers for the PostgreSQL backend layer.

Goals
-----
- Keep instrumentation lightweight and dependency-free by default.
- Emit slow-query warnings with stable, machine-parseable fields.
- Provide an optional histogram emitter hook for Prometheus/Datadog adapters.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager

_LOGGER = logging.getLogger(__name__)
_HISTOGRAM_NAME = "db_query_duration_ms"
_METRIC_EMITTER: Callable[[str, float, Sequence[str]], None] | None = None


def _env_flag(name: str, default: bool) -> bool:
    """Parse a boolean environment flag with a safe default."""
    raw = (os.getenv(name) or "").strip().lower()
    if raw == "":
        return default
    return raw in {"1", "true", "yes", "on"}


def query_metrics_enabled() -> bool:
    """Return whether DB query instrumentation is enabled."""
    return _env_flag("DB_QUERY_METRICS_ENABLED", True)


def slow_query_threshold_ms() -> float:
    """Return the slow-query warning threshold in milliseconds."""
    raw = (os.getenv("DB_SLOW_QUERY_THRESHOLD_MS") or "").strip()
    if not raw:
        return 1000.0
    try:
        value = float(raw)
    except ValueError:
        return 1000.0
    if value < 0.0:
        return 0.0
    return value


def register_histogram_emitter(emitter: Callable[[str, float, Sequence[str]], None] | None) -> None:
    """Register a histogram emitter callback.

    The callback receives:
    - metric_name
    - observed value (milliseconds)
    - tags (e.g. ["query:fetch_all:select"])
    """
    global _METRIC_EMITTER
    _METRIC_EMITTER = emitter


def _emit_histogram(name: str, value: float, tags: Sequence[str]) -> None:
    """Emit histogram metric if a callback is registered."""
    if _METRIC_EMITTER is None:
        return
    try:
        _METRIC_EMITTER(name, value, tags)
    except (TypeError, ValueError, RuntimeError) as exc:
        _LOGGER.debug("db metric emitter failed: %s", exc)


@contextmanager
def measure_query(name: str) -> Iterator[None]:
    """Measure query duration, warn on slow queries, and emit histogram data."""
    if not query_metrics_enabled():
        yield
        return

    start = time.perf_counter()
    try:
        yield
    finally:
        duration_ms = (time.perf_counter() - start) * 1000.0
        rounded_ms = round(duration_ms, 2)
        if duration_ms >= slow_query_threshold_ms():
            _LOGGER.warning("slow_query query_name=%s duration_ms=%.2f", str(name), rounded_ms)
        _emit_histogram(_HISTOGRAM_NAME, rounded_ms, [f"query:{name}"])
