# pipeline/correlate_findings.py
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from pathlib import Path

from pipeline.correlation.engine import CorrelationConfig, CorrelationEngine
from pipeline.correlation.ruleset import load_rules_from_dir

LOG = logging.getLogger(__name__)


def _compute_finding_id_salt(
    *,
    finding_id_mode: str,
    run_id: str,
    run_ts: Optional[datetime] = None,
) -> Optional[str]:
    """
    Convert runner finding-id mode to an optional salt string.
    - stable  -> None (fully stable fingerprints/ids, based on issue_key + scope)
    - per_run -> run_id
    - per_day -> YYYY-MM-DD (UTC)
    """
    mode = (finding_id_mode or "stable").strip().lower()
    if mode == "stable":
        return None
    if mode == "per_run":
        return str(run_id or "")
    if mode == "per_day":
        ts = run_ts or datetime.now(timezone.utc)
        return ts.date().isoformat()
    # Unknown mode -> behave like stable (do not destabilize IDs silently)
    return None


def run_correlation(
    *,
    tenant_id: str,
    workspace_id: str,
    run_id: str,
    findings_glob: str,
    out_dir: str,
    threads: int = 4,
    finding_id_mode: str = "stable",
    run_ts: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Pipeline step: correlate raw findings and emit meta-findings.

    This is the function the runner.py calls.

    Returns a dict so the runner can print a summary and decide exit codes, e.g.:
      {
        "enabled": True,
        "rules_enabled": 1,
        "emitted": 42,
        "errors": 0,
        "out_dir": "data/finops_findings_correlated"
      }
    """
    salt = _compute_finding_id_salt(
        finding_id_mode=finding_id_mode,
        run_id=run_id,
        run_ts=run_ts,
    )

    rules_dir = Path(__file__).resolve().parent / "rules"  # if this file is under pipeline/correlation/
    engine = CorrelationEngine(load_rules_from_dir(rules_dir))

    stats = engine.run(
        CorrelationConfig(
            findings_glob=findings_glob,
            tenant_id=tenant_id,
            workspace_id=workspace_id or "",
            run_id=run_id or "",
            out_dir=out_dir,
            threads=int(threads),
            finding_id_salt=salt,
            # Fail fast by default: correlation failures should be visible.
            fail_fast=True,
        )
    )

    errors_count = len(stats.errors or [])
    LOG.info(
        "Correlation complete: rules_enabled=%d emitted=%d errors=%d out_dir=%s",
        stats.rules_enabled,
        stats.emitted,
        errors_count,
        out_dir,
    )

    for err in stats.errors or []:
        LOG.error("Correlation rule error: %s", err)

    return {
        "enabled": True,
        "rules_enabled": stats.rules_enabled,
        "emitted": stats.emitted,
        "errors": errors_count,
        "out_dir": out_dir,
        "report_path": getattr(stats, "report_path", ""),
    }


def run_correlation_from_bootstrap(bootstrap: Dict[str, Any]) -> Dict[str, Any]:
    """
    Backward-compatible wrapper for older callers.

    Expected keys:
      - tenant_id
      - workspace_id (optional)
      - run_id (optional)
      - findings_parquet_glob OR findings_glob
      - findings_correlated_dir OR out_dir
    Optional:
      - correlation_threads
      - finding_id_mode
    """
    tenant_id = str(bootstrap["tenant_id"])
    workspace_id = str(bootstrap.get("workspace_id") or "")
    run_id = str(bootstrap.get("run_id") or "")

    findings_glob = (
        str(bootstrap.get("findings_parquet_glob") or "")
        or str(bootstrap.get("findings_glob") or "")
    )
    out_dir = (
        str(bootstrap.get("findings_correlated_dir") or "")
        or str(bootstrap.get("out_dir") or "")
    )

    if not findings_glob:
        raise ValueError("bootstrap is missing findings_parquet_glob/findings_glob")
    if not out_dir:
        raise ValueError("bootstrap is missing findings_correlated_dir/out_dir")

    threads = int(bootstrap.get("correlation_threads") or 4)
    finding_id_mode = str(bootstrap.get("finding_id_mode") or "stable")

    return run_correlation(
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        run_id=run_id,
        findings_glob=findings_glob,
        out_dir=out_dir,
        threads=threads,
        finding_id_mode=finding_id_mode,
    )
