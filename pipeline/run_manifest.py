"""Run manifest helpers.

This module provides a small, explicit "single source of truth" for run
identity and paths across pipeline steps.

Why
---
Some pipeline steps historically relied on environment variables or defaults
for critical identifiers like ``tenant_id``. That can lead to silent
"success" with empty outputs (for example, exporting the wrong tenant).

The run manifest is written by :mod:`runner` next to the produced datasets and
is consumed by downstream steps (export, ingest) to avoid hidden defaults.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MANIFEST_FILENAME = "run_manifest.json"


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class RunManifest:
    """Minimal run identity + path context shared across steps."""

    tenant_id: str
    workspace: str
    run_id: str
    run_ts: str

    # Engine metadata (best-effort)
    engine_name: str | None = None
    engine_version: str | None = None
    rulepack_version: str | None = None
    schema_version: int | None = None
    pricing_version: str | None = None
    pricing_source: str | None = None

    # Paths
    out_raw: str | None = None
    out_correlated: str | None = None
    out_enriched: str | None = None
    export_dir: str | None = None

    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if not d.get("created_at"):
            d["created_at"] = _utc_now_iso()
        return d

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> RunManifest:
        return cls(
            tenant_id=str(payload.get("tenant_id") or "").strip(),
            workspace=str(payload.get("workspace") or "").strip(),
            run_id=str(payload.get("run_id") or "").strip(),
            run_ts=str(payload.get("run_ts") or "").strip(),
            engine_name=(str(payload.get("engine_name") or "").strip() or None),
            engine_version=(str(payload.get("engine_version") or "").strip() or None),
            rulepack_version=(str(payload.get("rulepack_version") or "").strip() or None),
            schema_version=(int(payload["schema_version"]) if payload.get("schema_version") is not None else None),
            pricing_version=(str(payload.get("pricing_version") or "").strip() or None),
            pricing_source=(str(payload.get("pricing_source") or "").strip() or None),
            out_raw=(str(payload.get("out_raw") or "").strip() or None),
            out_correlated=(str(payload.get("out_correlated") or "").strip() or None),
            out_enriched=(str(payload.get("out_enriched") or "").strip() or None),
            export_dir=(str(payload.get("export_dir") or "").strip() or None),
            created_at=str(payload.get("created_at") or "").strip(),
        )

    def validate(self) -> None:
        if not self.tenant_id:
            raise ValueError("RunManifest missing tenant_id")
        if not self.workspace:
            raise ValueError("RunManifest missing workspace")
        if not self.run_id:
            raise ValueError("RunManifest missing run_id")
        if not self.run_ts:
            raise ValueError("RunManifest missing run_ts")


def manifest_path(base_dir: str | Path) -> Path:
    """Return the canonical manifest path for a dataset directory."""

    return Path(base_dir) / MANIFEST_FILENAME


def write_manifest(base_dir: str | Path, manifest: RunManifest) -> Path:
    """Write *manifest* to *base_dir* (atomically best-effort)."""

    base = Path(base_dir)
    base.mkdir(parents=True, exist_ok=True)
    path = manifest_path(base)
    tmp = path.with_suffix(path.suffix + ".tmp")

    manifest.validate()
    payload = manifest.to_dict()

    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)
    return path


def load_manifest(path: str | Path) -> RunManifest:
    """Load a manifest from *path* and validate it."""

    p = Path(path)
    payload = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Invalid run manifest (expected object): {p}")
    m = RunManifest.from_dict(payload)
    m.validate()
    return m


def find_manifest(start: str | Path) -> Path | None:
    """Search for a manifest starting at *start* and walking up a few levels."""

    cur = Path(start).resolve()
    if cur.is_file():
        cur = cur.parent

    for _ in range(6):
        cand = cur / MANIFEST_FILENAME
        if cand.exists():
            return cand
        cand2 = cur / "data" / "finops_findings" / MANIFEST_FILENAME
        if cand2.exists():
            return cand2
        if cur.parent == cur:
            break
        cur = cur.parent
    return None
