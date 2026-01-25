"""Path and glob conventions for pipeline datasets.

All code that needs to know where datasets live (raw findings, correlated
findings, CUR inputs, exports, ...) should go through
:class:`infra.pipeline_paths.PipelinePaths`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


def _p(path: str | Path) -> Path:
    return path if isinstance(path, Path) else Path(str(path))


def _as_posix_str(path: Path) -> str:
    # DuckDB + globbing are happier with forward slashes even on Windows.
    return path.as_posix()


@dataclass(frozen=True)
class PipelinePaths:
    """
    Central path conventions for all pipeline datasets.

    Rules:
      - Runner/orchestrator may override *base directories* (e.g. CLI --out)
      - Directory names and default layout live here, not scattered in code
      - Globs are produced from the resolved dirs and are stable

    This class should be the ONLY place that knows the canonical layout.
    """

    # Base roots
    base_data_dir: Path = Path("data")
    base_export_dir: Path = Path("webapp_data")

    # Dataset dir names (defaults)
    findings_raw_dirname: str = "finops_findings"
    findings_correlated_dirname: str = "finops_findings_correlated"
    findings_enriched_dirname: str = "finops_findings_enriched"

    cur_raw_dirname: str = "raw_cur"
    cur_facts_dirname: str = "cur_facts"

    # Optional overrides (used by CLI to point elsewhere)
    findings_raw_override: Optional[Path] = None
    findings_correlated_override: Optional[Path] = None
    findings_enriched_override: Optional[Path] = None

    export_override: Optional[Path] = None
    cur_raw_override: Optional[Path] = None
    cur_facts_override: Optional[Path] = None

    def __post_init__(self) -> None:
        # Validate the important invariants early so misuse fails fast.
        for name in (
            "base_data_dir",
            "base_export_dir",
            "findings_raw_override",
            "findings_correlated_override",
            "findings_enriched_override",
            "export_override",
            "cur_raw_override",
            "cur_facts_override",
        ):
            val = getattr(self, name)
            if val is None:
                continue
            if not isinstance(val, Path):
                raise TypeError(f"{name} must be a pathlib.Path (got {type(val)})")

        for dname in (
            "findings_raw_dirname",
            "findings_correlated_dirname",
            "findings_enriched_dirname",
            "cur_raw_dirname",
            "cur_facts_dirname",
        ):
            v = getattr(self, dname)
            if not isinstance(v, str) or not v.strip():
                raise ValueError(f"{dname} must be a non-empty string")
            if "/" in v or "\\" in v:
                raise ValueError(f"{dname} must be a simple directory name, not a path: {v!r}")

    # -------------------------
    # Resolved directories
    # -------------------------

    def findings_raw_dir(self) -> Path:
        return self.findings_raw_override or (self.base_data_dir / self.findings_raw_dirname)

    def findings_correlated_dir(self) -> Path:
        return self.findings_correlated_override or (self.base_data_dir / self.findings_correlated_dirname)

    def findings_enriched_dir(self) -> Path:
        return self.findings_enriched_override or (self.base_data_dir / self.findings_enriched_dirname)

    def cur_raw_dir(self) -> Path:
        return self.cur_raw_override or (self.base_data_dir / self.cur_raw_dirname)

    def cur_facts_dir(self) -> Path:
        return self.cur_facts_override or (self.base_data_dir / self.cur_facts_dirname)

    def export_dir(self) -> Path:
        return self.export_override or self.base_export_dir

    # -------------------------
    # Globs
    # -------------------------

    def parquet_glob(self, directory: Path) -> str:
        return _as_posix_str(directory / "**" / "*.parquet")

    def raw_findings_glob(self) -> str:
        return self.parquet_glob(self.findings_raw_dir())

    def correlated_findings_glob(self) -> str:
        return self.parquet_glob(self.findings_correlated_dir())

    def enriched_findings_glob(self) -> str:
        return self.parquet_glob(self.findings_enriched_dir())

    def cur_raw_glob(self) -> str:
        return self.parquet_glob(self.cur_raw_dir())

    def cur_facts_glob(self) -> str:
        return self.parquet_glob(self.cur_facts_dir())

    def export_findings_globs(self) -> List[str]:
        """
        Standard export inputs. The exporter may auto-select enriched if present,
        but callers should use this to stay consistent.
        """
        return [self.raw_findings_glob(), self.correlated_findings_glob()]

    # -------------------------
    # Constructors
    # -------------------------

    @classmethod
    def with_overrides(
        cls,
        *,
        findings_raw_dir: str | Path | None = None,
        findings_correlated_dir: str | Path | None = None,
        findings_enriched_dir: str | Path | None = None,
        export_dir: str | Path | None = None,
        cur_raw_dir: str | Path | None = None,
        cur_facts_dir: str | Path | None = None,
    ) -> "PipelinePaths":
        """
        Preferred way for runner/CLI to override locations without changing conventions.
        """
        return cls(
            findings_raw_override=_p(findings_raw_dir) if findings_raw_dir else None,
            findings_correlated_override=_p(findings_correlated_dir) if findings_correlated_dir else None,
            findings_enriched_override=_p(findings_enriched_dir) if findings_enriched_dir else None,
            export_override=_p(export_dir) if export_dir else None,
            cur_raw_override=_p(cur_raw_dir) if cur_raw_dir else None,
            cur_facts_override=_p(cur_facts_dir) if cur_facts_dir else None,
        )
