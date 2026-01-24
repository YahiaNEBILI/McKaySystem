from pathlib import Path

import pytest

from infra.pipeline_paths import PipelinePaths


def test_defaults_are_stable() -> None:
    p = PipelinePaths()
    assert p.findings_raw_dir() == Path("data") / "finops_findings"
    assert p.cur_raw_dir() == Path("data") / "raw_cur"
    assert p.raw_findings_glob().replace("\\", "/") == "data/finops_findings/**/*.parquet"


def test_rejects_path_in_dirname() -> None:
    with pytest.raises(ValueError):
        PipelinePaths(findings_raw_dirname="data/finops_findings")  # type: ignore[arg-type]


def test_overrides_work() -> None:
    p = PipelinePaths.with_overrides(findings_raw_dir="custom/raw", export_dir="custom/export")
    assert p.findings_raw_dir() == Path("custom/raw")
    assert p.export_dir() == Path("custom/export")
