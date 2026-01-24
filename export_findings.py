from infra.pipeline_paths import PipelinePaths
from pipeline.export_json import ExportConfig, run_export

paths = PipelinePaths()

cfg = ExportConfig(
    findings_globs=paths.export_findings_globs(),
    tenant_id="engie",
    out_dir=str(paths.export_dir()),
)

run_export(cfg)