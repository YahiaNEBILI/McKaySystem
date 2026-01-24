from pipeline.export_json import ExportConfig, run_export

cfg = ExportConfig(
    findings_globs=[
        "data/finops_findings/**/*.parquet",
        "data/finops_findings_correlated/**/*.parquet",
    ],
    tenant_id="engie",
    out_dir="webapp_data",
)

run_export(cfg)