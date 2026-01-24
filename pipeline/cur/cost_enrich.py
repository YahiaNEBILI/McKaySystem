from __future__ import annotations

import glob
from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence

import duckdb


def _expand_globs(globs: Sequence[str]) -> List[str]:
    files: List[str] = []
    for g in globs:
        for m in glob.glob(str(g), recursive=True):
            if m.endswith(".parquet"):
                files.append(m)
    return sorted(set(files))


@dataclass(frozen=True)
class CostEnrichConfig:
    """Enrich finops_findings with actual costs from normalized CUR facts."""

    tenant_id: str

    # Findings inputs (raw + correlated, etc.)
    findings_globs: List[str]

    # Normalized CUR facts inputs (output of normalize_cur.py)
    cur_facts_globs: List[str]

    # Output dataset
    out_dir: str = "data/finops_findings_enriched"

    # DuckDB
    threads: int = 4


class CostEnricher:
    """Set-based enrichment of findings with CUR-derived costs using DuckDB."""

    def __init__(self, cfg: CostEnrichConfig) -> None:
        self.cfg = cfg
        self.con = duckdb.connect(":memory:")
        self.con.execute(f"PRAGMA threads={int(cfg.threads)};")
        self.con.execute("PRAGMA enable_progress_bar=false;")

        self.finding_files = _expand_globs(cfg.findings_globs)
        if not self.finding_files:
            raise ValueError("No parquet files matched findings_globs")

        self.cur_files = _expand_globs(cfg.cur_facts_globs)
        if not self.cur_files:
            raise ValueError("No parquet files matched cur_facts_globs")

    def close(self) -> None:
        self.con.close()

    def enrich(self) -> Path:
        """Write an enriched parquet dataset (same schema) into cfg.out_dir."""
        out_root = Path(self.cfg.out_dir)
        out_root.mkdir(parents=True, exist_ok=True)

        # ----------------------------
        # Notes on matching strategy
        # ----------------------------
        # Tier A (high confidence): exact match on account_id + resource_id/arn (+ optional region/service)
        # Tier C (fallback): roll up by account_id (+ optional region/service)
        #
        # This first version intentionally keeps logic simple and deterministic.
        # Tag-based attribution can be added as Tier B later.

        sql = """
        WITH
        findings_all AS (
          SELECT *
          FROM read_parquet(?, union_by_name=true)
          WHERE tenant_id = ?
        ),
        findings AS (
          SELECT
            f.*,
            CAST(f.run_ts AS DATE) AS run_date,
            CAST(date_trunc('month', CAST(f.run_ts AS DATE)) AS DATE) AS month_start,
            CAST(date_trunc('month', CAST(f.run_ts AS DATE) - INTERVAL 1 month) AS DATE) AS prev_month_start,
            (CAST(date_trunc('month', CAST(f.run_ts AS DATE)) AS DATE) - INTERVAL 1 day) AS prev_month_end
          FROM findings_all f
        ),
        cur_facts AS (
          SELECT
            tenant_id,
            account_id,
            region,
            service,
            resource_id,
            currency,
            cost_model,
            cost_primary,
            COALESCE(usage_start, billing_period_start) AS cur_ts
          FROM read_parquet(?, union_by_name=true)
          WHERE tenant_id = ?
        ),

        -- Tier A: exact resource match
        exact_match AS (
          SELECT
            f.finding_id,
            f.fingerprint,
            ANY_VALUE(cf.currency) AS currency,
            ANY_VALUE(cf.cost_model) AS cost_model,

            SUM(CASE WHEN cf.cur_ts >= (f.run_date - INTERVAL 7 day)  AND cf.cur_ts < f.run_date THEN cf.cost_primary ELSE 0 END) AS sum_7d,
            SUM(CASE WHEN cf.cur_ts >= (f.run_date - INTERVAL 30 day) AND cf.cur_ts < f.run_date THEN cf.cost_primary ELSE 0 END) AS sum_30d,
            SUM(CASE WHEN cf.cur_ts >= f.month_start AND cf.cur_ts < (f.run_date + INTERVAL 1 day) THEN cf.cost_primary ELSE 0 END) AS sum_mtd,
            SUM(CASE WHEN cf.cur_ts >= f.prev_month_start AND cf.cur_ts <= f.prev_month_end THEN cf.cost_primary ELSE 0 END) AS sum_prev_month,

            COUNT(*) AS matched_rows
          FROM findings f
          JOIN cur_facts cf
            ON cf.account_id = f.scope.account_id
           AND (
                cf.resource_id = f.scope.resource_id
                OR (f.scope.resource_arn IS NOT NULL AND cf.resource_id = f.scope.resource_arn)
               )
           AND (f.scope.region IS NULL OR cf.region IS NULL OR lower(cf.region) = lower(f.scope.region))
           AND (f.scope.service IS NULL OR cf.service IS NULL OR lower(cf.service) = lower(f.scope.service))
          GROUP BY 1, 2
        ),

        -- Tier C: scoped rollup (account + optional region/service)
        rollup_match AS (
          SELECT
            f.finding_id,
            f.fingerprint,
            ANY_VALUE(cf.currency) AS currency,
            ANY_VALUE(cf.cost_model) AS cost_model,

            SUM(CASE WHEN cf.cur_ts >= (f.run_date - INTERVAL 7 day)  AND cf.cur_ts < f.run_date THEN cf.cost_primary ELSE 0 END) AS sum_7d,
            SUM(CASE WHEN cf.cur_ts >= (f.run_date - INTERVAL 30 day) AND cf.cur_ts < f.run_date THEN cf.cost_primary ELSE 0 END) AS sum_30d,
            SUM(CASE WHEN cf.cur_ts >= f.month_start AND cf.cur_ts < (f.run_date + INTERVAL 1 day) THEN cf.cost_primary ELSE 0 END) AS sum_mtd,
            SUM(CASE WHEN cf.cur_ts >= f.prev_month_start AND cf.cur_ts <= f.prev_month_end THEN cf.cost_primary ELSE 0 END) AS sum_prev_month,

            COUNT(*) AS matched_rows
          FROM findings f
          JOIN cur_facts cf
            ON cf.account_id = f.scope.account_id
           AND (f.scope.region IS NULL OR cf.region IS NULL OR lower(cf.region) = lower(f.scope.region))
           AND (f.scope.service IS NULL OR cf.service IS NULL OR lower(cf.service) = lower(f.scope.service))
          GROUP BY 1, 2
        ),

        enriched AS (
          SELECT
            f.* EXCLUDE (run_date, month_start, prev_month_start, prev_month_end),

            CASE
              WHEN em.matched_rows IS NOT NULL AND em.matched_rows > 0 THEN em.sum_7d
              WHEN rm.matched_rows IS NOT NULL AND rm.matched_rows > 0 THEN rm.sum_7d
              ELSE NULL
            END AS calc_cost_7d,

            CASE
              WHEN em.matched_rows IS NOT NULL AND em.matched_rows > 0 THEN em.sum_30d
              WHEN rm.matched_rows IS NOT NULL AND rm.matched_rows > 0 THEN rm.sum_30d
              ELSE NULL
            END AS calc_cost_30d,

            CASE
              WHEN em.matched_rows IS NOT NULL AND em.matched_rows > 0 THEN em.sum_mtd
              WHEN rm.matched_rows IS NOT NULL AND rm.matched_rows > 0 THEN rm.sum_mtd
              ELSE NULL
            END AS calc_cost_mtd,

            CASE
              WHEN em.matched_rows IS NOT NULL AND em.matched_rows > 0 THEN em.sum_prev_month
              WHEN rm.matched_rows IS NOT NULL AND rm.matched_rows > 0 THEN rm.sum_prev_month
              ELSE NULL
            END AS calc_cost_prev_month,

            CASE
              WHEN em.matched_rows IS NOT NULL AND em.matched_rows > 0 THEN em.currency
              WHEN rm.matched_rows IS NOT NULL AND rm.matched_rows > 0 THEN rm.currency
              ELSE NULL
            END AS calc_currency,

            CASE
              WHEN em.matched_rows IS NOT NULL AND em.matched_rows > 0 THEN em.cost_model
              WHEN rm.matched_rows IS NOT NULL AND rm.matched_rows > 0 THEN rm.cost_model
              ELSE NULL
            END AS calc_cost_model,

            CASE
              WHEN em.matched_rows IS NOT NULL AND em.matched_rows > 0 THEN 'exact_resource_id'
              WHEN rm.matched_rows IS NOT NULL AND rm.matched_rows > 0 THEN 'heuristic'
              ELSE 'none'
            END AS calc_method,

            CASE
              WHEN em.matched_rows IS NOT NULL AND em.matched_rows > 0 THEN 95
              WHEN rm.matched_rows IS NOT NULL AND rm.matched_rows > 0 THEN 20
              ELSE 0
            END AS calc_confidence,

            CASE
              WHEN em.matched_rows IS NOT NULL AND em.matched_rows > 0 THEN ['resource_id']
              WHEN rm.matched_rows IS NOT NULL AND rm.matched_rows > 0 THEN ['account_id','service','region']
              ELSE []
            END AS calc_matched_keys,

            f.run_date AS run_date
          FROM findings f
          LEFT JOIN exact_match em
            ON em.finding_id = f.finding_id
          LEFT JOIN rollup_match rm
            ON rm.finding_id = f.finding_id
        )

        SELECT
          e.* EXCLUDE (
            calc_cost_7d, calc_cost_30d, calc_cost_mtd, calc_cost_prev_month,
            calc_currency, calc_cost_model, calc_method, calc_confidence, calc_matched_keys,
            run_date
          ),

          -- Partition column (not part of schema, used for directory partitioning)
          CAST(e.run_date AS VARCHAR) AS run_date,

          -- Merge actual struct field-by-field (do not override existing values)
          struct_pack(
            cost_7d := COALESCE(e.actual.cost_7d, e.calc_cost_7d),
            cost_30d := COALESCE(e.actual.cost_30d, e.calc_cost_30d),
            cost_mtd := COALESCE(e.actual.cost_mtd, e.calc_cost_mtd),
            cost_prev_month := COALESCE(e.actual.cost_prev_month, e.calc_cost_prev_month),

            savings_7d := e.actual.savings_7d,
            savings_30d := e.actual.savings_30d,

            model := COALESCE(
              e.actual.model,
              struct_pack(
                currency := COALESCE(e.calc_currency, 'USD'),
                cost_model := COALESCE(e.calc_cost_model, 'unblended'),
                granularity := 'daily',
                period_start := CAST(e.run_date - INTERVAL 30 day AS DATE),
                period_end := CAST(e.run_date AS DATE)
              )
            ),

            attribution := COALESCE(
              e.actual.attribution,
              struct_pack(
                method := e.calc_method,
                confidence := CAST(e.calc_confidence AS UTINYINT),
                matched_keys := e.calc_matched_keys
              )
            )
          ) AS actual
        FROM enriched e
        """

        # Directory partitioning like FindingsParquetWriter: tenant_id, run_date
        copy_sql = (
            "COPY (" + sql + ") TO '" + str(out_root).replace("'", "''") + "' "
            "(FORMAT PARQUET, COMPRESSION ZSTD, PARTITION_BY (tenant_id, run_date));"
        )

        self.con.execute(
            copy_sql,
            [self.finding_files, self.cfg.tenant_id, self.cur_files, self.cfg.tenant_id],
        )

        return out_root / f"tenant_id={self.cfg.tenant_id}"


def enrich_findings_with_cur(cfg: CostEnrichConfig) -> Path:
    """Convenience wrapper."""
    enricher = CostEnricher(cfg)
    try:
        return enricher.enrich()
    finally:
        enricher.close()
