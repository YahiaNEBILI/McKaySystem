from __future__ import annotations

import glob
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

import duckdb


def _qident(name: str) -> str:
    """Quote an identifier for DuckDB SQL (double quotes).

    We avoid relying on duckdb.escape_identifier() because it's not available
    in all duckdb Python builds.
    """
    return '"' + name.replace('"', '""') + '"'


def _expand_globs(globs: Sequence[str]) -> List[str]:
    files: List[str] = []
    for g in globs:
        for m in glob.glob(str(g), recursive=True):
            if m.endswith(".parquet"):
                files.append(m)
    return sorted(set(files))


def _first_present(cols: Iterable[str], candidates: Sequence[str]) -> Optional[str]:
    colset = {c.lower(): c for c in cols}
    for cand in candidates:
        if cand.lower() in colset:
            return colset[cand.lower()]
    return None


def _tag_columns(cols: Iterable[str]) -> List[str]:
    """Best-effort detection of CUR tag columns.

    AWS CUR tag columns vary by format, but common parquet exports include:
      - resource_tags_user_<TagKey>
      - resource_tags_user:<TagKey>
      - resource_tags_<TagKey>
      - resource_tags:<TagKey>
    """
    out: List[str] = []
    prefixes = (
        "resource_tags_user_",
        "resource_tags_user:",
        "resource_tags_",
        "resource_tags:",
        "line_item_resource_tags_",
        "line_item_resource_tags:",
    )
    for c in cols:
        cl = c.lower()
        if any(cl.startswith(p) for p in prefixes):
            out.append(c)
    return sorted(set(out))


def _tag_key_from_column(col: str) -> str:
    for p in (
        "resource_tags_user_",
        "resource_tags_user:",
        "resource_tags_",
        "resource_tags:",
        "line_item_resource_tags_",
        "line_item_resource_tags:",
    ):
        if col.lower().startswith(p):
            return col[len(p) :]
    return col


@dataclass(frozen=True)
class CurNormalizeConfig:
    """Configuration for CUR normalization.

    Produces a 'cost_facts' parquet dataset optimized for joining against findings.
    """

    tenant_id: str
    input_globs: List[str]

    out_dir: str = "data/cur_facts"
    workspace_id: str = ""

    # Supported: "unblended" (default), "net", "amortized"
    cost_model: str = "unblended"

    # Partitioning
    partition_by_period: bool = True
    partition_by_account: bool = True
    partition_by_service: bool = False
    partition_by_region: bool = False

    # DuckDB
    threads: int = 4


class CurNormalizer:
    """Normalize AWS CUR parquet(s) into a stable cost_facts dataset."""

    def __init__(self, cfg: CurNormalizeConfig) -> None:
        self.cfg = cfg
        self._con = duckdb.connect(":memory:")
        self._con.execute(f"PRAGMA threads={int(cfg.threads)};")
        self._con.execute("PRAGMA enable_progress_bar=false;")

    def close(self) -> None:
        self._con.close()

    def _detect_columns(self, sample_files: Sequence[str]) -> List[str]:
        rel = "read_parquet(?, union_by_name=true)"
        cur = self._con.execute(f"DESCRIBE SELECT * FROM {rel} LIMIT 0", [list(sample_files)])
        rows = cur.fetchall()
        # DESCRIBE returns: column_name, column_type, null, key, default, extra
        return [r[0] for r in rows]

    def _build_select_sql(self, cols: List[str]) -> Tuple[str, List[str]]:
        # Canonical CUR columns (best effort)
        c_usage_start = _first_present(
            cols,
            ["line_item_usage_start_date", "line_item_usage_start_time", "usage_start_date"],
        )
        c_usage_end = _first_present(
            cols,
            ["line_item_usage_end_date", "line_item_usage_end_time", "usage_end_date"],
        )
        c_period_start = _first_present(
            cols,
            ["bill_billing_period_start_date", "bill_billing_period_start", "billing_period_start_date"],
        )
        c_period_end = _first_present(
            cols,
            ["bill_billing_period_end_date", "bill_billing_period_end", "billing_period_end_date"],
        )

        c_linked_account = _first_present(
            cols, ["line_item_usage_account_id", "line_item_usage_account", "linked_account_id"]
        )
        c_payer_account = _first_present(cols, ["bill_payer_account_id", "payer_account_id"])

        c_service_code = _first_present(
            cols, ["line_item_product_code", "product_product_name", "product_servicecode", "product_service_code"]
        )
        c_region = _first_present(cols, ["product_region", "line_item_region", "region"])
        c_az = _first_present(cols, ["line_item_availability_zone", "availability_zone", "product_availability_zone"])

        c_resource_id = _first_present(cols, ["line_item_resource_id", "resource_id"])
        c_line_item_type = _first_present(cols, ["line_item_line_item_type", "line_item_type"])
        c_usage_type = _first_present(cols, ["line_item_usage_type", "usage_type"])
        c_operation = _first_present(cols, ["line_item_operation", "operation"])

        c_cost_unblended = _first_present(cols, ["line_item_unblended_cost", "unblended_cost"])
        c_cost_net = _first_present(cols, ["line_item_net_unblended_cost", "net_unblended_cost"])
        c_cost_amortized = _first_present(cols, ["line_item_amortized_cost", "amortized_cost"])

        c_currency = _first_present(cols, ["pricing_currency", "bill_billing_currency", "currency"])

        tag_cols = _tag_columns(cols)

        def _safe(col: Optional[str], *, cast: Optional[str] = None, default_sql: str = "NULL") -> str:
            if not col:
                return default_sql
            if cast:
                return f"CAST({_qident(col)} AS {cast})"
            return _qident(col)

        # Region fallback: prefer explicit region, else derive from AZ (us-east-1a -> us-east-1)
        region_expr = "NULL"
        if c_region:
            region_expr = f"NULLIF(TRIM({_safe(c_region, cast='VARCHAR')}), '')"
        elif c_az:
            region_expr = (
                "CASE "
                f"WHEN {_safe(c_az, cast='VARCHAR')} IS NULL THEN NULL "
                f"WHEN length({_safe(c_az, cast='VARCHAR')}) >= 2 "
                f"THEN regexp_replace({_safe(c_az, cast='VARCHAR')}, '[a-z]$', '') "
                "ELSE NULL END"
            )

        # Costs (best-effort)
        cost_unblended_expr = _safe(c_cost_unblended, cast="DECIMAL(18,6)")
        cost_net_expr = _safe(c_cost_net, cast="DECIMAL(18,6)")
        cost_amortized_expr = _safe(c_cost_amortized, cast="DECIMAL(18,6)")

        model = (self.cfg.cost_model or "unblended").strip().lower()
        if model == "net":
            cost_primary_expr = f"COALESCE({cost_net_expr}, {cost_unblended_expr})"
        elif model == "amortized":
            cost_primary_expr = f"COALESCE({cost_amortized_expr}, {cost_unblended_expr})"
        else:
            cost_primary_expr = f"COALESCE({cost_unblended_expr}, {cost_net_expr}, {cost_amortized_expr})"
            model = "unblended"

        currency_expr = "'USD'"
        if c_currency:
            currency_expr = f"COALESCE(NULLIF(TRIM(CAST({_qident(c_currency)} AS VARCHAR)), ''), 'USD')"

        # period = YYYY-MM derived from billing_period_start if present, else usage_start.
        period_source = c_period_start or c_usage_start
        if not period_source:
            period_expr = "NULL"
        else:
            period_expr = f"strftime(CAST({_qident(period_source)} AS TIMESTAMP), '%Y-%m')"

        # Tags map
        tags_expr = "map()"
        if tag_cols:
            entries = []
            for tc in tag_cols:
                key = _tag_key_from_column(tc)
                val = f"NULLIF(TRIM(CAST({_qident(tc)} AS VARCHAR)), '')"
                entries.append(
                    "CASE "
                    f"WHEN {val} IS NULL THEN NULL "
                    f"ELSE struct_pack(k := '{key}', v := {val}) END"
                )
            tags_expr = (
                "map_from_entries("
                "list_filter("
                f"list_value({', '.join(entries)}), "
                "x -> x IS NOT NULL"
                ")"
                ")"
            )

        select_sql = f"""
        SELECT
            '{self.cfg.tenant_id}'::VARCHAR AS tenant_id,
            NULLIF('{self.cfg.workspace_id}'::VARCHAR, '') AS workspace_id,
            {period_expr}::VARCHAR AS billing_period,
            {_safe(c_period_start, cast='TIMESTAMP')} AS billing_period_start,
            {_safe(c_period_end, cast='TIMESTAMP')} AS billing_period_end,
            {_safe(c_usage_start, cast='TIMESTAMP')} AS usage_start,
            {_safe(c_usage_end, cast='TIMESTAMP')} AS usage_end,
            {_safe(c_payer_account, cast='VARCHAR')} AS payer_account_id,
            {_safe(c_linked_account, cast='VARCHAR')} AS account_id,
            {region_expr}::VARCHAR AS region,
            {_safe(c_service_code, cast='VARCHAR')} AS service,
            {_safe(c_resource_id, cast='VARCHAR')} AS resource_id,
            {_safe(c_line_item_type, cast='VARCHAR')} AS line_item_type,
            {_safe(c_usage_type, cast='VARCHAR')} AS usage_type,
            {_safe(c_operation, cast='VARCHAR')} AS operation,
            {currency_expr}::VARCHAR AS currency,
            {cost_unblended_expr} AS cost_unblended,
            {cost_net_expr} AS cost_net,
            {cost_amortized_expr} AS cost_amortized,
            {cost_primary_expr} AS cost_primary,
            '{model}'::VARCHAR AS cost_model,
            {tags_expr} AS tags
        FROM read_parquet(?, union_by_name=true)
        """.strip()

        partition_cols: List[str] = []
        if self.cfg.partition_by_period and period_expr != "NULL":
            partition_cols.append("billing_period")
        if self.cfg.partition_by_account:
            partition_cols.append("account_id")
        if self.cfg.partition_by_service:
            partition_cols.append("service")
        if self.cfg.partition_by_region:
            partition_cols.append("region")

        return select_sql, partition_cols

    def normalize(self) -> Path:
        files = _expand_globs(self.cfg.input_globs)
        if not files:
            raise ValueError("No parquet files matched input_globs")

        cols = self._detect_columns(files[: min(len(files), 50)])
        select_sql, partition_cols = self._build_select_sql(cols)

        out_root = Path(self.cfg.out_dir)
        out_root.mkdir(parents=True, exist_ok=True)

        # Deterministic tenant subdir
        tenant_dir = out_root / f"tenant_id={self.cfg.tenant_id}"
        tenant_dir.mkdir(parents=True, exist_ok=True)

        partition_by_sql = ""
        if partition_cols:
            partition_by_sql = f", PARTITION_BY ({', '.join(partition_cols)})"

        out_path_sql = str(tenant_dir).replace("'", "''")

        copy_sql = (
            "COPY (" + select_sql + ") "
            f"TO '{out_path_sql}' (FORMAT PARQUET, COMPRESSION ZSTD{partition_by_sql});"
        )

        self._con.execute(copy_sql, [files])
        return tenant_dir


def normalize_cur(cfg: CurNormalizeConfig) -> Path:
    normalizer = CurNormalizer(cfg)
    try:
        return normalizer.normalize()
    finally:
        normalizer.close()
