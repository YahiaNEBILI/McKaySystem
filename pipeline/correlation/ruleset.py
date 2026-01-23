# pipeline/correlation/ruleset.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence

from pipeline.correlation.engine import CorrelationRule, load_rule_sql


@dataclass(frozen=True)
class RuleSetConfig:
    """
    Where correlation SQL files live.
    Keep this configurable so you can ship different rulepacks later.
    """
    rules_dir: str = "pipeline/correlation/rules"


def _sql_path(cfg: RuleSetConfig, filename: str) -> str:
    return str(Path(cfg.rules_dir) / filename)


def build_rules(cfg: RuleSetConfig | None = None) -> List[CorrelationRule]:
    """
    Return the list of enabled correlation rules.

    Each rule must declare the check_ids it depends on. The engine will pre-filter
    findings by those check_ids, which is key for scalability on large Parquet datasets.
    """
    cfg = cfg or RuleSetConfig()

    return [
        CorrelationRule(
            rule_id="aws.backup.correlation.vault_risk",
            name="AWS Backup vault risk (correlated)",
            required_check_ids=_backup_vault_risk_required_check_ids(),
            sql=load_rule_sql(_sql_path(cfg, "aws_backup_vault_risk.sql")),
            enabled=True,
        ),
    ]


def _backup_vault_risk_required_check_ids() -> Sequence[str]:
    # Vaults checker
    # - aws.backup.vaults.no_lifecycle
    # - aws.backup.vaults.access_policy_misconfig
    #
    # Plans checker
    # - aws.backup.recovery_points.stale
    # - aws.backup.rules.no_lifecycle
    # - aws.backup.plans.no_selections
    return (
        "aws.backup.vaults.no_lifecycle",
        "aws.backup.vaults.access_policy_misconfig",
        "aws.backup.recovery_points.stale",
        "aws.backup.rules.no_lifecycle",
        "aws.backup.plans.no_selections",
    )
