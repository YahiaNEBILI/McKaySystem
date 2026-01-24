"""
Correlation ruleset registry.

Goals
- Deterministic rule registration & ordering
- Rule metadata lives in SQL headers to avoid drift
- Consistent output contract enforcement (at the SQL edge)

SQL rule header format (top of file, -- comments):

-- rule_id: aws_backup_vault_risk
-- name: AWS Backup vault risk
-- description: Detects risky Backup Vault settings and missing protections.
-- severity: medium
-- category: backup
-- service: aws.backup
-- enabled: true
-- requires: aws.backup.vaults, aws.backup.plans   # comma-separated table/view ids
-- tags_type: map                                 # map | json_string (default map)

Only rule_id is required; everything else is optional.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    sql_path: Path
    name: str = ""
    description: str = ""
    severity: str = "info"
    category: str = ""
    service: str = ""
    enabled: bool = True
    requires: Tuple[str, ...] = ()
    tags_type: str = "map"  # "map" or "json_string"
    extra: Dict[str, str] = field(default_factory=dict)


def _parse_sql_header(sql_text: str) -> Dict[str, str]:
    """
    Parse leading -- key: value lines.
    Stops at first non-comment, non-empty line.
    """
    meta: Dict[str, str] = {}
    for line in sql_text.splitlines():
        s = line.strip()
        if not s:
            continue
        if not s.startswith("--"):
            break
        # allow "-- key: value"
        body = s[2:].strip()
        if ":" in body:
            k, v = body.split(":", 1)
            meta[k.strip().lower()] = v.strip()
    return meta


def _coerce_bool(v: str, default: bool = True) -> bool:
    if v is None:
        return default
    s = v.strip().lower()
    if s in ("1", "true", "yes", "y", "on", "enabled"):
        return True
    if s in ("0", "false", "no", "n", "off", "disabled"):
        return False
    return default


def load_rules_from_dir(
    rules_dir: Path,
    allow_rule_ids: Optional[Sequence[str]] = None,
    deny_rule_ids: Optional[Sequence[str]] = None,
) -> List[RuleSpec]:
    """
    Loads *.sql rules from a directory with stable ordering.
    Supports allow/deny lists by rule_id.
    """
    allow = set(r.lower() for r in (allow_rule_ids or []))
    deny = set(r.lower() for r in (deny_rule_ids or []))

    rule_specs: List[RuleSpec] = []
    for p in sorted(rules_dir.glob("*.sql")):
        sql_text = p.read_text(encoding="utf-8")
        meta = _parse_sql_header(sql_text)

        rule_id = meta.get("rule_id") or p.stem
        rid = rule_id.strip()
        if not rid:
            raise ValueError(f"Missing rule_id in SQL header and empty filename stem: {p}")

        rid_l = rid.lower()
        if allow and rid_l not in allow:
            continue
        if rid_l in deny:
            continue

        requires_raw = meta.get("requires", "")
        requires = tuple(
            r.strip()
            for r in requires_raw.split(",")
            if r.strip()
        )

        spec = RuleSpec(
            rule_id=rid,
            sql_path=p,
            name=meta.get("name", ""),
            description=meta.get("description", ""),
            severity=meta.get("severity", "info"),
            category=meta.get("category", ""),
            service=meta.get("service", ""),
            enabled=_coerce_bool(meta.get("enabled", "true"), True),
            requires=requires,
            tags_type=(meta.get("tags_type", "map") or "map").strip().lower(),
            extra={k: v for k, v in meta.items() if k not in {
                "rule_id", "name", "description", "severity", "category",
                "service", "enabled", "requires", "tags_type"
            }},
        )
        rule_specs.append(spec)

    # deterministic: enabled first, then rule_id
    rule_specs.sort(key=lambda r: (not r.enabled, r.rule_id.lower()))
    return rule_specs


def default_rules_dir(repo_root: Path) -> Path:
    """
    Adjust if your repository layout differs.
    Expected: pipeline/correlation/rules/*.sql
    """
    return repo_root / "pipeline" / "correlation" / "rules"
