"""Execute approved remediation actions through the remediation executor."""

from __future__ import annotations

import argparse
import importlib
import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import boto3  # type: ignore[import-untyped]

from apps.backend.db import db_conn, fetch_all_dict_conn
from infra.config import get_settings
from services.remediation import ActionContext, ExecutionRequest, RemediationExecutor
from services.remediation.impact import upsert_action_impact
from services.remediation.payload import normalize_action_payload

logger = logging.getLogger(__name__)

_STATUS_APPROVED = "approved"
_STATUS_RUNNING = "running"
_STATUS_COMPLETED = "completed"
_STATUS_FAILED = "failed"


@dataclass(frozen=True)
class RemediationWorkerOptions:
    """Input options for one remediation worker run."""

    tenant_id: str
    workspace: str
    limit: int = 50
    actor_id: str = "worker:remediation"
    force_dry_run: bool | None = None


@dataclass(frozen=True)
class RemediationWorkerStats:
    """Worker execution summary for one scope."""

    claimed: int
    completed: int
    failed: int


def _payload_region(payload: Mapping[str, Any]) -> str:
    """Resolve execution region from payload or config default."""
    for key in ("region", "aws_region", "region_name"):
        value = str(payload.get(key) or "").strip()
        if value:
            return value
    default_region = str(get_settings(reload=True).aws.default_region or "").strip()
    return default_region or "us-east-1"


def _services_mapping(services: Any) -> dict[str, Any]:
    """Build ActionContext services mapping from ServicesFactory result."""
    keys = (
        "s3",
        "rds",
        "backup",
        "ec2",
        "ecs",
        "eks",
        "fsx",
        "efs",
        "elbv2",
        "lambda_client",
        "cloudwatch",
        "logs",
        "savingsplans",
        "ce",
        "cloudfront",
        "pricing",
        "region",
    )
    out: dict[str, Any] = {}
    for key in keys:
        out[key] = getattr(services, key, None)
    return out


def _claim_actions(
    conn: Any,
    *,
    tenant_id: str,
    workspace: str,
    limit: int,
) -> list[dict[str, Any]]:
    """Claim approved remediation actions and transition them to running."""
    sql = """
    WITH candidates AS (
      SELECT tenant_id, workspace, action_id
      FROM remediation_actions
      WHERE tenant_id = %s
        AND workspace = %s
        AND status = %s
      ORDER BY approved_at NULLS LAST, requested_at, action_id
      LIMIT %s
      FOR UPDATE SKIP LOCKED
    )
    UPDATE remediation_actions ra
    SET
      status = %s,
      updated_at = now(),
      version = version + 1
    FROM candidates c
    WHERE ra.tenant_id = c.tenant_id
      AND ra.workspace = c.workspace
      AND ra.action_id = c.action_id
    RETURNING
      ra.tenant_id,
      ra.workspace,
      ra.action_id,
      ra.fingerprint,
      ra.check_id,
      ra.action_type,
      ra.action_payload,
      ra.dry_run
    """
    return fetch_all_dict_conn(
        conn,
        sql,
        (tenant_id, workspace, _STATUS_APPROVED, int(limit), _STATUS_RUNNING),
    )


def _claimed_action_from_row(
    row: Mapping[str, Any],
    *,
    fallback_tenant_id: str,
    fallback_workspace: str,
    force_dry_run: bool | None,
) -> dict[str, Any]:
    """Parse one claimed row into execution payload."""
    action_dry_run = bool(row.get("dry_run"))
    effective_dry_run = action_dry_run if force_dry_run is None else bool(force_dry_run)
    return {
        "tenant_id": str(row.get("tenant_id") or fallback_tenant_id),
        "workspace": str(row.get("workspace") or fallback_workspace),
        "action_id": str(row.get("action_id") or ""),
        "fingerprint": str(row.get("fingerprint") or ""),
        "check_id": str(row.get("check_id") or ""),
        "action_type": str(row.get("action_type") or ""),
        "payload": normalize_action_payload(row.get("action_payload")),
        "dry_run": effective_dry_run,
    }


def _build_execution_meta(
    *,
    action_type: str,
    dry_run: bool,
    ok: bool,
    message: str,
    details: Mapping[str, str],
) -> dict[str, Any]:
    """Build execution metadata merged into action_payload."""
    processed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return {
        "execution": {
            "action_type": action_type,
            "dry_run": bool(dry_run),
            "ok": bool(ok),
            "message": str(message or ""),
            "details": dict(details),
            "processed_at": processed_at,
        }
    }


def _outcome_record_for_action(
    *,
    claimed_action: Mapping[str, Any],
    actor_id: str,
    ok: bool,
    message: str,
    details: Mapping[str, str],
) -> dict[str, Any]:
    """Build outcome record to persist for one executed action."""
    final_status = _STATUS_COMPLETED if ok else _STATUS_FAILED
    reason = str(message or final_status)
    return {
        "tenant_id": str(claimed_action.get("tenant_id") or ""),
        "workspace": str(claimed_action.get("workspace") or ""),
        "action_id": str(claimed_action.get("action_id") or ""),
        "status": final_status,
        "reason": reason,
        "event_type": f"remediation.{final_status}",
        "actor_id": actor_id,
        "execution_meta": _build_execution_meta(
            action_type=str(claimed_action.get("action_type") or ""),
            dry_run=bool(claimed_action.get("dry_run")),
            ok=ok,
            message=message,
            details=details,
        ),
    }


def _update_action_result(conn: Any, *, outcome: Mapping[str, Any]) -> None:
    """Persist remediation execution outcome."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE remediation_actions
            SET
              status = %s,
              reason = %s,
              action_payload = COALESCE(action_payload, '{}'::jsonb) || %s::jsonb,
              updated_at = now(),
              version = version + 1
            WHERE tenant_id = %s
              AND workspace = %s
              AND action_id = %s
              AND status = %s
            """,
            (
                str(outcome.get("status") or ""),
                str(outcome.get("reason") or ""),
                json.dumps(outcome.get("execution_meta") or {}, separators=(",", ":")),
                str(outcome.get("tenant_id") or ""),
                str(outcome.get("workspace") or ""),
                str(outcome.get("action_id") or ""),
                _STATUS_RUNNING,
            ),
        )
        if int(cur.rowcount or 0) != 1:
            raise RuntimeError(
                "remediation_action_update_failed: expected running row for "
                f"{outcome.get('tenant_id')}/{outcome.get('workspace')}/{outcome.get('action_id')}"
            )


def _audit_action_outcome(conn: Any, *, outcome: Mapping[str, Any]) -> None:
    """Best-effort write remediation worker event to audit_log."""
    execution_meta = outcome.get("execution_meta") or {}
    meta_map = dict(execution_meta) if isinstance(execution_meta, dict) else {}
    params = (
        str(outcome.get("tenant_id") or ""),
        str(outcome.get("workspace") or ""),
        "remediation_action",
        str(outcome.get("action_id") or ""),
        None,
        str(outcome.get("event_type") or ""),
        "remediation",
        json.dumps({"status": _STATUS_RUNNING}, separators=(",", ":")),
        json.dumps(
            {
                "status": str(outcome.get("status") or ""),
                "reason": str(outcome.get("reason") or ""),
                **meta_map,
            },
            separators=(",", ":"),
        ),
        str(outcome.get("actor_id") or ""),
        str(outcome.get("actor_id") or ""),
        None,
        "worker",
        None,
        "remediation_worker",
        None,
        None,
    )
    try:
        with conn.cursor() as cur:
            cur.execute("SAVEPOINT remediation_worker_audit_1")
            cur.execute(
                """
                INSERT INTO audit_log
                  (tenant_id, workspace, entity_type, entity_id, fingerprint,
                   event_type, event_category, previous_value, new_value,
                   actor_id, actor_email, actor_name, source, ip_address, user_agent,
                   run_id, correlation_id, created_at)
                VALUES
                  (%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s,%s,%s,%s,%s,%s,%s,%s,now())
                """,
                params,
            )
            cur.execute("RELEASE SAVEPOINT remediation_worker_audit_1")
            return
    except (RuntimeError, TypeError, ValueError, AttributeError):
        try:
            with conn.cursor() as cur:
                cur.execute("ROLLBACK TO SAVEPOINT remediation_worker_audit_1")
        except (RuntimeError, TypeError, ValueError, AttributeError):
            pass


def _default_services_factory() -> Any:
    """Build default AWS services factory for remediation worker."""
    session = boto3.Session()
    services_mod = importlib.import_module("contracts.services")
    aws_cfg_mod = importlib.import_module("infra.aws_config")
    services_factory_cls = services_mod.ServicesFactory
    sdk_config = aws_cfg_mod.SDK_CONFIG
    return services_factory_cls(session=session, sdk_config=sdk_config)


def _execute_one_claimed_action(
    *,
    claimed_action: Mapping[str, Any],
    executor: RemediationExecutor,
    services_factory: Any,
    actor_id: str,
) -> dict[str, Any]:
    """Execute one claimed action and build persistence payload."""
    payload = normalize_action_payload(claimed_action.get("payload"))
    region = _payload_region(payload)
    services = services_factory.for_region(region)
    ctx = ActionContext(
        tenant_id=str(claimed_action.get("tenant_id") or ""),
        workspace=str(claimed_action.get("workspace") or ""),
        action_id=str(claimed_action.get("action_id") or ""),
        fingerprint=str(claimed_action.get("fingerprint") or ""),
        check_id=str(claimed_action.get("check_id") or ""),
        services=_services_mapping(services),
    )
    outcome = executor.run(
        ExecutionRequest(
            ctx=ctx,
            action_type=str(claimed_action.get("action_type") or ""),
            payload=payload,
            dry_run=bool(claimed_action.get("dry_run")),
        )
    )
    return _outcome_record_for_action(
        claimed_action=claimed_action,
        actor_id=actor_id,
        ok=outcome.result.ok,
        message=outcome.result.message,
        details=outcome.result.details,
    )


def process_approved_actions(
    *,
    options: RemediationWorkerOptions,
    executor: RemediationExecutor | None = None,
    services_factory: Any = None,
) -> RemediationWorkerStats:
    """Claim and execute approved remediation actions for one scope."""
    if int(options.limit) <= 0:
        raise ValueError("limit must be >= 1")
    if executor is None:
        executor = RemediationExecutor()
    if services_factory is None:
        services_factory = _default_services_factory()

    with db_conn() as conn:
        claimed_rows = _claim_actions(
            conn,
            tenant_id=options.tenant_id,
            workspace=options.workspace,
            limit=int(options.limit),
        )
        conn.commit()

    claimed_actions = [
        _claimed_action_from_row(
            row,
            fallback_tenant_id=options.tenant_id,
            fallback_workspace=options.workspace,
            force_dry_run=options.force_dry_run,
        )
        for row in claimed_rows
    ]

    completed = 0
    failed = 0
    for claimed_action in claimed_actions:
        outcome = _execute_one_claimed_action(
            claimed_action=claimed_action,
            executor=executor,
            services_factory=services_factory,
            actor_id=options.actor_id,
        )
        with db_conn() as conn:
            _update_action_result(conn, outcome=outcome)
            _audit_action_outcome(conn, outcome=outcome)
            upsert_action_impact(
                conn,
                tenant_id=str(outcome.get("tenant_id") or ""),
                workspace=str(outcome.get("workspace") or ""),
                action_id=str(outcome.get("action_id") or ""),
            )
            conn.commit()
        if str(outcome.get("status") or "") == _STATUS_COMPLETED:
            completed += 1
        else:
            failed += 1

    return RemediationWorkerStats(
        claimed=len(claimed_actions),
        completed=completed,
        failed=failed,
    )


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser for remediation worker."""
    parser = argparse.ArgumentParser(description="Execute approved remediation actions.")
    parser.add_argument(
        "--tenant",
        required=False,
        default=None,
        help="Tenant id (or TENANT_ID env var).",
    )
    parser.add_argument(
        "--workspace",
        required=False,
        default=None,
        help="Workspace (or WORKSPACE env var).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Max actions to execute per run.",
    )
    parser.add_argument(
        "--actor",
        default="worker:remediation",
        help="Actor id used in audit events.",
    )
    parser.add_argument(
        "--force-dry-run",
        action="store_true",
        help="Execute all claimed actions in dry-run mode regardless of row value.",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    worker_cfg = get_settings(reload=True).worker
    tenant_id = str(args.tenant or worker_cfg.tenant_id or "").strip()
    workspace = str(args.workspace or worker_cfg.workspace or "").strip()
    if not tenant_id:
        raise SystemExit("Missing --tenant (or TENANT_ID env var).")
    if not workspace:
        raise SystemExit("Missing --workspace (or WORKSPACE env var).")

    stats = process_approved_actions(
        options=RemediationWorkerOptions(
            tenant_id=tenant_id,
            workspace=workspace,
            limit=int(args.limit),
            actor_id=str(args.actor or "worker:remediation"),
            force_dry_run=(True if bool(args.force_dry_run) else None),
        )
    )
    logger.info(
        "OK: remediation worker tenant=%s workspace=%s claimed=%s completed=%s failed=%s",
        tenant_id,
        workspace,
        stats.claimed,
        stats.completed,
        stats.failed,
    )


if __name__ == "__main__":
    main()
