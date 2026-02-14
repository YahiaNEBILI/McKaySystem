#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class Cfg:
    base_url: str
    tenant_id: str
    workspace: str
    bearer_token: str
    timeout_s: float = 20.0
    strict_json: bool = True
    verbose: bool = False
    lifecycle_retries: int = 40
    lifecycle_sleep_s: float = 0.5
    mutate: bool = True


class SmokeFail(RuntimeError):
    """Raised when a smoke check fails."""


def _utc_iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _trim(s: str, limit: int = 600) -> str:
    text = (s or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _read_headers_content_type(headers: Any) -> str:
    try:
        return str(headers.get("Content-Type") or "")
    except Exception:
        return ""


def _decode_body(raw_bytes: bytes) -> str:
    return raw_bytes.decode("utf-8", errors="replace") if raw_bytes else ""


def _parse_json_or_raise(
    *,
    method: str,
    url: str,
    status: int,
    content_type: str,
    raw_text: str,
    strict_json: bool,
) -> Dict[str, Any]:
    if not raw_text:
        return {}

    if strict_json and "application/json" not in (content_type or "").lower():
        raise SmokeFail(
            f"{method} {url}: expected JSON Content-Type, got '{content_type or 'unknown'}'. "
            f"Body: {_trim(raw_text)}"
        )

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise SmokeFail(
            f"{method} {url}: invalid JSON (status {status}, content-type '{content_type or 'unknown'}'): "
            f"{exc}. Body: {_trim(raw_text)}"
        ) from exc

    if not isinstance(payload, dict):
        raise SmokeFail(
            f"{method} {url}: expected JSON object at top-level, got {type(payload).__name__}. "
            f"Body: {_trim(raw_text)}"
        )
    return payload


def _http_json(
    cfg: Cfg,
    method: str,
    path: str,
    *,
    query: Optional[Dict[str, str]] = None,
    body: Optional[Dict[str, Any]] = None,
    with_auth: bool = True,
    bearer_override: Optional[str] = None,
    expected_status: Tuple[int, ...] = (200,),
    expect_json: bool = True,
) -> Tuple[int, Dict[str, Any]]:
    url = cfg.base_url.rstrip("/") + path
    if query:
        url += "?" + urlencode(query)

    headers: Dict[str, str] = {
        "Accept": "application/json" if expect_json else "*/*",
        "User-Agent": "mckay-api-smoke/2.0",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }

    bearer = cfg.bearer_token
    if bearer_override is not None:
        bearer = bearer_override
    if with_auth and bearer:
        headers["Authorization"] = f"Bearer {bearer}"

    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = Request(url=url, method=method, headers=headers, data=data)
    if cfg.verbose:
        print(f"> {method} {url}")

    try:
        with urlopen(req, timeout=cfg.timeout_s) as resp:
            status = int(getattr(resp, "status", 200))
            content_type = _read_headers_content_type(getattr(resp, "headers", None))
            raw_text = _decode_body(resp.read() if resp else b"")

            if status not in expected_status:
                payload = {"raw": _trim(raw_text), "content_type": content_type}
                if expect_json:
                    try:
                        payload = _parse_json_or_raise(
                            method=method,
                            url=url,
                            status=status,
                            content_type=content_type,
                            raw_text=raw_text,
                            strict_json=False,
                        )
                    except SmokeFail:
                        pass
                raise SmokeFail(f"{method} {url}: expected {expected_status}, got {status}: {payload}")

            if not expect_json:
                return status, {}

            payload = _parse_json_or_raise(
                method=method,
                url=url,
                status=status,
                content_type=content_type,
                raw_text=raw_text,
                strict_json=cfg.strict_json,
            )
            return status, payload

    except HTTPError as exc:
        status = int(getattr(exc, "code", 0))
        raw_text = ""
        try:
            raw_text = _decode_body(exc.read()) if getattr(exc, "fp", None) else ""
        except Exception:
            raw_text = ""

        content_type = ""
        try:
            content_type = _read_headers_content_type(getattr(exc, "headers", None))
        except Exception:
            content_type = ""

        if status in expected_status:
            if not expect_json:
                return status, {"raw": _trim(raw_text), "content_type": content_type}
            try:
                payload = _parse_json_or_raise(
                    method=method,
                    url=url,
                    status=status,
                    content_type=content_type,
                    raw_text=raw_text,
                    strict_json=False,
                )
            except SmokeFail:
                payload = {"raw": _trim(raw_text), "content_type": content_type}
            return status, payload

        payload = {"raw": _trim(raw_text), "content_type": content_type}
        if expect_json:
            try:
                payload = _parse_json_or_raise(
                    method=method,
                    url=url,
                    status=status,
                    content_type=content_type,
                    raw_text=raw_text,
                    strict_json=False,
                )
            except SmokeFail:
                pass
        raise SmokeFail(f"{method} {url}: expected {expected_status}, got {status}: {payload}") from exc

    except URLError as exc:
        raise SmokeFail(f"{method} {url}: connection error: {exc}") from exc


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise SmokeFail(msg)


def _assert_items_list(payload: Dict[str, Any], endpoint: str) -> None:
    items = payload.get("items")
    _assert(isinstance(items, list), f"{endpoint}: items must be a list")


def _collect_fps(payload: Dict[str, Any], *, only_effective_state: Optional[str] = None) -> set[str]:
    out: set[str] = set()
    for item in (payload.get("items") or []):
        fp = str((item or {}).get("fingerprint") or "")
        if not fp:
            continue
        if only_effective_state is not None:
            st = str((item or {}).get("effective_state") or "").strip().lower()
            if st != only_effective_state.strip().lower():
                continue
        out.add(fp)
    return out


def _get_findings(
    cfg: Cfg,
    *,
    state: Optional[str],
    limit: int = 200,
    extra_query: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    q: Dict[str, str] = {
        "tenant_id": cfg.tenant_id,
        "workspace": cfg.workspace,
        "limit": str(limit),
        "_ts": str(time.time_ns()),
    }
    if state:
        q["state"] = state
    if extra_query:
        q.update(extra_query)

    _, payload = _http_json(cfg, "GET", "/api/findings", query=q, with_auth=True, expected_status=(200,))
    _assert_items_list(payload, "/api/findings")
    return payload


def _wait_until_fp_not_in_state(
    cfg: Cfg,
    fp: str,
    *,
    state: str,
    retries: Optional[int] = None,
    sleep_s: Optional[float] = None,
) -> None:
    retries_i = max(1, int(retries if retries is not None else cfg.lifecycle_retries))
    sleep_s_f = max(0.01, float(sleep_s if sleep_s is not None else cfg.lifecycle_sleep_s))
    for _ in range(retries_i):
        payload = _get_findings(cfg, state=state, limit=400)
        if fp not in _collect_fps(payload, only_effective_state=state):
            return
        time.sleep(sleep_s_f)
    raise SmokeFail(f"fingerprint still present in state={state!r} after lifecycle update: {fp}")


def _wait_until_fp_in_state(
    cfg: Cfg,
    fp: str,
    *,
    state: str,
    retries: Optional[int] = None,
    sleep_s: Optional[float] = None,
) -> None:
    retries_i = max(1, int(retries if retries is not None else cfg.lifecycle_retries))
    sleep_s_f = max(0.01, float(sleep_s if sleep_s is not None else cfg.lifecycle_sleep_s))
    for _ in range(retries_i):
        payload = _get_findings(cfg, state=state, limit=400)
        if fp in _collect_fps(payload, only_effective_state=state):
            return
        time.sleep(sleep_s_f)
    raise SmokeFail(f"fingerprint not found in state={state!r} after lifecycle update: {fp}")


def _check_read_endpoints(cfg: Cfg, ok: list[str]) -> None:
    _http_json(
        cfg,
        "GET",
        "/api/findings/aggregates",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace},
        with_auth=True,
        expected_status=(200,),
    )
    ok.append("GET /api/findings/aggregates")

    _http_json(
        cfg,
        "GET",
        "/api/facets",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace},
        with_auth=True,
        expected_status=(200,),
    )
    ok.append("GET /api/facets")

    _, sla_payload = _http_json(
        cfg,
        "GET",
        "/api/findings/sla/breached",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace, "limit": "50"},
        with_auth=True,
        expected_status=(200,),
    )
    _assert_items_list(sla_payload, "/api/findings/sla/breached")
    ok.append("GET /api/findings/sla/breached")

    _, aging_payload = _http_json(
        cfg,
        "GET",
        "/api/findings/aging",
        query={
            "tenant_id": cfg.tenant_id,
            "workspace": cfg.workspace,
            "age_basis": "detected",
            "min_days": "0",
            "limit": "50",
        },
        with_auth=True,
        expected_status=(200,),
    )
    _assert_items_list(aging_payload, "/api/findings/aging")
    ok.append("GET /api/findings/aging")

    _, audit_payload = _http_json(
        cfg,
        "GET",
        "/api/audit",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace, "limit": "20"},
        with_auth=True,
        expected_status=(200,),
    )
    _assert_items_list(audit_payload, "/api/audit")
    ok.append("GET /api/audit")

    _, teams_payload = _http_json(
        cfg,
        "GET",
        "/api/teams",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace, "limit": "20"},
        with_auth=True,
        expected_status=(200,),
    )
    _assert_items_list(teams_payload, "/api/teams")
    ok.append("GET /api/teams")

    _, policies_payload = _http_json(
        cfg,
        "GET",
        "/api/sla/policies",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace, "limit": "50"},
        with_auth=True,
        expected_status=(200,),
    )
    _assert_items_list(policies_payload, "/api/sla/policies")
    ok.append("GET /api/sla/policies")

    _, overrides_payload = _http_json(
        cfg,
        "GET",
        "/api/sla/policies/overrides",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace, "limit": "50"},
        with_auth=True,
        expected_status=(200,),
    )
    _assert_items_list(overrides_payload, "/api/sla/policies/overrides")
    ok.append("GET /api/sla/policies/overrides")


def _run_team_and_member_mutations(cfg: Cfg, ok: list[str], *, fingerprint: Optional[str]) -> None:
    team_id = f"smoke-team-{int(time.time())}"
    user_id = f"smoke-user-{int(time.time())}"
    owner_email = f"{user_id}@example.com"
    created_team = False
    added_member = False

    try:
        _, create_team_payload = _http_json(
            cfg,
            "POST",
            "/api/teams",
            body={
                "tenant_id": cfg.tenant_id,
                "workspace": cfg.workspace,
                "team_id": team_id,
                "name": f"Smoke Team {team_id}",
                "description": "Created by api_smoke.py",
                "updated_by": "api_smoke",
            },
            with_auth=True,
            expected_status=(201,),
        )
        _assert((create_team_payload.get("team") or {}).get("team_id") == team_id, "created team_id mismatch")
        created_team = True
        ok.append("POST /api/teams (create)")

        _, add_member_payload = _http_json(
            cfg,
            "POST",
            f"/api/teams/{quote(team_id, safe='')}/members",
            body={
                "tenant_id": cfg.tenant_id,
                "workspace": cfg.workspace,
                "user_id": user_id,
                "user_email": owner_email,
                "user_name": "Smoke User",
                "role": "member",
                "updated_by": "api_smoke",
            },
            with_auth=True,
            expected_status=(201,),
        )
        _assert((add_member_payload.get("member") or {}).get("user_id") == user_id, "added user_id mismatch")
        added_member = True
        ok.append("POST /api/teams/<team_id>/members (add)")

        _, members_payload = _http_json(
            cfg,
            "GET",
            f"/api/teams/{quote(team_id, safe='')}/members",
            query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace, "limit": "50"},
            with_auth=True,
            expected_status=(200,),
        )
        _assert_items_list(members_payload, "/api/teams/<team_id>/members")
        member_ids = {str((m or {}).get("user_id") or "") for m in (members_payload.get("items") or [])}
        _assert(user_id in member_ids, "added member not found in member list")
        ok.append("GET /api/teams/<team_id>/members")

        if fingerprint:
            _http_json(
                cfg,
                "PUT",
                f"/api/findings/{quote(fingerprint, safe='')}/team",
                body={
                    "tenant_id": cfg.tenant_id,
                    "workspace": cfg.workspace,
                    "team_id": team_id,
                    "updated_by": "api_smoke",
                },
                with_auth=True,
                expected_status=(200,),
            )
            ok.append("PUT /api/findings/<fingerprint>/team (assign)")

            _http_json(
                cfg,
                "PUT",
                f"/api/findings/{quote(fingerprint, safe='')}/owner",
                body={
                    "tenant_id": cfg.tenant_id,
                    "workspace": cfg.workspace,
                    "owner_email": owner_email,
                    "updated_by": "api_smoke",
                },
                with_auth=True,
                expected_status=(200,),
            )
            ok.append("PUT /api/findings/<fingerprint>/owner (assign)")

            # Clear owner/team to keep test data minimally invasive.
            _http_json(
                cfg,
                "PUT",
                f"/api/findings/{quote(fingerprint, safe='')}/owner",
                body={
                    "tenant_id": cfg.tenant_id,
                    "workspace": cfg.workspace,
                    "owner_id": None,
                    "owner_email": None,
                    "owner_name": None,
                    "updated_by": "api_smoke",
                },
                with_auth=True,
                expected_status=(200,),
            )
            _http_json(
                cfg,
                "PUT",
                f"/api/findings/{quote(fingerprint, safe='')}/team",
                body={
                    "tenant_id": cfg.tenant_id,
                    "workspace": cfg.workspace,
                    "team_id": None,
                    "updated_by": "api_smoke",
                },
                with_auth=True,
                expected_status=(200,),
            )
            ok.append("PUT /api/findings/<fingerprint>/owner (clear)")
            ok.append("PUT /api/findings/<fingerprint>/team (clear)")

    finally:
        # Best-effort cleanup.
        if added_member:
            _http_json(
                cfg,
                "DELETE",
                f"/api/teams/{quote(team_id, safe='')}/members/{quote(user_id, safe='')}",
                query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace, "updated_by": "api_smoke"},
                with_auth=True,
                expected_status=(200, 404),
            )
        if created_team:
            _http_json(
                cfg,
                "DELETE",
                f"/api/teams/{quote(team_id, safe='')}",
                query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace, "updated_by": "api_smoke"},
                with_auth=True,
                expected_status=(200, 404),
            )


def _run_lifecycle_checks(cfg: Cfg, ok: list[str], *, fp_open: Optional[str], group_key: Optional[str]) -> None:
    if not fp_open:
        ok.append("No open findings (skipping lifecycle mutation checks)")
        return

    fp = fp_open
    snooze_until = _utc_iso_z(datetime.now(timezone.utc) + timedelta(days=7))

    _http_json(
        cfg,
        "POST",
        "/api/lifecycle/ignore",
        body={
            "tenant_id": cfg.tenant_id,
            "workspace": cfg.workspace,
            "fingerprint": fp,
            "reason": "smoke-test ignore",
            "updated_by": "api_smoke",
        },
        with_auth=True,
        expected_status=(200,),
    )
    _wait_until_fp_not_in_state(cfg, fp, state="open")
    _wait_until_fp_in_state(cfg, fp, state="ignored")
    ok.append("POST /api/lifecycle/ignore + verify state=ignored")

    _http_json(
        cfg,
        "POST",
        "/api/lifecycle/snooze",
        body={
            "tenant_id": cfg.tenant_id,
            "workspace": cfg.workspace,
            "fingerprint": fp,
            "snooze_until": snooze_until,
            "reason": "smoke-test snooze",
            "updated_by": "api_smoke",
        },
        with_auth=True,
        expected_status=(200,),
    )
    _wait_until_fp_in_state(cfg, fp, state="snoozed")
    ok.append("POST /api/lifecycle/snooze + verify state=snoozed")

    _http_json(
        cfg,
        "POST",
        "/api/lifecycle/resolve",
        body={
            "tenant_id": cfg.tenant_id,
            "workspace": cfg.workspace,
            "fingerprint": fp,
            "reason": "smoke-test resolve",
            "updated_by": "api_smoke",
        },
        with_auth=True,
        expected_status=(200,),
    )
    _wait_until_fp_in_state(cfg, fp, state="resolved")
    ok.append("POST /api/lifecycle/resolve + verify state=resolved")

    if not group_key:
        ok.append("No group_key (skipping group lifecycle checks)")
        return

    _http_json(
        cfg,
        "POST",
        "/api/lifecycle/group/ignore",
        body={
            "tenant_id": cfg.tenant_id,
            "workspace": cfg.workspace,
            "group_key": group_key,
            "reason": "smoke-test group ignore",
            "updated_by": "api_smoke",
        },
        with_auth=True,
        expected_status=(200,),
    )
    ok.append("POST /api/lifecycle/group/ignore")

    _http_json(
        cfg,
        "POST",
        "/api/lifecycle/group/snooze",
        body={
            "tenant_id": cfg.tenant_id,
            "workspace": cfg.workspace,
            "group_key": group_key,
            "snooze_until": snooze_until,
            "reason": "smoke-test group snooze",
            "updated_by": "api_smoke",
        },
        with_auth=True,
        expected_status=(200,),
    )
    ok.append("POST /api/lifecycle/group/snooze")

    _http_json(
        cfg,
        "POST",
        "/api/lifecycle/group/resolve",
        body={
            "tenant_id": cfg.tenant_id,
            "workspace": cfg.workspace,
            "group_key": group_key,
            "reason": "smoke-test group resolve",
            "updated_by": "api_smoke",
        },
        with_auth=True,
        expected_status=(200,),
    )
    ok.append("POST /api/lifecycle/group/resolve")


def run_smoke(cfg: Cfg) -> None:
    ok: list[str] = []

    # Health and auth gates.
    _http_json(cfg, "GET", "/health", with_auth=False, expected_status=(200,), expect_json=True)
    ok.append("GET /health")

    _http_json(cfg, "GET", "/api/health/db", with_auth=False, expected_status=(200,), expect_json=True)
    ok.append("GET /api/health/db (public)")

    _http_json(
        cfg,
        "GET",
        "/api/runs/latest",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace},
        with_auth=False,
        expected_status=(401,),
    )
    ok.append("Auth enforced (missing token -> 401)")

    _http_json(
        cfg,
        "GET",
        "/api/runs/latest",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace},
        with_auth=True,
        bearer_override="definitely-invalid-token",
        expected_status=(403,),
    )
    ok.append("Auth enforced (bad token -> 403)")

    _http_json(
        cfg,
        "GET",
        "/api/runs/latest",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace},
        with_auth=True,
        expected_status=(200,),
    )
    ok.append("GET /api/runs/latest (auth OK)")

    _http_json(
        cfg,
        "GET",
        "/api/runs/diff/latest",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace},
        with_auth=True,
        expected_status=(200,),
    )
    ok.append("GET /api/runs/diff/latest")

    # Core read coverage.
    all_payload = _get_findings(cfg, state=None, limit=200)
    ok.append("GET /api/findings")
    _check_read_endpoints(cfg, ok)

    # Group list/detail probe.
    _, groups_payload = _http_json(
        cfg,
        "GET",
        "/api/groups",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace, "limit": "5"},
        with_auth=True,
        expected_status=(200,),
    )
    _assert_items_list(groups_payload, "/api/groups")
    ok.append("GET /api/groups")

    group_key = ""
    groups = groups_payload.get("items") or []
    if groups:
        group_key = str((groups[0] or {}).get("group_key") or "").strip()
    if group_key:
        _http_json(
            cfg,
            "GET",
            f"/api/groups/{quote(group_key, safe='')}",
            query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace, "limit": "5"},
            with_auth=True,
            expected_status=(200,),
        )
        ok.append("GET /api/groups/<group_key>")
    else:
        ok.append("No group_key (skipping group detail)")

    # Select candidate fingerprints.
    open_payload = _get_findings(cfg, state="open", limit=200)
    open_items = open_payload.get("items") or []
    fp_open = str((open_items[0] or {}).get("fingerprint") or "").strip() if open_items else None
    any_items = all_payload.get("items") or []
    fp_any = str((any_items[0] or {}).get("fingerprint") or "").strip() if any_items else None
    fp_for_governance = fp_open or fp_any or None

    if cfg.mutate:
        _run_team_and_member_mutations(cfg, ok, fingerprint=fp_for_governance)
        _run_lifecycle_checks(cfg, ok, fp_open=fp_open, group_key=group_key or None)
    else:
        ok.append("Mutation checks disabled (--skip-mutations)")

    print("SMOKE OK")
    for line in ok:
        print("  -", line)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="McKaySystem API smoke checks")
    parser.add_argument("--base-url", default=os.getenv("BASE_URL") or "http://127.0.0.1:5000")
    parser.add_argument("--tenant-id", default=os.getenv("TENANT_ID") or "")
    parser.add_argument("--workspace", default=os.getenv("WORKSPACE") or "")
    parser.add_argument("--token", default=os.getenv("API_BEARER_TOKEN") or "")
    parser.add_argument("--timeout-s", type=float, default=float(os.getenv("TIMEOUT_S") or "20"))
    parser.add_argument("--lifecycle-retries", type=int, default=int(os.getenv("LIFECYCLE_RETRIES") or "40"))
    parser.add_argument("--lifecycle-sleep-s", type=float, default=float(os.getenv("LIFECYCLE_SLEEP_S") or "0.5"))
    parser.add_argument("--no-strict-json", action="store_true", help="Do not enforce Content-Type application/json")
    parser.add_argument("--verbose", action="store_true", help="Print requests as they run")
    parser.add_argument("--skip-mutations", action="store_true", help="Run read-only smoke checks")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(list(argv or sys.argv[1:]))

    base_url = str(args.base_url).strip()
    tenant_id = str(args.tenant_id).strip()
    workspace = str(args.workspace).strip()
    bearer = str(args.token).strip()

    if not tenant_id or not workspace:
        print("Missing TENANT_ID or WORKSPACE.", file=sys.stderr)
        print("Examples:", file=sys.stderr)
        print("  export BASE_URL=http://127.0.0.1:5000", file=sys.stderr)
        print("  export TENANT_ID=bugfix", file=sys.stderr)
        print("  export WORKSPACE=noprod", file=sys.stderr)
        print("  export API_BEARER_TOKEN=...", file=sys.stderr)
        print("", file=sys.stderr)
        print("Or:", file=sys.stderr)
        print(
            "  ./api_smoke.py --base-url http://127.0.0.1:5000 --tenant-id bugfix --workspace noprod --token ...",
            file=sys.stderr,
        )
        return 2

    cfg = Cfg(
        base_url=base_url,
        tenant_id=tenant_id,
        workspace=workspace,
        bearer_token=bearer,
        timeout_s=float(args.timeout_s),
        strict_json=not bool(args.no_strict_json),
        verbose=bool(args.verbose),
        lifecycle_retries=max(1, int(args.lifecycle_retries)),
        lifecycle_sleep_s=max(0.01, float(args.lifecycle_sleep_s)),
        mutate=not bool(args.skip_mutations),
    )

    try:
        run_smoke(cfg)
        return 0
    except SmokeFail as exc:
        print("SMOKE FAIL", file=sys.stderr)
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
