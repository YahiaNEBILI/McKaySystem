#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class Cfg:
    base_url: str
    tenant_id: str
    workspace: str
    bearer_token: str
    timeout_s: float = 20.0


class SmokeFail(RuntimeError):
    pass


def _utc_iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _http_json(
    cfg: Cfg,
    method: str,
    path: str,
    *,
    query: Optional[Dict[str, str]] = None,
    body: Optional[Dict[str, Any]] = None,
    with_auth: bool = True,
    expected_status: Tuple[int, ...] = (200,),
) -> Tuple[int, Dict[str, Any]]:
    url = cfg.base_url.rstrip("/") + path
    if query:
        url += "?" + urlencode(query)

    headers = {
        "Accept": "application/json",
        "User-Agent": "mckay-api-smoke/1.0",
    }
    if with_auth and cfg.bearer_token:
        headers["Authorization"] = f"Bearer {cfg.bearer_token}"

    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = Request(url=url, method=method, headers=headers, data=data)

    try:
        with urlopen(req, timeout=cfg.timeout_s) as resp:
            status = int(getattr(resp, "status", 200))
            raw = resp.read().decode("utf-8") if resp else ""
            payload = json.loads(raw) if raw else {}
            if status not in expected_status:
                raise SmokeFail(f"{method} {path}: expected {expected_status}, got {status}: {payload}")
            return status, payload
    except HTTPError as e:
        status = int(getattr(e, "code", 0))
        raw = e.read().decode("utf-8") if e.fp else ""
        try:
            payload = json.loads(raw) if raw else {}
        except Exception:
            payload = {"raw": raw}
        if status in expected_status:
            return status, payload
        raise SmokeFail(f"{method} {path}: expected {expected_status}, got {status}: {payload}") from e
    except URLError as e:
        raise SmokeFail(f"{method} {path}: connection error: {e}") from e


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise SmokeFail(msg)


def run_smoke(cfg: Cfg) -> None:
    ok: list[str] = []

    # 1) Public health
    _http_json(cfg, "GET", "/health", with_auth=False, expected_status=(200,))
    ok.append("GET /health")

    _http_json(cfg, "GET", "/api/health/db", with_auth=False, expected_status=(200,))
    ok.append("GET /api/health/db (public)")

    # 2) Auth enforced: /api/* (except /api/health/db) should be 401 when token missing
    _http_json(
        cfg,
        "GET",
        "/api/runs/latest",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace},
        with_auth=False,
        expected_status=(401, 403),  # 401 missing, 403 wrong (depends)
    )
    ok.append("Auth enforced (no token -> 401/403)")

    # 3) Auth works with token
    status, latest = _http_json(
        cfg,
        "GET",
        "/api/runs/latest",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace},
        with_auth=True,
        expected_status=(200,),
    )
    _assert(status == 200, "runs/latest did not return 200")
    ok.append("GET /api/runs/latest (auth OK)")

    # run_id might be None if no runs yet; tolerate that.
    run = latest.get("run") or {}
    run_id = str(run.get("run_id") or "").strip()

    # 4) Findings
    _, findings = _http_json(
        cfg,
        "GET",
        "/api/findings",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace, "limit": "5"},
        with_auth=True,
    )
    _assert("items" in findings, "findings response missing 'items'")
    items: list[dict[str, Any]] = findings.get("items") or []
    _assert(isinstance(items, list), "findings.items not a list")
    ok.append("GET /api/findings")

    # Need at least one finding to test lifecycle/group
    if not items:
        # still test diff endpoint and exit OK
        _http_json(
            cfg,
            "GET",
            "/api/runs/diff/latest",
            query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace},
            with_auth=True,
            expected_status=(200,),
        )
        ok.append("GET /api/runs/diff/latest (no findings case)")
        print("OK (no findings to test lifecycle). Checks passed:")
        for x in ok:
            print("  -", x)
        return

    fp = str(items[0].get("fingerprint") or "").strip()
    _assert(fp, "first finding has no fingerprint")

    # 5) Groups list + detail (may not exist if group_key is null everywhere)
    _, groups_resp = _http_json(
        cfg,
        "GET",
        "/api/groups",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace, "limit": "1"},
        with_auth=True,
        expected_status=(200,),
    )
    ok.append("GET /api/groups")

    groups = groups_resp.get("items") or []
    group_key = ""
    if groups:
        group_key = str(groups[0].get("group_key") or "").strip()

    if group_key:
        _http_json(
            cfg,
            "GET",
            f"/api/groups/{group_key}",
            query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace, "limit": "3"},
            with_auth=True,
            expected_status=(200,),
        )
        ok.append("GET /api/groups/<group_key>")
    else:
        ok.append("Groups present but no group_key (skipping group detail/lifecycle)")

    # 6) Fingerprint lifecycle ignore
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
    ok.append("POST /api/lifecycle/ignore")

    # Verify it shows under ignored
    _, ignored = _http_json(
        cfg,
        "GET",
        "/api/findings",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace, "state": "ignored", "limit": "200"},
        with_auth=True,
    )
    fps = {str(x.get("fingerprint") or "") for x in (ignored.get("items") or [])}
    _assert(fp in fps, "fingerprint not found in ignored after ignore()")
    ok.append("Verify fingerprint ignored")

    # 7) Fingerprint lifecycle snooze (overwrites per-fp state)
    snooze_until = _utc_iso_z(datetime.now(timezone.utc) + timedelta(days=7))
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
    ok.append("POST /api/lifecycle/snooze")

    _, snoozed = _http_json(
        cfg,
        "GET",
        "/api/findings",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace, "state": "snoozed", "limit": "200"},
        with_auth=True,
    )
    fps = {str(x.get("fingerprint") or "") for x in (snoozed.get("items") or [])}
    _assert(fp in fps, "fingerprint not found in snoozed after snooze()")
    ok.append("Verify fingerprint snoozed")

    # 8) Group lifecycle (if group_key available)
    if group_key:
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

    # 9) Run diff (graceful if <2 runs)
    _http_json(
        cfg,
        "GET",
        "/api/runs/diff/latest",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace},
        with_auth=True,
        expected_status=(200,),
    )
    ok.append("GET /api/runs/diff/latest")

    print("SMOKE OK ✅")
    for x in ok:
        print("  -", x)


def main() -> int:
    base_url = (os.getenv("BASE_URL") or "http://127.0.0.1:5000").strip()
    tenant_id = (os.getenv("TENANT_ID") or "").strip()
    workspace = (os.getenv("WORKSPACE") or "").strip()
    bearer = (os.getenv("API_BEARER_TOKEN") or "").strip()

    if not tenant_id or not workspace:
        print("Missing TENANT_ID or WORKSPACE env var.", file=sys.stderr)
        print("Example:", file=sys.stderr)
        print("  export BASE_URL=http://127.0.0.1:5000", file=sys.stderr)
        print("  export TENANT_ID=bugfix", file=sys.stderr)
        print("  export WORKSPACE=noprod", file=sys.stderr)
        print("  export API_BEARER_TOKEN=...", file=sys.stderr)
        return 2

    cfg = Cfg(base_url=base_url, tenant_id=tenant_id, workspace=workspace, bearer_token=bearer)

    try:
        run_smoke(cfg)
        return 0
    except SmokeFail as e:
        print("SMOKE FAIL ❌", file=sys.stderr)
        print(str(e), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
