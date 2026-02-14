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


class SmokeFail(RuntimeError):
    """Raised when a smoke check fails."""


def _utc_iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _trim(s: str, limit: int = 600) -> str:
    s = (s or "").strip()
    if len(s) <= limit:
        return s
    return s[:limit] + "…"


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
        "User-Agent": "mckay-api-smoke/1.3",
        # Reduce stale reads when API is behind caching layers.
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
                        payload = {"raw": _trim(raw_text), "content_type": content_type}
                else:
                    payload = {"raw": _trim(raw_text), "content_type": content_type}
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
                    return status, payload
                except SmokeFail:
                    return status, {"raw": _trim(raw_text), "content_type": content_type}
            return status, {"raw": _trim(raw_text), "content_type": content_type}

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
                payload = {"raw": _trim(raw_text), "content_type": content_type}
        else:
            payload = {"raw": _trim(raw_text), "content_type": content_type}

        raise SmokeFail(f"{method} {url}: expected {expected_status}, got {status}: {payload}") from exc

    except URLError as exc:
        raise SmokeFail(f"{method} {url}: connection error: {exc}") from exc


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise SmokeFail(msg)


def _collect_fps(payload: Dict[str, Any], *, only_effective_state: Optional[str] = None) -> set[str]:
    out: set[str] = set()
    for x in (payload.get("items") or []):
        fp = str((x or {}).get("fingerprint") or "")
        if not fp:
            continue
        if only_effective_state is not None:
            st = str((x or {}).get("effective_state") or "").strip().lower()
            if st != only_effective_state.strip().lower():
                continue
        out.add(fp)
    return out


def _get_findings(cfg: Cfg, *, state: Optional[str], limit: int = 200) -> Dict[str, Any]:
    q: Dict[str, str] = {
        "tenant_id": cfg.tenant_id,
        "workspace": cfg.workspace,
        "limit": str(limit),
        # Cache buster for API gateway / CDN paths.
        "_ts": str(time.time_ns()),
    }
    if state:
        q["state"] = state
    _, payload = _http_json(cfg, "GET", "/api/findings", query=q, with_auth=True, expected_status=(200,))
    items = payload.get("items") or []
    _assert(isinstance(items, list), "findings.items not a list")
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
    last_payload: Dict[str, Any] = {}
    for _ in range(retries_i):
        payload = _get_findings(cfg, state=state, limit=400)
        last_payload = payload
        if fp not in _collect_fps(payload, only_effective_state=state):
            return
        time.sleep(sleep_s_f)
    details = []
    for item in (last_payload.get("items") or []):
        item_fp = str((item or {}).get("fingerprint") or "")
        if item_fp == fp or item_fp.strip() == fp.strip():
            details.append(
                {
                    "expected_fingerprint": fp,
                    "expected_fingerprint_len": len(fp),
                    "observed_fingerprint": item_fp,
                    "observed_fingerprint_len": len(item_fp),
                    "state": item.get("state"),
                    "effective_state": item.get("effective_state"),
                    "group_key": item.get("group_key"),
                    "run_id": item.get("run_id"),
                }
            )
    raise SmokeFail(
        f"fingerprint still present in state={state!r} after lifecycle update. "
        f"details={details or 'not in current page'}"
    )


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
    raise SmokeFail(f"fingerprint not found in state={state!r} after lifecycle update")


def run_smoke(cfg: Cfg) -> None:
    ok: list[str] = []

    # 1) Public health endpoints
    _http_json(cfg, "GET", "/health", with_auth=False, expected_status=(200,), expect_json=True)
    ok.append("GET /health")

    _http_json(cfg, "GET", "/api/health/db", with_auth=False, expected_status=(200,), expect_json=True)
    ok.append("GET /api/health/db (public)")

    # 2) Auth behavior per flask_app:
    # - missing "Bearer " -> 401
    # - bad token -> 403
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

    # 3) Auth works with token
    _http_json(
        cfg,
        "GET",
        "/api/runs/latest",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace},
        with_auth=True,
        expected_status=(200,),
    )
    ok.append("GET /api/runs/latest (auth OK)")

    # 4) Diff endpoint (does not require findings)
    _http_json(
        cfg,
        "GET",
        "/api/runs/diff/latest",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace},
        with_auth=True,
        expected_status=(200,),
    )
    ok.append("GET /api/runs/diff/latest")

    # 5) Pick an OPEN finding for lifecycle checks
    open_payload = _get_findings(cfg, state="open", limit=200)
    ok.append("GET /api/findings?state=open")

    open_items = open_payload.get("items") or []
    if not open_items:
        # If no open findings, we can still pass basic checks (health/auth/runs/diff).
        print("SMOKE OK ✅ (no open findings to test lifecycle). Checks passed:")
        for x in ok:
            print("  -", x)
        return

    fp = str((open_items[0] or {}).get("fingerprint") or "")
    _assert(bool(fp.strip()), "open finding has no fingerprint")
    ok.append("Select open finding fingerprint")

    print("SMOKE using fingerprint:", fp)

    # 6) Groups list + detail (optional)
    _, groups_resp = _http_json(
        cfg,
        "GET",
        "/api/groups",
        query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace, "limit": "5"},
        with_auth=True,
        expected_status=(200,),
    )
    ok.append("GET /api/groups")

    groups = groups_resp.get("items") or []
    group_key = ""
    if isinstance(groups, list) and groups:
        group_key = str((groups[0] or {}).get("group_key") or "").strip()

    if group_key:
        group_key_escaped = quote(group_key, safe="")
        _http_json(
            cfg,
            "GET",
            f"/api/groups/{group_key_escaped}",
            query={"tenant_id": cfg.tenant_id, "workspace": cfg.workspace, "limit": "3"},
            with_auth=True,
            expected_status=(200,),
        )
        ok.append("GET /api/groups/<group_key>")
    else:
        ok.append("No group_key (skipping group detail/lifecycle)")

    # 7) Fingerprint lifecycle ignore
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

    # Verify state transition via the API filter semantics (effective_state)
    _wait_until_fp_not_in_state(cfg, fp, state="open")
    ok.append("Verify fp removed from state=open after ignore")

    # Optional: verify it is visible under ignored (this should work given your filter is on effective_state)
    _wait_until_fp_in_state(cfg, fp, state="ignored")
    ok.append("Verify fp present in state=ignored after ignore")

    # 8) Fingerprint lifecycle snooze
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

    _wait_until_fp_not_in_state(cfg, fp, state="open")
    ok.append("Verify fp removed from state=open after snooze")

    _wait_until_fp_in_state(cfg, fp, state="snoozed")
    ok.append("Verify fp present in state=snoozed after snooze")

    # 9) Group lifecycle (optional)
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

    print("SMOKE OK ✅")
    for x in ok:
        print("  -", x)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="McKaySystem API smoke checks")
    p.add_argument("--base-url", default=os.getenv("BASE_URL") or "http://127.0.0.1:5000")
    p.add_argument("--tenant-id", default=os.getenv("TENANT_ID") or "")
    p.add_argument("--workspace", default=os.getenv("WORKSPACE") or "")
    p.add_argument("--token", default=os.getenv("API_BEARER_TOKEN") or "")
    p.add_argument("--timeout-s", type=float, default=float(os.getenv("TIMEOUT_S") or "20"))
    p.add_argument("--lifecycle-retries", type=int, default=int(os.getenv("LIFECYCLE_RETRIES") or "40"))
    p.add_argument("--lifecycle-sleep-s", type=float, default=float(os.getenv("LIFECYCLE_SLEEP_S") or "0.5"))
    p.add_argument("--no-strict-json", action="store_true", help="Do not enforce Content-Type application/json")
    p.add_argument("--verbose", action="store_true", help="Print requests as they run")
    return p.parse_args(argv)


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
    )

    try:
        run_smoke(cfg)
        return 0
    except SmokeFail as exc:
        print("SMOKE FAIL ❌", file=sys.stderr)
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
