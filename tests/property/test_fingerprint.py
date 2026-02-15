"""Property-based tests for fingerprint stability and uniqueness."""

from __future__ import annotations

import pytest

pytest.importorskip("hypothesis")
from hypothesis import assume, given, settings  # type: ignore  # noqa: E402
from hypothesis import strategies as st

from contracts.finops_contracts import compute_fingerprint

_TENANT_ID = st.from_regex(r"[a-z0-9._-]{2,24}", fullmatch=True)
_CHECK_ID = st.from_regex(r"[a-z0-9._-]{5,64}", fullmatch=True)
_ACCOUNT_ID = st.from_regex(r"\d{12}", fullmatch=True)
_REGION = st.sampled_from(
    ("us-east-1", "us-west-2", "eu-west-1", "eu-west-3", "ap-southeast-1", "ca-central-1")
)
_SERVICE = st.sampled_from(("amazonec2", "awsbackup", "amazonrds", "amazons3", "awslambda"))
_RESOURCE_TYPE = st.sampled_from(("instance", "volume", "bucket", "db", "function"))
_RESOURCE_ID = st.from_regex(r"[A-Za-z0-9:/._-]{3,48}", fullmatch=True)
_ISSUE_KEY = st.dictionaries(
    keys=st.from_regex(r"[a-z_]{1,20}", fullmatch=True),
    values=st.from_regex(r"[A-Za-z0-9._:-]{0,32}", fullmatch=True),
    max_size=6,
)


def _scope_strategy(*, resource_id: st.SearchStrategy[str] = _RESOURCE_ID) -> st.SearchStrategy[dict[str, str]]:
    return st.fixed_dictionaries(
        {
            "cloud": st.just("aws"),
            "billing_account_id": _ACCOUNT_ID,
            "account_id": _ACCOUNT_ID,
            "region": _REGION,
            "service": _SERVICE,
            "resource_type": _RESOURCE_TYPE,
            "resource_id": resource_id,
        }
    )


@settings(max_examples=200, deadline=None, database=None)
@given(tenant_id=_TENANT_ID, check_id=_CHECK_ID, scope=_scope_strategy(), issue_key=_ISSUE_KEY)
def test_fingerprint_deterministic(
    tenant_id: str, check_id: str, scope: dict[str, str], issue_key: dict[str, str]
) -> None:
    """Same canonical inputs must always produce the same fingerprint."""
    fp1 = compute_fingerprint(tenant_id=tenant_id, check_id=check_id, scope=scope, issue_key=issue_key)
    fp2 = compute_fingerprint(tenant_id=tenant_id, check_id=check_id, scope=scope, issue_key=issue_key)
    assert fp1 == fp2
    assert len(fp1) == 64


@settings(max_examples=200, deadline=None, database=None)
@given(tenant_id=_TENANT_ID, check_id=_CHECK_ID, scope=_scope_strategy(), issue_key=_ISSUE_KEY)
def test_fingerprint_independent_of_issue_key_order(
    tenant_id: str, check_id: str, scope: dict[str, str], issue_key: dict[str, str]
) -> None:
    """Issue-key insertion order must not change fingerprint output."""
    forward = dict(issue_key.items())
    reverse = {k: issue_key[k] for k in sorted(issue_key.keys(), reverse=True)}
    fp_forward = compute_fingerprint(tenant_id=tenant_id, check_id=check_id, scope=scope, issue_key=forward)
    fp_reverse = compute_fingerprint(tenant_id=tenant_id, check_id=check_id, scope=scope, issue_key=reverse)
    assert fp_forward == fp_reverse


@settings(max_examples=200, deadline=None, database=None)
@given(tenant_id=_TENANT_ID, check_id=_CHECK_ID, scope=_scope_strategy(), res_b=_RESOURCE_ID)
def test_fingerprint_changes_for_different_resources(
    tenant_id: str, check_id: str, scope: dict[str, str], res_b: str
) -> None:
    """Distinct resource ids for the same check and scope dimensions should not share a fingerprint."""
    assume(scope["resource_id"] != res_b)
    scope_a = dict(scope)
    scope_b = dict(scope)
    scope_b["resource_id"] = res_b
    fp_a = compute_fingerprint(tenant_id=tenant_id, check_id=check_id, scope=scope_a, issue_key={})
    fp_b = compute_fingerprint(tenant_id=tenant_id, check_id=check_id, scope=scope_b, issue_key={})
    assert fp_a != fp_b
