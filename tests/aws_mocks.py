"""Shared AWS test doubles for checker unit tests.

These mocks intentionally avoid boto3 client construction and focus on:
- paginated API behavior
- token-based API pagination
- deterministic pricing lookups
- compact RunContext construction
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from types import SimpleNamespace
from typing import Any, cast

from botocore.exceptions import ClientError

from contracts.finops_checker_pattern import RunContext

PageProvider = list[Mapping[str, Any]] | Callable[[dict[str, Any]], Iterable[Mapping[str, Any]]]


def make_client_error(
    operation_name: str,
    *,
    code: str = "AccessDeniedException",
    message: str = "Denied",
) -> ClientError:
    """Build a deterministic botocore ClientError payload for tests."""
    return ClientError({"Error": {"Code": code, "Message": message}}, operation_name)


class FakePaginator:
    """Simple paginator that supports static pages or kwargs-aware providers."""

    def __init__(self, pages: PageProvider) -> None:
        self._pages = pages

    def paginate(self, **kwargs: Any) -> Iterable[Mapping[str, Any]]:
        provider = self._pages
        if callable(provider):
            yield from provider(dict(kwargs))
            return
        yield from provider


class FakePaginatedAwsClient:
    """Generic fake AWS client exposing get_paginator(op_name)."""

    def __init__(
        self,
        *,
        region: str,
        pages_by_op: Mapping[str, PageProvider],
        raise_on: str | None = None,
        raise_code: str = "AccessDeniedException",
    ) -> None:
        self.meta = SimpleNamespace(region_name=region)
        self._pages_by_op = dict(pages_by_op)
        self._raise_on = raise_on
        self._raise_code = raise_code

    def get_paginator(self, op_name: str) -> FakePaginator:
        if self._raise_on == op_name:
            raise make_client_error(op_name, code=self._raise_code)
        pages = self._pages_by_op.get(op_name)
        if pages is None:
            raise KeyError(f"FakePaginatedAwsClient has no paginator pages configured for {op_name}")
        return FakePaginator(pages)


class FakeBackupClient:
    """Backup client fake covering common ops in backup_* checker tests."""

    def __init__(
        self,
        *,
        region: str,
        plans: list[dict[str, Any]] | None = None,
        selections_by_plan: dict[str, list[dict[str, Any]]] | None = None,
        plan_detail_by_id: dict[str, dict[str, Any]] | None = None,
        vaults: list[dict[str, Any]] | None = None,
        describe_by_name: dict[str, dict[str, Any]] | None = None,
        policy_by_name: dict[str, Any] | None = None,
        recovery_points_by_vault: dict[str, list[dict[str, Any]]] | None = None,
        raise_on: str | None = None,
        raise_code: str = "AccessDeniedException",
    ) -> None:
        self.meta = SimpleNamespace(region_name=region)
        self._plans = plans or []
        self._selections_by_plan = selections_by_plan or {}
        self._plan_detail_by_id = plan_detail_by_id or {}
        self._vaults = vaults or []
        self._describe_by_name = describe_by_name or {}
        self._policy_by_name = policy_by_name or {}
        self._recovery_points_by_vault = recovery_points_by_vault or {}
        self._raise_on = raise_on
        self._raise_code = raise_code

        def _pages_for_plans(_kwargs: dict[str, Any]) -> Iterable[dict[str, Any]]:
            yield {"BackupPlansList": self._plans}

        def _pages_for_selections(kwargs: dict[str, Any]) -> Iterable[dict[str, Any]]:
            plan_id = str(kwargs.get("BackupPlanId") or "")
            yield {"BackupSelectionsList": self._selections_by_plan.get(plan_id, [])}

        def _pages_for_vaults(_kwargs: dict[str, Any]) -> Iterable[dict[str, Any]]:
            yield {"BackupVaultList": self._vaults}

        def _pages_for_recovery_points(kwargs: dict[str, Any]) -> Iterable[dict[str, Any]]:
            vault_name = str(kwargs.get("BackupVaultName") or "")
            yield {"RecoveryPoints": self._recovery_points_by_vault.get(vault_name, [])}

        self._paged = FakePaginatedAwsClient(
            region=region,
            pages_by_op={
                "list_backup_plans": _pages_for_plans,
                "list_backup_selections": _pages_for_selections,
                "list_backup_vaults": _pages_for_vaults,
                "list_recovery_points_by_backup_vault": _pages_for_recovery_points,
            },
            raise_on=raise_on,
            raise_code=raise_code,
        )

    def _maybe_raise(self, operation_name: str) -> None:
        if self._raise_on == operation_name:
            raise make_client_error(operation_name, code=self._raise_code)

    def get_paginator(self, op_name: str) -> FakePaginator:
        return self._paged.get_paginator(op_name)

    def list_backup_plans(self, **_kwargs: Any) -> dict[str, Any]:
        self._maybe_raise("list_backup_plans")
        return {"BackupPlansList": self._plans}

    def list_backup_selections(self, *, BackupPlanId: str, **_kwargs: Any) -> dict[str, Any]:
        self._maybe_raise("list_backup_selections")
        return {"BackupSelectionsList": self._selections_by_plan.get(BackupPlanId, [])}

    def get_backup_plan(self, *, BackupPlanId: str) -> dict[str, Any]:
        self._maybe_raise("get_backup_plan")
        return {"BackupPlan": self._plan_detail_by_id.get(BackupPlanId, {})}

    def list_backup_vaults(self, **_kwargs: Any) -> dict[str, Any]:
        self._maybe_raise("list_backup_vaults")
        return {"BackupVaultList": self._vaults}

    def list_recovery_points_by_backup_vault(self, *, BackupVaultName: str, **_kwargs: Any) -> dict[str, Any]:
        self._maybe_raise("list_recovery_points_by_backup_vault")
        return {"RecoveryPoints": self._recovery_points_by_vault.get(BackupVaultName, [])}

    def describe_backup_vault(self, *, BackupVaultName: str) -> dict[str, Any]:
        self._maybe_raise("describe_backup_vault")
        if BackupVaultName not in self._describe_by_name:
            raise make_client_error("describe_backup_vault", code="ResourceNotFoundException", message="NotFound")
        return self._describe_by_name[BackupVaultName]

    def get_backup_vault_access_policy(self, *, BackupVaultName: str) -> dict[str, Any]:
        self._maybe_raise("get_backup_vault_access_policy")
        policy = self._policy_by_name.get(BackupVaultName)
        if policy is None:
            raise make_client_error(
                "get_backup_vault_access_policy", code="ResourceNotFoundException", message="NotFound"
            )
        if isinstance(policy, str):
            return {"Policy": policy}
        return {"Policy": json.dumps(policy)}


class FakeRdsClient:
    """RDS client fake covering snapshot and instance optimization checker tests."""

    def __init__(
        self,
        *,
        region: str,
        instances: list[dict[str, Any]] | None = None,
        clusters: list[dict[str, Any]] | None = None,
        db_snapshots: list[dict[str, Any]] | None = None,
        cluster_snapshots: list[dict[str, Any]] | None = None,
        tags_by_arn: dict[str, dict[str, str]] | None = None,
        raise_on: str | None = None,
        raise_code: str = "AccessDeniedException",
    ) -> None:
        self.meta = SimpleNamespace(region_name=region)
        self._instances = instances or []
        self._clusters = clusters or []
        self._db_snaps = db_snapshots or []
        self._cluster_snaps = cluster_snapshots or []
        self._tags_by_arn = tags_by_arn or {}

        self._paged = FakePaginatedAwsClient(
            region=region,
            pages_by_op={
                "describe_db_instances": [{"DBInstances": self._instances}],
                "describe_db_clusters": [{"DBClusters": self._clusters}],
                "describe_db_snapshots": [{"DBSnapshots": self._db_snaps}],
                "describe_db_cluster_snapshots": [{"DBClusterSnapshots": self._cluster_snaps}],
            },
            raise_on=raise_on,
            raise_code=raise_code,
        )

    def get_paginator(self, op_name: str) -> FakePaginator:
        return self._paged.get_paginator(op_name)

    def list_tags_for_resource(self, *, ResourceName: str) -> dict[str, Any]:
        tags = self._tags_by_arn.get(ResourceName, {})
        return {"TagList": [{"Key": k, "Value": v} for k, v in tags.items()]}


class FakeTokenPagedClient:
    """Token-paged fake for APIs that page via a `nextToken` parameter."""

    def __init__(self, *, pages: list[Mapping[str, Any]], token_key: str = "nextToken") -> None:
        self._pages = list(pages)
        self._token_key = token_key

    def token_paged_call(self, **kwargs: Any) -> dict[str, Any]:
        """Return page `n` based on `nextToken`; set next token when more pages exist."""
        token = str(kwargs.get(self._token_key) or "")
        idx = int(token) if token else 0
        if idx >= len(self._pages):
            return {}

        payload = dict(self._pages[idx])
        if idx + 1 < len(self._pages):
            payload[self._token_key] = str(idx + 1)
        return payload


class FakeSavingsPlansClient(FakeTokenPagedClient):
    """Savings Plans fake implementing describe_savings_plans()."""

    def describe_savings_plans(self, **kwargs: Any) -> Mapping[str, Any]:
        _ = kwargs.get("states")
        payload = self.token_paged_call(**kwargs)
        if payload:
            return payload
        return {"savingsPlans": []}


class FakePriceQuote:
    """Minimal pricing quote object with the expected unit_price field."""

    def __init__(self, unit_price: float) -> None:
        self.unit_price = float(unit_price)


class FakePricingByField:
    """Deterministic pricing fake keyed by one pricing filter field."""

    def __init__(
        self,
        prices_by_value: Mapping[str, float],
        *,
        field_name: str,
        service_code: str = "AmazonEC2",
        unit: str = "Hrs",
        default_price: float = 0.1,
    ) -> None:
        self._prices_by_value = {str(k): float(v) for k, v in prices_by_value.items()}
        self._field_name = str(field_name)
        self._service_code = str(service_code)
        self._unit = str(unit)
        self._default_price = float(default_price)

    def location_for_region(self, region: str) -> str:
        """Return deterministic location label for pricing filters."""
        assert region
        return "EU (Paris)"

    def get_on_demand_unit_price(self, *, service_code: str, filters: Any, unit: str) -> FakePriceQuote:
        """Resolve fake price from filter field; default when absent."""
        assert service_code == self._service_code
        assert unit == self._unit

        value = ""
        for filt in list(filters or []):
            if str((filt or {}).get("Field") or "") == self._field_name:
                value = str((filt or {}).get("Value") or "")
                break
        return FakePriceQuote(self._prices_by_value.get(value, self._default_price))


def make_run_ctx(**services: Any) -> RunContext:
    """Build a minimal AWS RunContext-like object for checker tests."""
    return cast(
        RunContext,
        SimpleNamespace(
            cloud="aws",
            services=SimpleNamespace(**services),
        ),
    )
