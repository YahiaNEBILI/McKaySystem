"""
contracts/services.py

Services container + region-aware factory (DI-friendly).

Goals:
- Keep existing code working:
    Services(s3=..., rds=..., backup=..., ec2=...)
- Enable multi-region runs without checkers creating clients:
    factory.for_region("eu-west-3") -> Services (cached)
- Keep it lightweight and pylint-friendly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import boto3
from botocore.config import Config

from services.pricing_service import PricingService, default_cache_dir, make_pricing_cache


@dataclass(frozen=True)
class Services:
    """
    Bag of SDK clients injected into RunContext.

    Backward compatible with existing runner/checkers: s3/rds/backup/ec2 are required.

    `region` is informational and helps with deterministic finding identity/debugging.
    """
    s3: Any
    rds: Any
    backup: Any
    ec2: Any
    ecs: Any = None
    eks: Any = None
    fsx: Any = None
    efs: Any = None
    elbv2: Any = None
    lambda_client: Any = None
    cloudwatch: Any = None
    logs: Any = None
    savingsplans: Any = None
    ce: Any = None  # Cost Explorer client (global, us-east-1)
    region: str = ""
    pricing: Any = None


class ServicesFactory:
    """
    Creates and caches AWS SDK clients per region.

    Usage:
      session = boto3.Session()
      factory = ServicesFactory(session=session, sdk_config=SDK_CONFIG)

      svcs = factory.for_region("eu-west-3")
      svcs2 = factory.for_region("eu-west-3")  # cached, same object

    Notes:
    - S3 is effectively global for most operations; still fine to create it per-region.
      We keep S3 cached globally to avoid pointless duplication.
    - For "global" checks, you can pick a control region and call for_region(control_region).
    """

    def __init__(self, *, session: boto3.Session, sdk_config: Config | None = None) -> None:
        self._session = session
        self._sdk_config = sdk_config
        self._by_region: dict[str, Services] = {}
        self._s3_global: Any | None = None
        self._savingsplans_global: Any | None = None
        self._ce_global: Any | None = None
        self._pricing_client = self._client("pricing", region="us-east-1")
        self._pricing_cache = make_pricing_cache(base_dir=default_cache_dir(), ttl_days=7)
        self._pricing_service = PricingService(pricing_client=self._pricing_client, cache=self._pricing_cache)

    def _client(self, service: str, *, region: str | None) -> Any:
        kwargs: dict[str, Any] = {}
        if region:
            kwargs["region_name"] = region
        if self._sdk_config is not None:
            kwargs["config"] = self._sdk_config
        return self._session.client(service, **kwargs)

    def global_s3(self) -> Any:
        """
        S3 is not truly global, but client behavior doesn't usually depend on region.
        Cache one S3 client to reduce client fan-out.
        """
        if self._s3_global is None:
            self._s3_global = self._client("s3", region=None)
        return self._s3_global

    def global_savingsplans(self) -> Any:
        """Savings Plans inventory is account-wide; reuse one client."""
        if self._savingsplans_global is None:
            self._savingsplans_global = self._client("savingsplans", region="us-east-1")
        return self._savingsplans_global

    def global_ce(self) -> Any:
        """Cost Explorer is a global API; reuse one client."""
        if self._ce_global is None:
            self._ce_global = self._client("ce", region="us-east-1")
        return self._ce_global

    def for_region(self, region: str) -> Services:
        """
        Return cached Services for a given region, creating it if needed.
        """
        reg = str(region or "").strip()
        if not reg:
            raise ValueError("region must be a non-empty string")

        cached = self._by_region.get(reg)
        if cached is not None:
            return cached

        svcs = Services(
            s3=self.global_s3(),
            rds=self._client("rds", region=reg),
            backup=self._client("backup", region=reg),
            ec2=self._client("ec2", region=reg),
            ecs=self._client("ecs", region=reg),
            eks=self._client("eks", region=reg),
            fsx=self._client("fsx", region=reg),
            efs=self._client("efs", region=reg),
            elbv2=self._client("elbv2", region=reg),
            lambda_client=self._client("lambda", region=reg),
            cloudwatch=self._client("cloudwatch", region=reg),
            logs=self._client("logs", region=reg),
            savingsplans=self.global_savingsplans(),
            ce=self.global_ce(),
            pricing=self._pricing_service,
            region=reg,
        )
        self._by_region[reg] = svcs
        return svcs

    def clear_cache(self) -> None:
        """
        Clears per-region Services cache. (Mostly useful for tests.)
        """
        self._by_region.clear()
