from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from contracts.finops_checker_pattern import FindingDraft, Scope, Severity

from checks.registry import register_checker


@dataclass(frozen=True)
class AwsAccountContext:
    account_id: str
    billing_account_id: Optional[str] = None


def _normalize_s3_location_constraint(value: Optional[str]) -> str:
    """
    S3 GetBucketLocation returns:
      - None or "" for us-east-1
      - "EU" legacy for eu-west-1
      - otherwise region like "eu-west-3", "us-west-2", ...
    """
    if not value:
        return "us-east-1"
    if value == "EU":
        return "eu-west-1"
    return value


class S3LifecycleMissingChecker:
    checker_id = "aws.s3.governance.lifecycle_missing"
    is_regional = False

    def __init__(self, *, account: AwsAccountContext) -> None:
        self._account = account

    def run(self, ctx) -> Iterable[FindingDraft]:
        """
        Real AWS checker: emits a finding for every bucket without lifecycle configuration.
        Also enriches scope.region using get_bucket_location.
        """
        if ctx.services is None:
            raise RuntimeError("S3LifecycleMissingChecker requires ctx.services (AWS clients)")

        s3: BaseClient = ctx.services.s3  # injected by runner

        resp = s3.list_buckets()
        for b in resp.get("Buckets", []) or []:
            name = b.get("Name") or ""
            if not name:
                continue

            # 1) Resolve bucket region (best-effort)
            bucket_region = "unknown"
            try:
                loc = s3.get_bucket_location(Bucket=name)
                bucket_region = _normalize_s3_location_constraint(loc.get("LocationConstraint"))
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                # If we can't read location, keep "unknown" but don't fail the whole checker.
                if code not in ("AccessDenied", "AllAccessDisabled"):
                    # unknown errors should still be visible during MVP
                    raise

            # 2) Detect lifecycle presence
            try:
                s3.get_bucket_lifecycle_configuration(Bucket=name)
                continue  # lifecycle exists => no finding
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")

                if code in ("NoSuchLifecycleConfiguration", "NoSuchLifecycleConfigurationException"):
                    # Missing lifecycle => FAIL finding
                    yield FindingDraft(
                        check_id=self.checker_id,
                        check_name="S3 bucket missing lifecycle policy",
                        category="governance",
                        status="fail",
                        severity=Severity(level="medium", score=50),
                        title="S3 bucket has no lifecycle configuration",
                        message=f"Bucket {name} does not have a lifecycle policy.",
                        recommendation=(
                            "Add lifecycle rules to transition or expire objects where appropriate."
                        ),
                        scope=Scope(
                            cloud=ctx.cloud,
                            billing_account_id=self._account.billing_account_id or self._account.account_id,
                            account_id=self._account.account_id,
                            region=bucket_region,
                            service="AmazonS3",
                            resource_type="s3_bucket",
                            resource_id=name,
                            resource_arn=f"arn:aws:s3:::{name}",
                        ),
                        issue_key={"lifecycle": "missing", "bucket": name},
                        estimated_monthly_savings="",
                        estimate_confidence=0,
                    )
                    continue

                # Access issues => INFO (practical)
                if code in ("AccessDenied", "AllAccessDisabled"):
                    yield FindingDraft(
                        check_id=self.checker_id,
                        check_name="S3 lifecycle policy missing (unable to verify)",
                        category="governance",
                        status="info",
                        severity=Severity(level="low", score=10),
                        title="Cannot verify lifecycle policy (access denied)",
                        message=f"Access denied when reading lifecycle configuration for bucket {name}.",
                        recommendation="Grant s3:GetLifecycleConfiguration to the scanner role.",
                        scope=Scope(
                            cloud=ctx.cloud,
                            billing_account_id=self._account.billing_account_id or self._account.account_id,
                            account_id=self._account.account_id,
                            region=bucket_region,
                            service="AmazonS3",
                            resource_type="s3_bucket",
                            resource_id=name,
                            resource_arn=f"arn:aws:s3:::{name}",
                        ),
                        issue_key={"lifecycle": "unknown_access_denied", "bucket": name},
                        estimated_monthly_savings="",
                        estimate_confidence=0,
                    )
                    continue

                # Unknown error: bubble up for visibility in MVP
                raise


# -----------------------------
# Factory registration (runner uses this; no runner special-casing)
# -----------------------------


@register_checker("checks.aws.s3_lifecycle_missing:S3LifecycleMissingChecker")
def _factory(ctx, bootstrap):
    """Instantiate this checker from runtime bootstrap data.

    Expected bootstrap keys:
      - aws_account_id: str
      - aws_billing_account_id: Optional[str]
    """
    account_id = str(bootstrap.get("aws_account_id") or "")
    if not account_id:
        raise RuntimeError(
            "aws_account_id missing from bootstrap (required for S3LifecycleMissingChecker)"
        )

    billing_account_id = bootstrap.get("aws_billing_account_id") or account_id
    account_ctx = AwsAccountContext(
        account_id=account_id,
        billing_account_id=str(billing_account_id),
    )
    return S3LifecycleMissingChecker(account=account_ctx)
