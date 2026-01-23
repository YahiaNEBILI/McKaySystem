from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from contracts.finops_checker_pattern import FindingDraft, Scope, Severity


@dataclass(frozen=True)
class AwsAccountContext:
    account_id: str
    billing_account_id: Optional[str] = None


class S3LifecycleMissingChecker:
    """
    Real AWS checker: emits a finding for every bucket without lifecycle configuration.

    it uses get_bucket_lifecycle_configuration and treats missing lifecycle as "fail",
    similar to how your previous module derived LifecycleRules. :contentReference[oaicite:1]{index=1}
    """
    checker_id = "aws.s3.governance.lifecycle_missing"

    def __init__(self, *, account: AwsAccountContext) -> None:
        self._account = account

    def run(self, ctx) -> Iterable[FindingDraft]:
        s3: BaseClient = ctx.services.s3  # injected by runner

        resp = s3.list_buckets()
        for b in resp.get("Buckets", []) or []:
            name = b.get("Name") or ""
            if not name:
                continue

            # Detect lifecycle presence (same API as the historical checker). :contentReference[oaicite:2]{index=2}
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
                        recommendation="Add lifecycle rules to transition or expire objects where appropriate.",
                        scope=Scope(
                            cloud=ctx.cloud,
                            billing_account_id=self._account.billing_account_id or self._account.account_id,
                            account_id=self._account.account_id,
                            region="global",
                            service="AmazonS3",
                            resource_type="s3_bucket",
                            resource_id=name,
                            resource_arn=f"arn:aws:s3:::{name}",
                        ),
                        issue_key={"lifecycle": "missing"},
                        estimated_monthly_savings="",
                        estimate_confidence=0,
                    )
                    continue

                # Access issues => INFO (optional but practical)
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
                            region="global",
                            service="AmazonS3",
                            resource_type="s3_bucket",
                            resource_id=name,
                            resource_arn=f"arn:aws:s3:::{name}",
                        ),
                        issue_key={"lifecycle": "unknown_access_denied"},
                        estimated_monthly_savings="",
                        estimate_confidence=0,
                    )
                    continue

                # Unknown error: bubble up for visibility in MVP
                raise
