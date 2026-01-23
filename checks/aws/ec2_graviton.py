from __future__ import annotations

from typing import Iterable

from contracts.finops_checker_pattern import FindingDraft, Severity, Scope


class EC2GravitonChecker:
    checker_id = "aws.ec2.rightsizing.graviton"

    def run(self, ctx) -> Iterable[FindingDraft]:
        """
        Dummy EC2 Graviton checker.
        Replace inventory with real AWS calls later.
        """

        # Fake inventory (for now)
        instances = [
            {
                "account_id": "123456789012",
                "region": "eu-west-3",
                "instance_id": "i-abc123",
                "instance_type": "m5.large",
                "arch": "x86_64",
            }
        ]

        for inst in instances:
            if inst["arch"] != "x86_64":
                continue

            yield FindingDraft(
                check_id=self.checker_id,
                check_name="EC2 Graviton candidate",
                category="rightsizing",
                status="fail",
                severity=Severity(level="medium", score=60),
                title="Instance is likely Graviton-compatible",
                message=f"Instance {inst['instance_id']} is running on x86.",
                recommendation="Consider migrating to Graviton (m7g/c7g/r7g).",
                scope=Scope(
                    cloud=ctx.cloud,
                    billing_account_id=inst["account_id"],
                    account_id=inst["account_id"],
                    region=inst["region"],
                    service="AmazonEC2",
                    resource_type="ec2_instance",
                    resource_id=inst["instance_id"],
                ),
                issue_key={
                    "current_arch": "x86_64",
                    "recommended_arch": "arm64",
                },
                estimated_monthly_savings="12.34",
                estimate_confidence=70,
            )
