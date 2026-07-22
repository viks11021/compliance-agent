"""Compliance rules evaluated against live Cloud Storage bucket snapshots."""

from __future__ import annotations

from ..collectors.storage import BucketSnapshot
from ..models import Finding, Severity

PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


def evaluate(buckets: list[BucketSnapshot]) -> list[Finding]:
    findings: list[Finding] = []

    for bucket in buckets:
        public_bindings = [
            b for b in bucket.bindings if PUBLIC_MEMBERS & set(b["members"])
        ]

        if public_bindings and bucket.public_access_prevention == "enforced":
            # Public Access Prevention overrides public IAM bindings — the
            # binding exists but GCS actively blocks it from taking effect.
            # Still worth a LOW finding: the binding is dead weight that
            # should be cleaned up, and if PAP is ever turned off, it
            # immediately becomes exploitable.
            findings.append(
                Finding(
                    rule_id="STORAGE_PUBLIC_BINDING_BUT_PAP_ENFORCED",
                    severity=Severity.LOW,
                    resource_type="storage_bucket",
                    resource_name=bucket.name,
                    message=(
                        f"Bucket '{bucket.name}' has a public IAM binding "
                        f"({[b['role'] for b in public_bindings]}), but Public "
                        "Access Prevention is enforced, so it isn't currently "
                        "exploitable."
                    ),
                    recommendation=(
                        "Remove the unused public binding for cleanliness, and "
                        "don't rely on Public Access Prevention alone — if it's "
                        "ever disabled, this binding becomes live immediately."
                    ),
                    raw={"bucket": bucket.name, "bindings": public_bindings},
                )
            )
        elif public_bindings:
            findings.append(
                Finding(
                    rule_id="STORAGE_PUBLIC_BUCKET",
                    severity=Severity.CRITICAL,
                    resource_type="storage_bucket",
                    resource_name=bucket.name,
                    message=(
                        f"Bucket '{bucket.name}' grants "
                        f"{[b['role'] for b in public_bindings]} to the public "
                        f"internet ({sorted(PUBLIC_MEMBERS & set().union(*[set(b['members']) for b in public_bindings]))}), "
                        "with no Public Access Prevention to stop it."
                    ),
                    recommendation=(
                        "Remove the public binding unless this bucket is "
                        "genuinely meant to serve public content, and enable "
                        "Public Access Prevention as a backstop either way."
                    ),
                    raw={"bucket": bucket.name, "bindings": public_bindings},
                )
            )

    return findings
