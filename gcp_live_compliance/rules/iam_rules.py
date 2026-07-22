"""Compliance rules evaluated against a live IamPolicySnapshot."""

from __future__ import annotations

from ..collectors.iam import IamPolicySnapshot
from ..models import Finding, Severity

PRIMITIVE_ROLES = {"roles/owner", "roles/editor", "roles/viewer"}
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


def evaluate(snapshot: IamPolicySnapshot) -> list[Finding]:
    findings: list[Finding] = []

    for binding in snapshot.bindings:
        public_members = [m for m in binding.members if m in PUBLIC_MEMBERS]
        if public_members:
            findings.append(
                Finding(
                    rule_id="IAM_PUBLIC_BINDING",
                    severity=Severity.CRITICAL,
                    resource_type="iam_policy",
                    resource_name=snapshot.project_id,
                    message=(
                        f"Role '{binding.role}' is granted to {public_members} — "
                        "this makes the grant public to anyone on the internet, "
                        "not just your organisation."
                    ),
                    recommendation=(
                        f"Remove {public_members} from the '{binding.role}' binding "
                        "unless this project genuinely needs anonymous public access."
                    ),
                    raw={"role": binding.role, "members": binding.members},
                )
            )

        if binding.role in PRIMITIVE_ROLES:
            non_service_account_members = [
                m for m in binding.members if not m.startswith("serviceAccount:")
            ]
            if non_service_account_members:
                findings.append(
                    Finding(
                        rule_id="IAM_PRIMITIVE_ROLE",
                        severity=Severity.HIGH,
                        resource_type="iam_policy",
                        resource_name=snapshot.project_id,
                        message=(
                            f"Primitive role '{binding.role}' is bound directly to "
                            f"{non_service_account_members}. Primitive roles grant broad, "
                            "project-wide permissions and don't follow least privilege."
                        ),
                        recommendation=(
                            f"Replace '{binding.role}' with predefined or custom roles "
                            "scoped to what each principal actually needs."
                        ),
                        raw={"role": binding.role, "members": binding.members},
                    )
                )

    return findings
