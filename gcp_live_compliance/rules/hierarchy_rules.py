"""Compliance rules evaluated against a HierarchySnapshot (folder/org
ancestor policies)."""

from __future__ import annotations

from ..collectors.hierarchy import HierarchySnapshot
from ..models import Finding, Severity

PRIMITIVE_ROLES = {"roles/owner", "roles/editor", "roles/viewer"}
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


def evaluate(snapshot: HierarchySnapshot) -> list[Finding]:
    findings: list[Finding] = []

    if not snapshot.has_organization and not snapshot.ancestors:
        # Genuinely nothing above this project — not a gap, just the
        # actual shape of this project's hierarchy. No finding needed;
        # this isn't a problem to report.
        return findings

    for ancestor in snapshot.ancestors:
        if ancestor.error:
            findings.append(
                Finding(
                    rule_id="HIERARCHY_UNVERIFIABLE",
                    severity=Severity.LOW,
                    resource_type="resource_hierarchy",
                    resource_name=ancestor.resource_name,
                    message=(
                        f"Could not read the IAM policy inherited from "
                        f"{ancestor.resource_name} — this scan cannot see "
                        "whether that level grants access beyond what's "
                        "visible at the project."
                    ),
                    recommendation=(
                        "If you need full inherited-permission visibility, "
                        "have an org admin grant the scanner service account "
                        "roles/resourcemanager.folderViewer or "
                        "organizationViewer at that level."
                    ),
                    raw={"resource": ancestor.resource_name, "error": ancestor.error},
                )
            )
            continue

        for binding in ancestor.bindings:
            public_members = [m for m in binding["members"] if m in PUBLIC_MEMBERS]
            if public_members:
                findings.append(
                    Finding(
                        rule_id="HIERARCHY_PUBLIC_BINDING",
                        severity=Severity.CRITICAL,
                        resource_type="resource_hierarchy",
                        resource_name=ancestor.resource_name,
                        message=(
                            f"{ancestor.resource_type.title()} "
                            f"'{ancestor.resource_name}' grants "
                            f"'{binding['role']}' to {public_members} — this "
                            "is inherited by every project underneath it, "
                            "including this one."
                        ),
                        recommendation=(
                            f"Remove {public_members} from this "
                            f"{ancestor.resource_type}-level binding — it "
                            "affects every project inheriting from it, not "
                            "just this one."
                        ),
                        raw={"resource": ancestor.resource_name, "binding": binding},
                    )
                )

            if binding["role"] in PRIMITIVE_ROLES:
                non_service_accounts = [
                    m for m in binding["members"] if not m.startswith("serviceAccount:")
                ]
                if non_service_accounts:
                    findings.append(
                        Finding(
                            rule_id="HIERARCHY_PRIMITIVE_ROLE",
                            severity=Severity.HIGH,
                            resource_type="resource_hierarchy",
                            resource_name=ancestor.resource_name,
                            message=(
                                f"{ancestor.resource_type.title()} "
                                f"'{ancestor.resource_name}' grants the "
                                f"primitive role '{binding['role']}' to "
                                f"{non_service_accounts}, inherited by every "
                                "project underneath, including this one."
                            ),
                            recommendation=(
                                f"Replace this {ancestor.resource_type}-level "
                                "primitive role binding with a narrower "
                                "predefined or custom role."
                            ),
                            raw={"resource": ancestor.resource_name, "binding": binding},
                        )
                    )

    return findings
