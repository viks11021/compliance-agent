"""Unit tests for hierarchy_rules — hand-built HierarchySnapshot objects,
no live Resource Manager API calls."""

from gcp_live_compliance.collectors.hierarchy import AncestorPolicy, HierarchySnapshot
from gcp_live_compliance.rules import hierarchy_rules


def test_no_organization_no_ancestors_gives_no_findings():
    snapshot = HierarchySnapshot(project_id="demo-project", ancestors=[], has_organization=False)
    assert hierarchy_rules.evaluate(snapshot) == []


def test_permission_denied_produces_low_informational_finding():
    snapshot = HierarchySnapshot(
        project_id="demo-project",
        has_organization=True,
        ancestors=[
            AncestorPolicy(
                resource_name="organizations/123",
                resource_type="organization",
                error="Permission denied reading IAM policy",
            )
        ],
    )
    findings = hierarchy_rules.evaluate(snapshot)
    assert len(findings) == 1
    assert findings[0].rule_id == "HIERARCHY_UNVERIFIABLE"
    assert findings[0].severity.value == "LOW"


def test_public_binding_at_folder_level_flagged_critical():
    snapshot = HierarchySnapshot(
        project_id="demo-project",
        has_organization=True,
        ancestors=[
            AncestorPolicy(
                resource_name="folders/111",
                resource_type="folder",
                bindings=[{"role": "roles/viewer", "members": ["allUsers"]}],
            )
        ],
    )
    findings = hierarchy_rules.evaluate(snapshot)
    assert any(f.rule_id == "HIERARCHY_PUBLIC_BINDING" for f in findings)


def test_primitive_role_on_human_at_org_level_flagged_high():
    snapshot = HierarchySnapshot(
        project_id="demo-project",
        has_organization=True,
        ancestors=[
            AncestorPolicy(
                resource_name="organizations/123",
                resource_type="organization",
                bindings=[{"role": "roles/editor", "members": ["user:dev@example.com"]}],
            )
        ],
    )
    findings = hierarchy_rules.evaluate(snapshot)
    assert any(f.rule_id == "HIERARCHY_PRIMITIVE_ROLE" for f in findings)


def test_primitive_role_on_service_account_only_not_flagged():
    snapshot = HierarchySnapshot(
        project_id="demo-project",
        has_organization=True,
        ancestors=[
            AncestorPolicy(
                resource_name="organizations/123",
                resource_type="organization",
                bindings=[
                    {
                        "role": "roles/editor",
                        "members": ["serviceAccount:ci@demo-project.iam.gserviceaccount.com"],
                    }
                ],
            )
        ],
    )
    assert hierarchy_rules.evaluate(snapshot) == []


def test_clean_ancestor_no_findings():
    snapshot = HierarchySnapshot(
        project_id="demo-project",
        has_organization=True,
        ancestors=[
            AncestorPolicy(
                resource_name="organizations/123",
                resource_type="organization",
                bindings=[{"role": "roles/logging.viewer", "members": ["group:sre@example.com"]}],
            )
        ],
    )
    assert hierarchy_rules.evaluate(snapshot) == []
