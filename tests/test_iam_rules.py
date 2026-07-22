"""Unit tests for iam_rules — these construct IamPolicySnapshot objects by
hand, they never call the real Resource Manager API. See tests/README.md."""

from gcp_live_compliance.collectors.iam import IamBinding, IamPolicySnapshot
from gcp_live_compliance.models import Severity
from gcp_live_compliance.rules import iam_rules


def test_flags_public_binding():
    snapshot = IamPolicySnapshot(
        project_id="demo-project",
        bindings=[IamBinding(role="roles/viewer", members=["allUsers"])],
    )
    findings = iam_rules.evaluate(snapshot)
    assert any(f.rule_id == "IAM_PUBLIC_BINDING" for f in findings)
    assert findings[0].severity == Severity.CRITICAL


def test_flags_primitive_role_on_user():
    snapshot = IamPolicySnapshot(
        project_id="demo-project",
        bindings=[IamBinding(role="roles/owner", members=["user:dev@example.com"])],
    )
    findings = iam_rules.evaluate(snapshot)
    assert any(f.rule_id == "IAM_PRIMITIVE_ROLE" for f in findings)


def test_primitive_role_on_service_account_only_not_flagged():
    snapshot = IamPolicySnapshot(
        project_id="demo-project",
        bindings=[
            IamBinding(
                role="roles/editor",
                members=["serviceAccount:ci@demo-project.iam.gserviceaccount.com"],
            )
        ],
    )
    findings = iam_rules.evaluate(snapshot)
    assert not any(f.rule_id == "IAM_PRIMITIVE_ROLE" for f in findings)


def test_clean_policy_produces_no_findings():
    snapshot = IamPolicySnapshot(
        project_id="demo-project",
        bindings=[IamBinding(role="roles/logging.viewer", members=["group:sre@example.com"])],
    )
    assert iam_rules.evaluate(snapshot) == []
