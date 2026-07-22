"""Tests build_prompt() and parse_response() only — both pure functions.
The actual `detect()` call hits real Vertex AI and is deliberately NOT unit
tested here; see tests/README.md for why, and scripts/live_smoke_test.py
for how to check it against a real project."""

import pytest

from gcp_live_compliance.ai_detector import build_prompt, parse_response
from gcp_live_compliance.collectors.hierarchy import AncestorPolicy, HierarchySnapshot
from gcp_live_compliance.collectors.iam import IamBinding, IamPolicySnapshot
from gcp_live_compliance.collectors.network import FirewallRuleSnapshot
from gcp_live_compliance.collectors.storage import BucketSnapshot
from gcp_live_compliance.models import Severity


def test_build_prompt_includes_project_and_data():
    iam_snapshot = IamPolicySnapshot(
        project_id="demo-project",
        bindings=[IamBinding(role="roles/owner", members=["user:dev@example.com"])],
    )
    fw_rules = [
        FirewallRuleSnapshot(
            name="fw-allow-ssh", network="default", direction="INGRESS",
            disabled=False, source_ranges=["0.0.0.0/0"], target_tags=[],
            allowed=[{"protocol": "tcp", "ports": ["22"]}],
        )
    ]
    prompt = build_prompt(iam_snapshot, fw_rules)
    assert "demo-project" in prompt
    assert "roles/owner" in prompt
    assert "fw-allow-ssh" in prompt
    assert "JSON array" in prompt


def test_build_prompt_includes_bucket_data_when_provided():
    iam_snapshot = IamPolicySnapshot(project_id="demo-project", bindings=[])
    bucket = BucketSnapshot(
        name="my-public-bucket",
        bindings=[{"role": "roles/storage.objectViewer", "members": ["allUsers"]}],
        public_access_prevention=None,
    )
    prompt = build_prompt(iam_snapshot, [], buckets=[bucket])
    assert "my-public-bucket" in prompt
    assert "STORAGE_BUCKETS" in prompt


def test_build_prompt_omits_bucket_section_when_not_provided():
    iam_snapshot = IamPolicySnapshot(project_id="demo-project", bindings=[])
    prompt = build_prompt(iam_snapshot, [])
    assert "STORAGE_BUCKETS" not in prompt


def test_build_prompt_includes_hierarchy_data_when_provided():
    iam_snapshot = IamPolicySnapshot(project_id="demo-project", bindings=[])
    hierarchy = HierarchySnapshot(
        project_id="demo-project",
        has_organization=True,
        ancestors=[
            AncestorPolicy(
                resource_name="organizations/123",
                resource_type="organization",
                bindings=[{"role": "roles/owner", "members": ["allUsers"]}],
            )
        ],
    )
    prompt = build_prompt(iam_snapshot, [], hierarchy=hierarchy)
    assert "organizations/123" in prompt
    assert "INHERITED_HIERARCHY_POLICIES" in prompt


def test_build_prompt_omits_hierarchy_section_when_no_ancestors():
    iam_snapshot = IamPolicySnapshot(project_id="demo-project", bindings=[])
    hierarchy = HierarchySnapshot(project_id="demo-project", has_organization=False, ancestors=[])
    prompt = build_prompt(iam_snapshot, [], hierarchy=hierarchy)
    assert "INHERITED_HIERARCHY_POLICIES" not in prompt


def test_parse_response_valid_json():
    raw = """[
        {"rule_id": "IAM_PUBLIC_BINDING", "severity": "CRITICAL",
         "resource_type": "iam_policy", "resource_name": "roles/viewer",
         "message": "allUsers has viewer access", "recommendation": "Remove allUsers"}
    ]"""
    findings = parse_response(raw)
    assert len(findings) == 1
    assert findings[0].rule_id == "IAM_PUBLIC_BINDING"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].source == "ai"


def test_parse_response_strips_markdown_fence():
    raw = '```json\n[{"rule_id": "X", "severity": "LOW", "resource_type": "iam_policy", "resource_name": "r", "message": "m", "recommendation": "rec"}]\n```'
    findings = parse_response(raw)
    assert len(findings) == 1
    assert findings[0].rule_id == "X"


def test_parse_response_empty_array():
    assert parse_response("[]") == []


def test_parse_response_unknown_severity_defaults_medium():
    raw = '[{"rule_id": "X", "severity": "YOLO", "resource_type": "t", "resource_name": "r", "message": "m", "recommendation": "rec"}]'
    findings = parse_response(raw)
    assert findings[0].severity == Severity.MEDIUM


def test_parse_response_invalid_json_raises():
    with pytest.raises(ValueError):
        parse_response("this is not json at all")
