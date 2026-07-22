"""Tests build_prompt() and parse_response() only — both pure functions.
The actual `detect()` call hits real Vertex AI and is deliberately NOT unit
tested here; see tests/README.md for why, and scripts/live_smoke_test.py
for how to check it against a real project."""

import pytest

from gcp_live_compliance.ai_detector import build_prompt, parse_response
from gcp_live_compliance.collectors.iam import IamBinding, IamPolicySnapshot
from gcp_live_compliance.collectors.network import FirewallRuleSnapshot
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
