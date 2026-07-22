"""Tests build_prompt only — a pure string-building function. The actual
`explain()` call hits real Vertex AI and is deliberately NOT unit tested
here; see tests/README.md for why, and scripts/live_smoke_test.py for how
to check it against a real project."""

from gcp_live_compliance.models import Finding, Severity
from gcp_live_compliance.vertex_explainer import build_prompt


def test_prompt_mentions_project_and_findings():
    findings = [
        Finding(
            rule_id="FW_SENSITIVE_PORT_PUBLIC",
            severity=Severity.CRITICAL,
            resource_type="firewall_rule",
            resource_name="fw-allow-ssh",
            message="SSH exposed to the internet",
            recommendation="Restrict source range",
        )
    ]
    prompt = build_prompt(findings, "demo-project")
    assert "demo-project" in prompt
    assert "FW_SENSITIVE_PORT_PUBLIC" in prompt
    assert "SSH exposed to the internet" in prompt


def test_prompt_handles_zero_findings():
    prompt = build_prompt([], "demo-project")
    assert "demo-project" in prompt
    assert "zero issues" in prompt
