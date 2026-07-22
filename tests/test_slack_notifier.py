"""Tests build_slack_payload() only — a pure function. send() makes a real
HTTP call and is deliberately not unit tested here; see the module
docstring in notifiers/slack.py."""

from gcp_live_compliance.models import Finding, Severity
from gcp_live_compliance.notifiers.slack import build_slack_payload


def _finding(severity):
    return Finding(
        rule_id="TEST_RULE",
        severity=severity,
        resource_type="iam_policy",
        resource_name="roles/owner",
        message="test message",
        recommendation="test recommendation",
    )


def test_no_notable_findings_gives_ok_message():
    payload = build_slack_payload("demo-project", [_finding(Severity.LOW)])
    assert "no CRITICAL/HIGH" in payload["text"]


def test_critical_finding_included():
    payload = build_slack_payload("demo-project", [_finding(Severity.CRITICAL)])
    assert "CRITICAL" in payload["text"]
    assert "TEST_RULE" in payload["text"]


def test_low_and_medium_excluded_from_notable_count():
    findings = [_finding(Severity.LOW), _finding(Severity.MEDIUM), _finding(Severity.CRITICAL)]
    payload = build_slack_payload("demo-project", findings)
    assert "found 1 CRITICAL/HIGH" in payload["text"]


def test_explanation_included_when_present():
    payload = build_slack_payload("demo-project", [_finding(Severity.HIGH)], explanation="Fix this now.")
    assert "Fix this now." in payload["text"]


def test_caps_at_ten_with_overflow_note():
    findings = [_finding(Severity.CRITICAL) for _ in range(15)]
    payload = build_slack_payload("demo-project", findings)
    assert "and 5 more" in payload["text"]
