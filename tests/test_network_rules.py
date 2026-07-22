"""Unit tests for network_rules — hand-built FirewallRuleSnapshot objects,
no live Compute Engine calls."""

from gcp_live_compliance.collectors.network import FirewallRuleSnapshot
from gcp_live_compliance.rules import network_rules


def _rule(**overrides):
    defaults = dict(
        name="test-rule",
        network="default",
        direction="INGRESS",
        disabled=False,
        source_ranges=["0.0.0.0/0"],
        target_tags=[],
        allowed=[{"protocol": "tcp", "ports": ["22"]}],
    )
    defaults.update(overrides)
    return FirewallRuleSnapshot(**defaults)


def test_flags_public_ssh():
    findings = network_rules.evaluate([_rule()])
    assert any(f.rule_id == "FW_SENSITIVE_PORT_PUBLIC" for f in findings)


def test_flags_allow_all_protocol():
    findings = network_rules.evaluate([_rule(allowed=[{"protocol": "all", "ports": []}])])
    assert any(f.rule_id == "FW_ALLOW_ALL_PUBLIC" for f in findings)


def test_ignores_disabled_rule():
    findings = network_rules.evaluate([_rule(disabled=True)])
    assert findings == []


def test_ignores_egress_rule():
    findings = network_rules.evaluate([_rule(direction="EGRESS")])
    assert findings == []


def test_ignores_restricted_source_range():
    findings = network_rules.evaluate([_rule(source_ranges=["10.0.0.0/8"])])
    assert findings == []


def test_port_range_expansion_catches_sensitive_port():
    findings = network_rules.evaluate([_rule(allowed=[{"protocol": "tcp", "ports": ["20-25"]}])])
    assert any(f.rule_id == "FW_SENSITIVE_PORT_PUBLIC" and "22" in f.message for f in findings)


def test_non_sensitive_port_not_flagged():
    findings = network_rules.evaluate([_rule(allowed=[{"protocol": "tcp", "ports": ["8080"]}])])
    assert findings == []
