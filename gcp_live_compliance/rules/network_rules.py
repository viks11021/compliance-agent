"""Compliance rules evaluated against live VPC firewall rules."""

from __future__ import annotations

from ..collectors.network import FirewallRuleSnapshot
from ..models import Finding, Severity

PUBLIC_RANGE = "0.0.0.0/0"

# port -> friendly name, for clearer messages
SENSITIVE_PORTS = {
    "22": "SSH",
    "3389": "RDP",
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "1433": "MSSQL",
    "6379": "Redis",
    "27017": "MongoDB",
    "9200": "Elasticsearch",
}


def _ports_from_range(port_range: str) -> set[str]:
    """'20-25' -> {'20','21','22','23','24','25'}; '22' -> {'22'}."""
    if "-" not in port_range:
        return {port_range}
    start, end = port_range.split("-", 1)
    try:
        return {str(p) for p in range(int(start), int(end) + 1)}
    except ValueError:
        return {port_range}


def evaluate(rules: list[FirewallRuleSnapshot]) -> list[Finding]:
    findings: list[Finding] = []

    for rule in rules:
        if rule.disabled or rule.direction != "INGRESS":
            continue
        if PUBLIC_RANGE not in rule.source_ranges:
            continue

        for allowed in rule.allowed:
            protocol = str(allowed.get("protocol", "")).lower()
            ports = allowed.get("ports") or []

            if protocol == "all" or not ports:
                findings.append(
                    Finding(
                        rule_id="FW_ALLOW_ALL_PUBLIC",
                        severity=Severity.CRITICAL,
                        resource_type="firewall_rule",
                        resource_name=rule.name,
                        message=(
                            f"Firewall rule '{rule.name}' allows ALL traffic on protocol "
                            f"'{protocol or 'all'}' from {PUBLIC_RANGE} (the entire internet)."
                        ),
                        recommendation=(
                            "Restrict source_ranges to known IP ranges (e.g. your office/VPN "
                            "CIDR or a bastion host) and scope allowed ports explicitly."
                        ),
                        raw={"rule": rule.name, "allowed": allowed},
                    )
                )
                continue

            matched_ports = set()
            for port_range in ports:
                matched_ports |= _ports_from_range(port_range) & SENSITIVE_PORTS.keys()

            for port in sorted(matched_ports, key=int):
                findings.append(
                    Finding(
                        rule_id="FW_SENSITIVE_PORT_PUBLIC",
                        severity=Severity.CRITICAL,
                        resource_type="firewall_rule",
                        resource_name=rule.name,
                        message=(
                            f"Firewall rule '{rule.name}' exposes {SENSITIVE_PORTS[port]} "
                            f"(port {port}/{protocol}) to {PUBLIC_RANGE} (the entire internet)."
                        ),
                        recommendation=(
                            f"Restrict this rule's source_ranges so port {port} is reachable "
                            "only from a bastion, VPN range, or IAP-tunnelled access."
                        ),
                        raw={"rule": rule.name, "allowed": allowed, "port": port},
                    )
                )

    return findings
