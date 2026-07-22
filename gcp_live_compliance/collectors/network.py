"""Fetches live VPC firewall rules for a GCP project via the Compute Engine API.

Uses google-cloud-compute's FirewallsClient.list — equivalent to
`gcloud compute firewall-rules list --project <id>` — so results reflect
what's actually enforced on the network right now.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FirewallRuleSnapshot:
    name: str
    network: str
    direction: str               # "INGRESS" | "EGRESS"
    disabled: bool
    source_ranges: list[str] = field(default_factory=list)
    target_tags: list[str] = field(default_factory=list)
    allowed: list[dict] = field(default_factory=list)   # [{"protocol": "tcp", "ports": ["22"]}, ...]


def fetch_firewall_rules(project_id: str) -> list[FirewallRuleSnapshot]:
    """Fetch all firewall rules configured on `project_id`'s VPC networks.

    Requires the caller's ADC identity to have
    `compute.firewalls.list` (included in Compute Viewer or above).
    """
    from google.cloud import compute_v1

    client = compute_v1.FirewallsClient()
    rules: list[FirewallRuleSnapshot] = []

    for fw in client.list(project=project_id):
        allowed = [
            {"protocol": _get_ip_protocol(a), "ports": list(a.ports)}
            for a in fw.allowed
        ]
        rules.append(
            FirewallRuleSnapshot(
                name=fw.name,
                network=fw.network,
                direction=fw.direction,
                disabled=fw.disabled,
                source_ranges=list(fw.source_ranges),
                target_tags=list(fw.target_tags),
                allowed=allowed,
            )
        )
    return rules


def _get_ip_protocol(allowed_obj) -> str:
    """The generated compute_v1.Allowed field name for IPProtocol has varied
    across google-cloud-compute versions (seen as both `I_p_protocol` and
    `ip_protocol` depending on the proto-plus code-gen pass). Try both rather
    than hard-failing on a library version mismatch — this couldn't be
    verified against a live install from the sandbox this was built in, so
    treat it as unconfirmed until you've run it once."""
    for attr in ("I_p_protocol", "ip_protocol", "IPProtocol"):
        if hasattr(allowed_obj, attr):
            return getattr(allowed_obj, attr)
    return "unknown"
