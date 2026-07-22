from __future__ import annotations

from dataclasses import dataclass, field

from .auth import check_adc_available, resolve_project_id
from .collectors.iam import fetch_project_iam_policy
from .collectors.network import fetch_firewall_rules
from .models import Finding
from .rules import iam_rules, network_rules


@dataclass
class ScanResult:
    project_id: str
    findings: list[Finding] = field(default_factory=list)
    explanation: str | None = None


def run_scan(
    project: str | None = None,
    explain: bool = False,
    location: str = "us-central1",
) -> ScanResult:
    """Run a full live scan: resolve project -> verify ADC -> collect ->
    evaluate rules -> (optionally) explain via Vertex AI."""
    check_adc_available()
    project_id = resolve_project_id(project)

    findings: list[Finding] = []

    iam_snapshot = fetch_project_iam_policy(project_id)
    findings.extend(iam_rules.evaluate(iam_snapshot))

    firewall_rules = fetch_firewall_rules(project_id)
    findings.extend(network_rules.evaluate(firewall_rules))

    result = ScanResult(project_id=project_id, findings=findings)

    if explain:
        from .vertex_explainer import explain as vertex_explain

        result.explanation = vertex_explain(findings, project_id, location=location)

    return result
