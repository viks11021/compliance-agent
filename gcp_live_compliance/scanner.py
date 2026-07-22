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
    rules_only: bool = False,
    explain: bool = False,
    location: str = "us-central1",
) -> ScanResult:
    """Run a full live scan: resolve project -> verify ADC -> collect ->
    detect -> (optionally) add a narrative summary via Vertex AI.

    Detection mode:
      - Default (rules_only=False): the raw IAM/firewall data is sent to
        Gemini via Vertex AI, which identifies the findings itself
        (see ai_detector.py). Requires Vertex AI access.
      - rules_only=True: findings come from the deterministic rule engine
        in rules/ instead — no AI call, no Vertex AI access needed. Useful
        for CI, or anywhere you want a guaranteed-consistent baseline.

    `explain` adds one further Vertex AI call that writes a short narrative
    executive summary on top of whichever findings were produced by either
    mode above.
    """
    check_adc_available()
    project_id = resolve_project_id(project)

    iam_snapshot = fetch_project_iam_policy(project_id)
    firewall_rules = fetch_firewall_rules(project_id)

    if rules_only:
        findings: list[Finding] = []
        findings.extend(iam_rules.evaluate(iam_snapshot))
        findings.extend(network_rules.evaluate(firewall_rules))
    else:
        from .ai_detector import detect as ai_detect

        findings = ai_detect(iam_snapshot, firewall_rules, project_id, location=location)

    result = ScanResult(project_id=project_id, findings=findings)

    if explain:
        from .vertex_explainer import explain as vertex_explain

        result.explanation = vertex_explain(findings, project_id, location=location)

    return result
