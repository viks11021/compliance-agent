from __future__ import annotations

from dataclasses import dataclass, field

from .auth import check_adc_available, resolve_project_id
from .collectors.hierarchy import fetch_resource_hierarchy
from .collectors.iam import fetch_project_iam_policy
from .collectors.network import fetch_firewall_rules
from .collectors.storage import fetch_bucket_iam_policies
from .models import Finding
from .rules import hierarchy_rules, iam_rules, network_rules, storage_rules


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

    Collects four resource types: project IAM policy, VPC firewall rules,
    Cloud Storage bucket IAM policies, and the folder/org ancestor chain's
    IAM policies (best-effort — see collectors/hierarchy.py for why that
    one is often permission-limited by design).

    Detection mode:
      - Default (rules_only=False): the raw collected data is sent to
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
    buckets = fetch_bucket_iam_policies(project_id)
    hierarchy = fetch_resource_hierarchy(project_id)

    if rules_only:
        findings: list[Finding] = []
        findings.extend(iam_rules.evaluate(iam_snapshot))
        findings.extend(network_rules.evaluate(firewall_rules))
        findings.extend(storage_rules.evaluate(buckets))
        findings.extend(hierarchy_rules.evaluate(hierarchy))
    else:
        from .ai_detector import detect as ai_detect

        findings = ai_detect(
            iam_snapshot, firewall_rules, project_id, buckets=buckets, hierarchy=hierarchy, location=location
        )

    result = ScanResult(project_id=project_id, findings=findings)

    if explain:
        from .vertex_explainer import explain as vertex_explain

        result.explanation = vertex_explain(findings, project_id, location=location)

    return result
