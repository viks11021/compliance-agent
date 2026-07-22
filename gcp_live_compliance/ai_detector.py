"""AI-driven compliance detection.

This sends the raw, live IAM policy and firewall configuration directly to
Gemini via Vertex AI and asks the model to identify compliance issues
itself — the model makes the actual judgment call, rather than
summarising judgments a fixed rule set already made. This is what
`gcp-live-compliance scan` uses by default.

See rules/iam_rules.py and rules/network_rules.py for the deterministic
alternative, available via `--rules-only`.

Trade-off, stated plainly, because it matters for how you describe this in
an interview:
  - Deterministic rules (--rules-only): same input always produces the same
    output, every time, and can be unit-tested exhaustively with zero API
    cost. But they only catch patterns someone explicitly coded a check
    for.
  - AI detection (this module, the default): can reason about context and
    combinations a fixed rule list doesn't cover. But it is
    non-deterministic — the same input can produce a different finding set
    on a different run — it can hallucinate a finding that isn't real, and
    it can just as easily miss something a two-line rule would catch every
    time. It also costs a Vertex AI API call per scan.

Treat --rules-only as the guaranteed floor and this mode as a second,
more contextual opinion — not the other way around. Saying that
distinction out loud is a stronger interview answer than either "it's all
AI" or "it's not really AI, it just summarises."
"""

from __future__ import annotations

import json
import re

from .collectors.iam import IamPolicySnapshot
from .collectors.network import FirewallRuleSnapshot
from .models import Finding, Severity

DEFAULT_LOCATION = "us-central1"
# Check https://cloud.google.com/vertex-ai/generative-ai/docs/models before
# relying on this — Gemini model names/versions are updated by Google
# independently of this project, and this couldn't be confirmed live from
# the sandbox this was written in.
DEFAULT_MODEL = "gemini-2.0-flash-001"

_JSON_SCHEMA_INSTRUCTIONS = """Respond with ONLY a JSON array (no prose, no markdown code fences). Each element must be an object with exactly these keys:
  "rule_id": a short UPPER_SNAKE_CASE identifier you choose, e.g. "IAM_PUBLIC_BINDING"
  "severity": one of "CRITICAL", "HIGH", "MEDIUM", "LOW"
  "resource_type": "iam_policy" or "firewall_rule"
  "resource_name": the specific role, member, or firewall rule name this finding is about
  "message": one sentence describing the issue in plain English
  "recommendation": one sentence describing the fix
If you find nothing wrong, respond with an empty JSON array: []
"""


def build_prompt(
    iam_snapshot: IamPolicySnapshot, firewall_rules: list[FirewallRuleSnapshot]
) -> str:
    """Build the prompt that hands Gemini the raw live data and asks it to
    do the actual compliance analysis. Pure function — no API calls, fully
    unit-testable."""
    iam_payload = [{"role": b.role, "members": b.members} for b in iam_snapshot.bindings]
    fw_payload = [
        {
            "name": r.name,
            "direction": r.direction,
            "disabled": r.disabled,
            "source_ranges": r.source_ranges,
            "target_tags": r.target_tags,
            "allowed": r.allowed,
        }
        for r in firewall_rules
    ]

    return (
        "You are a GCP cloud security compliance reviewer. Analyse the live IAM "
        f"policy and VPC firewall configuration below for project "
        f"'{iam_snapshot.project_id}' and identify genuine compliance/security "
        "issues yourself — for example (but not limited to) public IAM bindings "
        "(allUsers/allAuthenticatedUsers), overly broad primitive roles "
        "(Owner/Editor) bound to real users rather than service accounts, and "
        "firewall rules exposing sensitive ports or all traffic to 0.0.0.0/0. "
        "Only report on resources that actually appear in the data below — do "
        "not invent resource names.\n\n"
        f"IAM_POLICY_BINDINGS:\n{json.dumps(iam_payload, indent=2)}\n\n"
        f"FIREWALL_RULES:\n{json.dumps(fw_payload, indent=2)}\n\n"
        f"{_JSON_SCHEMA_INSTRUCTIONS}"
    )


def parse_response(raw_text: str) -> list[Finding]:
    """Parse Gemini's JSON response into Finding objects. Tolerates a
    markdown code fence in case the model adds one despite being told not
    to — real models don't always follow formatting instructions exactly.
    Pure function — no API calls, fully unit-testable."""
    text = raw_text.strip()
    fence_match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1)

    try:
        items = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Gemini's response wasn't valid JSON. Raw response started with: "
            f"{raw_text[:300]!r}"
        ) from exc

    findings = []
    for item in items:
        severity_raw = str(item.get("severity", "MEDIUM")).upper()
        try:
            severity = Severity(severity_raw)
        except ValueError:
            severity = Severity.MEDIUM

        findings.append(
            Finding(
                rule_id=item.get("rule_id", "AI_DETECTED"),
                severity=severity,
                resource_type=item.get("resource_type", "unknown"),
                resource_name=item.get("resource_name", "unknown"),
                message=item.get("message", ""),
                recommendation=item.get("recommendation", ""),
                raw=item,
                source="ai",
            )
        )
    return findings


def detect(
    iam_snapshot: IamPolicySnapshot,
    firewall_rules: list[FirewallRuleSnapshot],
    project_id: str,
    location: str = DEFAULT_LOCATION,
    model_name: str = DEFAULT_MODEL,
) -> list[Finding]:
    """Calls Gemini via Vertex AI to identify compliance findings directly
    from the live data — the model does the actual judgment call here, not
    just the write-up. Requires the same setup as vertex_explainer.explain()
    (Vertex AI API enabled, ADC configured, aiplatform access) — and, like
    that function, has not been exercised against a live project from the
    sandbox this was written in. Run scripts/live_smoke_test.py to confirm."""
    import vertexai
    from vertexai.generative_models import GenerativeModel

    vertexai.init(project=project_id, location=location)
    model = GenerativeModel(model_name)

    prompt = build_prompt(iam_snapshot, firewall_rules)
    response = model.generate_content(prompt)
    return parse_response(response.text)
