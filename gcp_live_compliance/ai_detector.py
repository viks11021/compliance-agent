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

from .collectors.hierarchy import HierarchySnapshot
from .collectors.iam import IamPolicySnapshot
from .collectors.network import FirewallRuleSnapshot
from .collectors.storage import BucketSnapshot
from .models import Finding, Severity

DEFAULT_LOCATION = "us-central1"
# gemini-2.5-flash has been GA since June 2025 and is the stable default
# here. Newer families (gemini-3.x) exist and move fast — check
# https://cloud.google.com/vertex-ai/generative-ai/docs/learn/models before
# assuming this is still current; Gemini models are retired on their own
# schedule independent of this project (e.g. gemini-2.0-flash-001, this
# project's original default, was shut down June 1, 2026).
DEFAULT_MODEL = "gemini-2.5-flash"

_JSON_SCHEMA_INSTRUCTIONS = """Respond with ONLY a JSON array (no prose, no markdown code fences). Each element must be an object with exactly these keys:
  "rule_id": a short UPPER_SNAKE_CASE identifier you choose, e.g. "IAM_PUBLIC_BINDING"
  "severity": one of "CRITICAL", "HIGH", "MEDIUM", "LOW"
  "resource_type": "iam_policy", "firewall_rule", "storage_bucket", or "resource_hierarchy"
  "resource_name": the specific role, member, firewall rule, bucket, or folder/org name this finding is about
  "message": one sentence describing the issue in plain English
  "recommendation": one sentence describing the fix
If you find nothing wrong, respond with an empty JSON array: []
"""


def build_prompt(
    iam_snapshot: IamPolicySnapshot,
    firewall_rules: list[FirewallRuleSnapshot],
    buckets: list[BucketSnapshot] | None = None,
    hierarchy: HierarchySnapshot | None = None,
) -> str:
    """Build the prompt that hands Gemini the raw live data and asks it to
    do the actual compliance analysis. Pure function — no API calls, fully
    unit-testable. `buckets` and `hierarchy` are optional so existing
    callers (and existing tests) that only pass IAM/firewall data keep
    working unchanged."""
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

    sections = [
        "You are a GCP cloud security compliance reviewer. Analyse the live "
        f"resource data below for project '{iam_snapshot.project_id}' and "
        "identify genuine compliance/security issues yourself — for example "
        "(but not limited to) public IAM bindings (allUsers/"
        "allAuthenticatedUsers), overly broad primitive roles (Owner/Editor) "
        "bound to real users rather than service accounts, firewall rules "
        "exposing sensitive ports or all traffic to 0.0.0.0/0, publicly "
        "accessible storage buckets, and IAM bindings inherited from a "
        "folder or organization that grant more than the project itself "
        "does. Only report on resources that actually appear in the data "
        "below — do not invent resource names.",
        "",
        f"IAM_POLICY_BINDINGS:\n{json.dumps(iam_payload, indent=2)}",
        "",
        f"FIREWALL_RULES:\n{json.dumps(fw_payload, indent=2)}",
    ]

    if buckets:
        bucket_payload = [
            {
                "name": b.name,
                "bindings": b.bindings,
                "public_access_prevention": b.public_access_prevention,
            }
            for b in buckets
        ]
        sections += ["", f"STORAGE_BUCKETS:\n{json.dumps(bucket_payload, indent=2)}"]

    if hierarchy and hierarchy.ancestors:
        hierarchy_payload = [
            {
                "resource_name": a.resource_name,
                "resource_type": a.resource_type,
                "bindings": a.bindings,
                "error": a.error,
            }
            for a in hierarchy.ancestors
        ]
        sections += [
            "",
            f"INHERITED_HIERARCHY_POLICIES (folder/org level; an 'error' field "
            f"means this scan could not read that level's policy — treat that "
            f"as a LOW-severity finding about limited visibility, not as a "
            f"clean bill of health):\n{json.dumps(hierarchy_payload, indent=2)}",
        ]

    sections += ["", _JSON_SCHEMA_INSTRUCTIONS]
    return "\n".join(sections)


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
    buckets: list[BucketSnapshot] | None = None,
    hierarchy: HierarchySnapshot | None = None,
    location: str = DEFAULT_LOCATION,
    model_name: str = DEFAULT_MODEL,
) -> list[Finding]:
    """Calls Gemini (via google-genai, targeting Vertex AI) to identify
    compliance findings directly from the live data — the model does the
    actual judgment call here, not just the write-up. Requires the same
    setup as vertex_explainer.explain() (Vertex AI API enabled, ADC
    configured, aiplatform access) — and, like that function, has not been
    exercised against a live project from the sandbox this was written in.
    Run scripts/live_smoke_test.py to confirm.

    Uses google-genai (`from google import genai`), not the older
    `vertexai.generative_models` SDK — that module was deprecated by
    Google on June 24, 2025 and removed June 24, 2026. See
    vertex_explainer.py's module docstring for details.
    """
    from google import genai

    client = genai.Client(vertexai=True, project=project_id, location=location)

    prompt = build_prompt(iam_snapshot, firewall_rules, buckets=buckets, hierarchy=hierarchy)
    response = client.models.generate_content(model=model_name, contents=prompt)
    return parse_response(response.text)
