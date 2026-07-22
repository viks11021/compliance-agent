"""Sends findings to Gemini for a plain-English risk summary and
remediation plan.

Uses the **google-genai** SDK (`from google import genai`), Google's
current unified client for Gemini — targeted at Vertex AI here via
`genai.Client(vertexai=True, ...)`, which keeps the same auth/access
model this project relies on:

    Vertex AI mode (vertexai=True)             Gemini Developer API mode
    ------------------------------------------ -----------------------
    Auth: GCP project + ADC                    Auth: API key
    Access: IAM-controlled, audit-logged        Access: key-based only
    Fit: production GCP workloads               Fit: prototyping

This project previously used `vertexai.generative_models.GenerativeModel`
(the older `google-cloud-aiplatform` SDK surface). That module was
deprecated by Google on June 24, 2025 and its removal date, June 24, 2026,
has now passed — see
https://cloud.google.com/vertex-ai/generative-ai/docs/deprecations/genai-vertexai-sdk
This file was migrated to `google-genai` accordingly; if you're reading
this in an interview and want to explain the change, that's the real
reason, not a style preference.

IMPORTANT: this call has not been exercised against a live GCP project
from the environment this file was written in (no network path to
*.googleapis.com available there). The request shape matches Google's
current documented SDK usage as of this writing, but Gemini model names
are retired on their own schedule independent of this project — confirm
the model name below is still live (check
https://cloud.google.com/vertex-ai/generative-ai/docs/learn/models) and
run this once against your own project before using it in a demo or
interview.
"""

from __future__ import annotations

from .models import Finding

DEFAULT_LOCATION = "us-central1"
# gemini-2.5-flash has been GA since June 2025 and is the stable default
# here. Newer families (gemini-3.x) exist and move fast — check the models
# page above before assuming this is still current.
DEFAULT_MODEL = "gemini-2.5-flash"


def build_prompt(findings: list[Finding], project_id: str) -> str:
    if not findings:
        return (
            f"A GCP compliance scan of project '{project_id}' found zero issues "
            "across IAM and firewall rules. Write one short congratulatory "
            "sentence confirming this, and one sentence reminding the reader "
            "that a clean scan only covers what this tool checks today."
        )

    lines = [
        f"You are a cloud security reviewer. A compliance scan of GCP project "
        f"'{project_id}' found {len(findings)} issue(s) listed below. For each, "
        "the tool already assigned a severity and a recommendation. Your job is "
        "to add a short, plain-English executive summary (max 150 words) "
        "prioritising what to fix first and why, for someone who is not a "
        "security specialist. Do not invent findings beyond what's listed.",
        "",
        "FINDINGS:",
    ]
    for f in findings:
        lines.append(
            f"- [{f.severity.value}] ({f.rule_id}) {f.resource_type} "
            f"'{f.resource_name}': {f.message} Recommendation: {f.recommendation}"
        )
    return "\n".join(lines)


def explain(
    findings: list[Finding],
    project_id: str,
    location: str = DEFAULT_LOCATION,
    model_name: str = DEFAULT_MODEL,
) -> str:
    """Calls Gemini (via google-genai, targeting Vertex AI) and returns its
    plain-English summary.

    Requires:
      - `pip install -e ".[ai]"` (installs google-genai)
      - Application Default Credentials configured
      - The Vertex AI API enabled on `project_id`
      - `project_id` to have quota/access for the chosen model in `location`
    """
    from google import genai

    client = genai.Client(vertexai=True, project=project_id, location=location)

    prompt = build_prompt(findings, project_id)
    response = client.models.generate_content(model=model_name, contents=prompt)
    return response.text
