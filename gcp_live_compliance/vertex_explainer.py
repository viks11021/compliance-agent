"""Sends findings to Gemini via the real Vertex AI SDK for a plain-English
risk summary and remediation plan.

This deliberately uses `google-cloud-aiplatform` (Vertex AI), not the
consumer Gemini API / API-key flow:

    Vertex AI                                  Gemini API (AI Studio)
    ------------------------------------------ -----------------------
    Auth: GCP project + ADC                    Auth: API key
    Access: IAM-controlled, audit-logged        Access: key-based only
    Fit: production GCP workloads               Fit: prototyping

That match to the production auth/permissions model is the point of using
Vertex AI here at all — see the top-level README for why.

IMPORTANT: this call has not been exercised against a live GCP project from
the environment this file was written in (no network path to
*.googleapis.com available there). The request shape matches Google's
documented SDK usage as of this writing, but model names and SDK surface
change — confirm the model name below is still current, and run this once
against your own project, before using `--explain` in a demo or interview.
"""

from __future__ import annotations

from .models import Finding

DEFAULT_LOCATION = "us-central1"
# Check https://cloud.google.com/vertex-ai/generative-ai/docs/models before
# relying on this — Gemini model names/versions are updated by Google
# independently of this project.
DEFAULT_MODEL = "gemini-2.0-flash-001"


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
    """Calls Gemini via Vertex AI and returns its plain-English summary.

    Requires:
      - `pip install -e ".[ai]"` (installs google-cloud-aiplatform)
      - Application Default Credentials configured
      - The Vertex AI API enabled on `project_id`
      - `project_id` to have quota/access for the chosen model in `location`
    """
    import vertexai
    from vertexai.generative_models import GenerativeModel

    vertexai.init(project=project_id, location=location)
    model = GenerativeModel(model_name)

    prompt = build_prompt(findings, project_id)
    response = model.generate_content(prompt)
    return response.text
