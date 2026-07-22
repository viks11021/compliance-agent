"""Posts a scan result to Slack via an incoming webhook.

This is intentionally the *only* place in the codebase that makes an
outbound network call to something other than Google's own APIs — kept
small and isolated so it's easy to swap for Jira/ServiceNow/PagerDuty/email
without touching the scanner or detectors.
"""

from __future__ import annotations

NOTIFY_SEVERITIES = {"CRITICAL", "HIGH"}


def build_slack_payload(project_id: str, findings: list, explanation: str | None = None) -> dict:
    """Build the Slack Block Kit payload. Pure function — no network call —
    so this is fully unit-testable without a real webhook."""
    notable = [f for f in findings if f.severity.value in NOTIFY_SEVERITIES]

    if not notable:
        text = f":white_check_mark: GCP compliance scan of `{project_id}`: no CRITICAL/HIGH findings."
        return {"text": text}

    header = (
        f":rotating_light: GCP compliance scan of `{project_id}` found "
        f"{len(notable)} CRITICAL/HIGH issue(s)"
    )
    lines = [header, ""]
    for f in notable[:10]:  # cap to keep the message readable; full detail lives in --format json
        lines.append(f"*[{f.severity.value}]* `{f.rule_id}` — {f.resource_name}")
        lines.append(f"  {f.message}")
        lines.append(f"  → {f.recommendation}")
    if len(notable) > 10:
        lines.append(f"...and {len(notable) - 10} more. See the full JSON report for details.")

    if explanation:
        lines.append("")
        lines.append("*Summary:*")
        lines.append(explanation.strip())

    return {"text": "\n".join(lines)}


def send(webhook_url: str, project_id: str, findings: list, explanation: str | None = None) -> None:
    """POST the payload to a Slack incoming webhook.

    Not unit tested beyond build_slack_payload() — this makes a real HTTP
    call and hasn't been exercised against a live webhook from the sandbox
    this was written in (no network path there). Test with a real webhook
    URL before relying on it: https://api.slack.com/messaging/webhooks
    """
    import json
    import urllib.request

    payload = build_slack_payload(project_id, findings, explanation)
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status >= 300:
            raise RuntimeError(f"Slack webhook returned HTTP {resp.status}")
