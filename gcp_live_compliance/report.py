from __future__ import annotations

import json

from .models import Severity
from .scanner import ScanResult

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


def to_console(result: ScanResult) -> str:
    lines = [f"GCP Live Compliance Scan — project: {result.project_id}", ""]

    if not result.findings:
        lines.append("No issues found. ✅")
    else:
        source = result.findings[0].source
        source_label = "Gemini (AI-detected)" if source == "ai" else "deterministic rule engine"
        lines.append(f"Detection: {source_label}")

        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in result.findings:
            counts[f.severity] += 1
        summary = "  ".join(f"{s.value}: {counts[s]}" for s in SEVERITY_ORDER if counts[s])
        lines.append(summary)
        lines.append("")

        for severity in SEVERITY_ORDER:
            group = [f for f in result.findings if f.severity == severity]
            if not group:
                continue
            lines.append(f"[{severity.value}]")
            for f in group:
                lines.append(f"  - ({f.rule_id}) {f.resource_type} '{f.resource_name}'")
                lines.append(f"    {f.message}")
                lines.append(f"    → {f.recommendation}")
            lines.append("")

    if result.explanation:
        lines.append("--- Gemini summary (Vertex AI) ---")
        lines.append(result.explanation.strip())

    return "\n".join(lines)


def to_json(result: ScanResult) -> str:
    payload = {
        "project_id": result.project_id,
        "findings": [f.to_dict() for f in result.findings],
        "explanation": result.explanation,
    }
    return json.dumps(payload, indent=2)


def to_markdown(result: ScanResult) -> str:
    lines = [f"# GCP Live Compliance Scan — `{result.project_id}`", ""]

    if not result.findings:
        lines.append("No issues found across IAM and firewall checks. ✅")
    else:
        lines.append("| Severity | Rule | Resource | Message |")
        lines.append("|---|---|---|---|")
        for f in result.findings:
            lines.append(
                f"| {f.severity.value} | {f.rule_id} | `{f.resource_name}` | {f.message} |"
            )

    if result.explanation:
        lines.append("")
        lines.append("## Gemini summary (Vertex AI)")
        lines.append(result.explanation.strip())

    return "\n".join(lines)


FORMATTERS = {"console": to_console, "json": to_json, "markdown": to_markdown}


def render(result: ScanResult, fmt: str = "console") -> str:
    try:
        formatter = FORMATTERS[fmt]
    except KeyError:
        raise ValueError(f"Unknown format '{fmt}'. Choose from: {list(FORMATTERS)}")
    return formatter(result)


def highest_severity(result: ScanResult) -> Severity | None:
    for severity in SEVERITY_ORDER:
        if any(f.severity == severity for f in result.findings):
            return severity
    return None
