from __future__ import annotations

import os
import sys

import click

from .auth import ConfigError
from .models import Severity
from .report import SEVERITY_ORDER, highest_severity, render
from .scanner import run_scan


@click.group()
@click.version_option()
def main():
    """gcp-live-compliance-agent — scan a live GCP project's IAM and firewall
    configuration, optionally explained by Gemini via Vertex AI."""


@main.command()
@click.option("--project", default=None, help="GCP project ID. Defaults to GOOGLE_CLOUD_PROJECT / ADC project.")
@click.option("--rules-only", is_flag=True, default=False,
              help="Use the deterministic rule engine instead of Gemini for detection (no Vertex AI call, no AI cost).")
@click.option("--explain", is_flag=True, default=False, help="Add a narrative executive summary via Gemini on top of the findings.")
@click.option("--location", default="us-central1", show_default=True, help="Vertex AI region.")
@click.option("--format", "fmt", type=click.Choice(["console", "json", "markdown"]), default="console", show_default=True)
@click.option("--output", type=click.Path(dir_okay=False, writable=True), default=None, help="Write report to a file instead of stdout.")
@click.option("--fail-on", type=click.Choice([s.value for s in SEVERITY_ORDER]), default=None,
              help="Exit non-zero if a finding at or above this severity is present (for CI).")
@click.option("--notify-slack", is_flag=True, default=False,
              help="Post CRITICAL/HIGH findings to Slack. Requires SLACK_WEBHOOK_URL env var (read from Secret Manager in the Cloud Run deployment — see deploy/).")
def scan(project, rules_only, explain, location, fmt, output, fail_on, notify_slack):
    """Run a live scan against a real GCP project.

    By default, Gemini (via Vertex AI) analyses the live IAM policy and
    firewall rules directly and identifies the findings itself — pass
    --rules-only to use the deterministic rule engine instead (no AI call).
    """
    try:
        result = run_scan(project=project, rules_only=rules_only, explain=explain, location=location)
    except ConfigError as exc:
        click.echo(f"Config error: {exc}", err=True)
        sys.exit(2)
    except Exception as exc:  # surfaces real Google/Vertex AI API errors (permissions, disabled API, etc.)
        click.echo(f"Scan failed: {exc}", err=True)
        sys.exit(1)

    rendered = render(result, fmt)
    if output:
        with open(output, "w") as fh:
            fh.write(rendered + "\n")
    else:
        click.echo(rendered)

    if notify_slack:
        webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
        if not webhook_url:
            click.echo("--notify-slack was set but SLACK_WEBHOOK_URL is not set; skipping notification.", err=True)
        else:
            from .notifiers import slack

            try:
                slack.send(webhook_url, result.project_id, result.findings, result.explanation)
            except Exception as exc:
                # Don't let a Slack outage fail the whole scan job — log and move on.
                click.echo(f"Slack notification failed: {exc}", err=True)

    if fail_on:
        threshold = Severity(fail_on)
        worst = highest_severity(result)
        if worst is not None and SEVERITY_ORDER.index(worst) <= SEVERITY_ORDER.index(threshold):
            sys.exit(1)


if __name__ == "__main__":
    main()
