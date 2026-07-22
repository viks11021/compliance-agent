from __future__ import annotations

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
@click.option("--explain", is_flag=True, default=False, help="Send findings to Gemini (Vertex AI) for a plain-English summary.")
@click.option("--location", default="us-central1", show_default=True, help="Vertex AI region for --explain.")
@click.option("--format", "fmt", type=click.Choice(["console", "json", "markdown"]), default="console", show_default=True)
@click.option("--output", type=click.Path(dir_okay=False, writable=True), default=None, help="Write report to a file instead of stdout.")
@click.option("--fail-on", type=click.Choice([s.value for s in SEVERITY_ORDER]), default=None,
              help="Exit non-zero if a finding at or above this severity is present (for CI).")
def scan(project, explain, location, fmt, output, fail_on):
    """Run a live scan against a real GCP project."""
    try:
        result = run_scan(project=project, explain=explain, location=location)
    except ConfigError as exc:
        click.echo(f"Config error: {exc}", err=True)
        sys.exit(2)
    except Exception as exc:  # surfaces real Google API errors (permissions, disabled API, etc.)
        click.echo(f"Scan failed: {exc}", err=True)
        sys.exit(1)

    rendered = render(result, fmt)
    if output:
        with open(output, "w") as fh:
            fh.write(rendered + "\n")
    else:
        click.echo(rendered)

    if fail_on:
        threshold = Severity(fail_on)
        worst = highest_severity(result)
        if worst is not None and SEVERITY_ORDER.index(worst) <= SEVERITY_ORDER.index(threshold):
            sys.exit(1)


if __name__ == "__main__":
    main()
