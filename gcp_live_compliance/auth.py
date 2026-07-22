"""Application Default Credentials (ADC) helper.

This project deliberately uses ADC + real GCP client libraries, the same
auth model production workloads use (service account attached to a VM/GKE
node/Cloud Run service, or `gcloud auth application-default login` for local
dev) rather than a hand-rolled API-key flow. If ADC isn't configured, every
collector call below fails loudly with Google's own DefaultCredentialsError
instead of silently returning empty/fake data.
"""

from __future__ import annotations

import os


class ConfigError(RuntimeError):
    pass


def resolve_project_id(explicit_project: str | None) -> str:
    """Resolve the target GCP project ID, in priority order:
    1. --project flag passed on the CLI
    2. GOOGLE_CLOUD_PROJECT env var
    3. The project baked into the active ADC (if any)
    """
    if explicit_project:
        return explicit_project

    env_project = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT")
    if env_project:
        return env_project

    try:
        import google.auth

        _, adc_project = google.auth.default()
        if adc_project:
            return adc_project
    except Exception:
        pass

    raise ConfigError(
        "No GCP project specified. Pass --project <id>, set GOOGLE_CLOUD_PROJECT, "
        "or run `gcloud config set project <id>` before `gcloud auth application-default login`."
    )


def check_adc_available() -> None:
    """Raise a clear, actionable error if ADC isn't configured at all."""
    import google.auth
    from google.auth.exceptions import DefaultCredentialsError

    try:
        google.auth.default()
    except DefaultCredentialsError as exc:
        raise ConfigError(
            "Application Default Credentials not found. Run:\n"
            "  gcloud auth application-default login\n"
            "or set GOOGLE_APPLICATION_CREDENTIALS to a service account key file."
        ) from exc
