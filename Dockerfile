# Minimal image for running gcp-live-compliance as a Cloud Run Job.
# Not tested against a live `docker build`/`docker run` from the sandbox
# this was written in (no registry.terraform.io / docker.io network path
# there either) — build and run this once yourself before trusting it,
# same as everything else flagged in the top-level README.

FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY gcp_live_compliance ./gcp_live_compliance

RUN pip install --no-cache-dir ".[ai]"

# Cloud Run Jobs pass no HTTP request — this just runs to completion.
# Defaults below: AI-detect mode (default), add a narrative summary, notify
# Slack, fail the job (non-zero exit -> visible in Cloud Run Job history)
# on CRITICAL findings. Override any of this via the Cloud Run Job's
# `--args` at deploy time or per-execution override.
ENTRYPOINT ["gcp-live-compliance", "scan"]
CMD ["--explain", "--notify-slack", "--fail-on", "CRITICAL"]
