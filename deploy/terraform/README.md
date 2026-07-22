# Deploying the automated nightly scan

This turns the manual `gcp-live-compliance scan` command into a Cloud
Scheduler → Cloud Run Job that runs on its own, with Slack alerts on
CRITICAL/HIGH findings.

**Not yet run against live GCP** — same caveat as the rest of this repo.
The Terraform here was written against the current `google` provider's
documented resource schemas but couldn't be `terraform validate`'d or
`plan`'d from the sandbox this was built in. Walk through it once
carefully before `apply`, and expect to fix small things (a provider
version pin, an IAM role name) on the first real run.

## 1. Build and push the image

```bash
cd gcp-live-compliance-agent
gcloud auth configure-docker us-central1-docker.pkg.dev

# First apply creates the Artifact Registry repo — you need it to exist
# before you can push, so do a first, image-less apply, or create the
# repo by hand first:
gcloud artifacts repositories create compliance-agent \
  --repository-format=docker --location=us-central1

docker build -t us-central1-docker.pkg.dev/YOUR_PROJECT_ID/compliance-agent/scanner:latest .
docker push us-central1-docker.pkg.dev/YOUR_PROJECT_ID/compliance-agent/scanner:latest
```

## 2. Get a Slack webhook URL (optional)

Slack → your workspace → Apps → search "Incoming Webhooks" → add to the
channel you want alerts in → copy the URL
(`https://hooks.slack.com/services/...`). Leave `slack_webhook_url` unset
in the next step to skip Slack entirely.

## 3. Deploy

```bash
cd deploy/terraform
terraform init
terraform apply \
  -var="project_id=YOUR_PROJECT_ID" \
  -var="image=us-central1-docker.pkg.dev/YOUR_PROJECT_ID/compliance-agent/scanner:latest" \
  -var="slack_webhook_url=https://hooks.slack.com/services/..."
```

This creates:
- A dedicated `compliance-agent-scanner` service account (Viewer +
  Vertex AI User on the scanned project) — no key file, attached directly
  to the job.
- The Cloud Run Job itself.
- A separate `compliance-agent-invoker` service account whose only
  permission is triggering that specific job — Cloud Scheduler uses this,
  not the scanner's own identity.
- The nightly Cloud Scheduler trigger (`0 2 * * *` UTC by default — change
  via `-var="schedule_cron=..."`).
- If a Slack URL was given: a Secret Manager secret holding it, readable
  only by the scanner service account.

## 4. Test it without waiting for 2am

```bash
gcloud run jobs execute compliance-agent-scan --region=us-central1
```

Then check Cloud Run → Jobs → compliance-agent-scan → Logs, and your Slack
channel if you configured one.

## Changing what runs

The container's default args (`--explain --notify-slack --fail-on
CRITICAL`) live in the `Dockerfile`'s `CMD`. To run `--rules-only` instead
(no AI cost, deterministic) without rebuilding the image, override at
execute time:

```bash
gcloud run jobs execute compliance-agent-scan --region=us-central1 \
  --args="--rules-only,--notify-slack,--fail-on,CRITICAL"
```

## Cost note

Cloud Scheduler + Cloud Run Jobs are both effectively free at this volume
(one run a night). The real cost is the Gemini call in the default
detection mode — small per-run, but not zero. `--rules-only` removes it
entirely if you want a free baseline while iterating.

## Cleanup

```bash
terraform destroy -var="project_id=YOUR_PROJECT_ID" -var="image=..."
```

This does not delete the Artifact Registry repo's images or the Secret
Manager secret's old versions — check the GCP Console if you want those
gone too.
