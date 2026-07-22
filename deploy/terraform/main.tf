# gcp-live-compliance-agent automation: Cloud Scheduler -> Cloud Run Job.
#
# NOT VALIDATED: `terraform validate` / `terraform plan` could not be run
# against this from the sandbox this was written in — no `terraform`
# binary and no network path to registry.terraform.io there. Written
# carefully against the current `google` provider's documented resource
# schemas, but run `terraform validate` yourself before `apply`. Same
# category of caveat as the Python API calls elsewhere in this repo — see
# the top-level README's "Known limitations".

locals {
  job_name = "compliance-agent-scan"
  # Secret Manager rejects a zero-length payload (a real error hit while
  # deploying this, not a hypothetical) — an unset webhook needs a
  # non-empty placeholder, not "". The CLI's --notify-slack will still
  # attempt to POST to this and fail gracefully (caught, logged, doesn't
  # fail the job) rather than silently skip, but that's a minor cosmetic
  # gap, not a functional one.
  slack_webhook_value = var.slack_webhook_url != "" ? var.slack_webhook_url : "not-configured"
}

# --- APIs ---------------------------------------------------------------

resource "google_project_service" "required" {
  for_each = toset([
    "run.googleapis.com",
    "cloudscheduler.googleapis.com",
    "secretmanager.googleapis.com",
    "aiplatform.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "compute.googleapis.com",
    "artifactregistry.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
  ])
  service            = each.value
  disable_on_destroy = false
}

# --- Artifact Registry (holds the container image) ----------------------

resource "google_artifact_registry_repository" "scanner" {
  location      = var.region
  repository_id = "compliance-agent"
  format        = "DOCKER"
  description   = "Container images for gcp-live-compliance-agent"

  depends_on = [google_project_service.required]
}

# --- Runtime service account (attached to the Cloud Run Job) ------------
# Least privilege: read-only on the project being scanned, plus Vertex AI
# user for Gemini. No key file is ever created — Cloud Run attaches this
# identity directly, so there's no long-lived credential to leak.

resource "google_service_account" "scanner" {
  account_id   = "compliance-agent-scanner"
  display_name = "gcp-live-compliance-agent runtime identity"

  depends_on = [google_project_service.required]
}

resource "google_project_iam_member" "scanner_viewer" {
  project = var.project_id
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.scanner.email}"
}

resource "google_project_iam_member" "scanner_vertex_ai" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.scanner.email}"
}

# --- Slack webhook secret -------------------------------------------------
# Always created, even if slack_webhook_url is left as "" — this avoids
# conditionally-created resources and a dynamic env block on
# google_cloud_run_v2_job, which doesn't reliably support `dynamic` block
# generation regardless of collection type (a real quirk hit while
# deploying this, not a hypothetical). An empty secret value means the
# scanner's SLACK_WEBHOOK_URL env var is empty at runtime, and the CLI's
# --notify-slack already treats an empty value as "not configured" and
# skips notification rather than erroring.

resource "google_secret_manager_secret" "slack_webhook" {
  secret_id = "compliance-agent-slack-webhook"

  replication {
    auto {}
  }

  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "slack_webhook" {
  secret      = google_secret_manager_secret.slack_webhook.id
  secret_data = local.slack_webhook_value
}

resource "google_secret_manager_secret_iam_member" "scanner_secret_access" {
  secret_id = google_secret_manager_secret.slack_webhook.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.scanner.email}"
}

# --- Cloud Run Job --------------------------------------------------------
# A Job (not a Service) — this runs to completion on a trigger, it doesn't
# serve HTTP traffic. That's the correct Cloud Run primitive for a
# scheduled batch/CLI task like a compliance scan.

resource "google_cloud_run_v2_job" "scanner" {
  name                = local.job_name
  location            = var.region
  deletion_protection = false

  template {
    template {
      service_account = google_service_account.scanner.email
      timeout         = "600s" # Gemini calls + two GCP API calls should comfortably fit; raise if you add more collectors
      max_retries     = 0      # A CRITICAL finding is a legitimate result, not a transient failure — retrying just re-runs Gemini 3 extra times for the same answer.

      containers {
        image = var.image

        env {
          name  = "GOOGLE_CLOUD_PROJECT"
          value = var.project_id
        }

        env {
          name = "SLACK_WEBHOOK_URL"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.slack_webhook.secret_id
              version = "latest"
            }
          }
        }
      }
    }
  }

  depends_on = [
    google_project_service.required,
    google_project_iam_member.scanner_viewer,
    google_project_iam_member.scanner_vertex_ai,
  ]
}

# --- Scheduler invoker identity -------------------------------------------
# Separate from the scanner's own runtime identity, on purpose: this SA's
# only job is "permission to press the run button" (roles/run.invoker),
# not permission to read the project it's scanning.

resource "google_service_account" "scheduler_invoker" {
  account_id   = "compliance-agent-invoker"
  display_name = "Cloud Scheduler -> Cloud Run Job invoker for gcp-live-compliance-agent"

  depends_on = [google_project_service.required]
}

resource "google_cloud_run_v2_job_iam_member" "scheduler_can_invoke" {
  name     = google_cloud_run_v2_job.scanner.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.scheduler_invoker.email}"
}

# --- Scheduler trigger -----------------------------------------------------

resource "google_cloud_scheduler_job" "nightly_scan" {
  name      = "compliance-agent-nightly-scan"
  region    = var.region
  schedule  = var.schedule_cron
  time_zone = var.time_zone

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${var.project_id}/jobs/${local.job_name}:run"

    oauth_token {
      service_account_email = google_service_account.scheduler_invoker.email
    }
  }

  depends_on = [
    google_project_service.required,
    google_cloud_run_v2_job_iam_member.scheduler_can_invoke,
  ]
}

# --- Email alerting on job failure -----------------------------------------
# Optional (skipped entirely if alert_email is ""). A "failed" execution
# here means either a genuine technical break OR a legitimate CRITICAL/HIGH
# finding — the CLI's --fail-on flag makes those exit non-zero on purpose.
# Check the execution's logs to tell which; the alert's own description
# links straight there.
#
# UNVERIFIED: the metric filter below (run.googleapis.com/job/completed_execution_count,
# result="failed") is written against Google's documented Cloud Run Jobs
# monitoring metrics, but has not been confirmed against a live alert firing
# from the sandbox this was written in. If it doesn't fire on a real job
# failure, check Cloud Monitoring's Metrics Explorer for the exact current
# metric/label names under resource type "Cloud Run Job" and adjust the
# filter accordingly — same category of caveat as everything else
# unverified in this repo.

resource "google_monitoring_notification_channel" "email" {
  count        = var.alert_email != "" ? 1 : 0
  display_name = "compliance-agent email alerts"
  type         = "email"

  labels = {
    email_address = var.alert_email
  }
}

resource "google_monitoring_alert_policy" "job_failure" {
  count        = var.alert_email != "" ? 1 : 0
  display_name = "compliance-agent-scan execution failed"
  combiner     = "OR"

  conditions {
    display_name = "Cloud Run Job execution failed"

    condition_threshold {
      filter = join(" AND ", [
        "resource.type=\"cloud_run_job\"",
        "resource.labels.job_name=\"${local.job_name}\"",
        "metric.type=\"run.googleapis.com/job/completed_execution_count\"",
        "metric.labels.result=\"failed\"",
      ])
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email[0].id]

  documentation {
    content   = "The compliance-agent-scan Cloud Run Job reported a failed execution. This means either a technical failure or a CRITICAL/HIGH compliance finding (the CLI exits non-zero on purpose in that case via --fail-on). Check the execution's logs to tell which: https://console.cloud.google.com/run/jobs/executions?project=${var.project_id}"
    mime_type = "text/markdown"
  }

  depends_on = [google_project_service.required]
}