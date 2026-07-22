variable "project_id" {
  description = "GCP project to deploy the automation into AND to scan. If you want to scan a different project than you deploy into, add a second project_id_to_scan variable and grant the service account roles/viewer on that project too."
  type        = string
}

variable "region" {
  description = "Region for Cloud Run Job, Artifact Registry, and Cloud Scheduler."
  type        = string
  default     = "us-central1"
}

variable "image" {
  description = "Full Artifact Registry image path, e.g. us-central1-docker.pkg.dev/PROJECT/compliance-agent/scanner:latest. Build and push this yourself (see deploy/terraform/README.md) — Terraform does not build the image."
  type        = string
}

variable "schedule_cron" {
  description = "Cron schedule for the scan, in Cloud Scheduler's App Engine cron syntax."
  type        = string
  default     = "0 2 * * *" # nightly at 02:00
}

variable "time_zone" {
  description = "IANA time zone for schedule_cron."
  type        = string
  default     = "Etc/UTC"
}

variable "slack_webhook_url" {
  description = "Slack incoming webhook URL. Stored in Secret Manager, never in plain Terraform state as an env var. Leave empty to deploy without Slack notifications."
  type        = string
  sensitive   = true
  default     = ""
}
