output "job_name" {
  value       = google_cloud_run_v2_job.scanner.name
  description = "Cloud Run Job name — use with `gcloud run jobs execute` to trigger a run manually, outside the schedule."
}

output "scanner_service_account" {
  value       = google_service_account.scanner.email
  description = "Runtime identity the job runs as — this is what needs any additional IAM roles if you scan a different project."
}

output "artifact_registry_repo" {
  value       = google_artifact_registry_repository.scanner.name
  description = "Push your built image here before the first `terraform apply` that references it."
}
