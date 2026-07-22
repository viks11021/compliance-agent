terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }

  # Remote state, not local. Without this, a GitHub Actions runner (a
  # fresh machine every run) has no way to see resources already created
  # from a local `terraform apply` — it would try to recreate them and
  # fail with "already exists" errors. Bucket name is set via
  # `-backend-config` at init time (see deploy/github-actions-setup.md)
  # rather than hardcoded here, so this file doesn't need editing per
  # environment.
  backend "gcs" {}
}

provider "google" {
  project = var.project_id
  region  = var.region
}
