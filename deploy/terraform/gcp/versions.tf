terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Environment-specific remote backend supplied at init time:
  #   terraform init -backend-config=backend.prod.hcl   (bucket, prefix)
  # State contains the generated DB password and secret values: use a private, versioned, CMEK-encrypted bucket.
  backend "gcs" {}
}

provider "google" {
  project = var.project_id
  region  = var.region
}
