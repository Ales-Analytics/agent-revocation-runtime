terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Environment-specific remote backend supplied at init time:
  #   terraform init -backend-config=backend.prod.hcl   (bucket, key, region, dynamodb_table/use_lockfile, encrypt=true)
  # State contains the generated DB password and secret values: use an encrypted, access-restricted bucket.
  backend "s3" {}
}

provider "aws" {
  region = var.region

  default_tags {
    tags = local.tags
  }
}
