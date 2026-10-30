terraform {
  required_version = "= 1.17.1"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.71.0"
    }
  }

  # Partial configuration: bucket, key, region, encrypt and use_lockfile are supplied by
  # the runner as -backend-config arguments so every deployment gets an isolated state key.
  backend "s3" {}
}

provider "aws" {
  region              = var.region
  allowed_account_ids = [var.account_id]
}
