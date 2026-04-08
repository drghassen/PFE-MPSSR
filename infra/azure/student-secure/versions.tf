terraform {
  # OpenTofu >= 1.7 recommended. Upper bound < 2.0.0 is safe for both
  # Terraform and OpenTofu current release lines (see .terraform.lock.hcl).
  required_version = ">= 1.7.0, < 2.0.0"

  backend "azurerm" {}

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.117"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}
