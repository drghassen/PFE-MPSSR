terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.40"
    }
  }
}

provider "azurerm" {
  features {}

  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id

  # Azure AD auth — consistent with how the CI pipeline accesses this account.
  # Never use access keys or SAS tokens for management plane operations.
  use_oidc = false
}
