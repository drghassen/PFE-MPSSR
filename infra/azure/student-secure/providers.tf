provider "azurerm" {
  features {}

  # Avoid key-based data-plane calls for storage resources when shared keys are disabled.
  storage_use_azuread = true
}

