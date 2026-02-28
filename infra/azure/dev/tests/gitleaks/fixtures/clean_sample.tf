# ==============================================================================
# CloudSentinel — Fixture : Configuration Propre (Gitleaks Smoke Test)
#
# Ce fichier ne doit déclencher AUCUN finding Gitleaks.
# Il valide que les règles ne génèrent pas de faux positifs sur
# des patterns légitimes (variables d'environnement sans valeur,
# références à des secrets via vault, etc.)
# ==============================================================================

# Bonne pratique : valeur lue depuis une variable d'environnement
variable "storage_account_name" {
  description = "Nom du compte de stockage Azure"
  type        = string
}

# Bonne pratique : référence Vault — jamais de valeur hardcodée
data "vault_generic_secret" "azure_creds" {
  path = "secret/cloudsentinel/azure"
}

# Bonne pratique : tag de resource sans credential
resource "azurerm_resource_group" "main" {
  name     = "rg-cloudsentinel-dev"
  location = "West Europe"

  tags = {
    Environment = "dev"
    ManagedBy   = "terraform"
    Project     = "cloudsentinel"
  }
}

# Bonne pratique : référence à une variable d'env externe (pas de valeur)
locals {
  app_settings = {
    AZURE_CLIENT_ID = var.client_id
    AZURE_TENANT_ID = var.tenant_id
    KEY_VAULT_URL   = "https://kv-cloudsentinel.vault.azure.net/"
    # Pas de secret en clair ici
  }
}
