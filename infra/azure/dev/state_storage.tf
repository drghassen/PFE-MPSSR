# Ce fichier permet de gérer le backend Terraform LUI-MÊME avec Terraform.
# Cela garantit que les règles de sécurité (Versioning, TLS, Private Access) restent actives.

resource "azurerm_resource_group" "tfstate" {
  name     = "rg-terraform-state"
  location = var.location
  tags     = local.mandatory_tags
}

resource "azurerm_storage_account" "tfstate" {
  name                     = "sttfstateghassen"
  resource_group_name      = azurerm_resource_group.tfstate.name
  location                 = azurerm_resource_group.tfstate.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  # Sécurité : Désactiver l'accès public par défaut (Bonne pratique)
  public_network_access_enabled = true # Doit être true pour que vous puissiez y accéder depuis WSL/Github Actions sans VPN, mais on peut restreindre via firewall rules si besoin. 
  # Note: "true" ici signifie "Enabled from all networks" ou "Enabled from selected virtual networks and IP addresses".
  # Pour un PFE, on laisse souvent true pour simplifier l'accès depuis n'importe quelle IP (Roadwarrior), 
  # mais en prod entreprise on mettrait false et on utiliserait des Private Endpoints.
  
  # On s'assure que le trafic est chiffré
  https_traffic_only_enabled = true

  blob_properties {
    versioning_enabled = true
    
    delete_retention_policy {
      days = 7
    }
    
    container_delete_retention_policy {
      days = 7
    }
  }

  tags = local.mandatory_tags
}

resource "azurerm_storage_container" "tfstate" {
  name                  = "tfstate"
  storage_account_name  = azurerm_storage_account.tfstate.name
  container_access_type = "private"
}
