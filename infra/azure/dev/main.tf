resource "azurerm_resource_group" "app" {
  name     = "rg-${var.project_name}-${var.environment}-${var.location}"
  location = var.location

  tags = merge(local.mandatory_tags, {
    Owner          = var.owner
    DeploymentDate = formatdate("YYYY-MM-DD", timestamp())
  })

  lifecycle {
    ignore_changes = [
      tags["DeploymentDate"]
    ]
  }
}

# Enterprise composition split by domains (network/storage/iam/compute).
module "network" {
  source = "../modules/network"

  project_name        = var.project_name
  environment         = var.environment
  location            = azurerm_resource_group.app.location
  resource_group_name = azurerm_resource_group.app.name
  tags                = merge(local.mandatory_tags, { Owner = var.owner })
}

module "storage" {
  source = "../modules/storage"

  project_name        = var.project_name
  environment         = var.environment
  location            = azurerm_resource_group.app.location
  resource_group_name = azurerm_resource_group.app.name
  tags                = merge(local.mandatory_tags, { Owner = var.owner })
}

module "iam" {
  source = "../modules/iam"

  project_name        = var.project_name
  environment         = var.environment
  location            = azurerm_resource_group.app.location
  resource_group_name = azurerm_resource_group.app.name
  resource_group_id   = azurerm_resource_group.app.id
  tags                = merge(local.mandatory_tags, { Owner = var.owner })
}

module "compute" {
  source = "../modules/compute"

  project_name                  = var.project_name
  environment                   = var.environment
  location                      = azurerm_resource_group.app.location
  resource_group_name           = azurerm_resource_group.app.name
  app_subnet_id                 = module.network.app_subnet_id
  identity_id                   = module.iam.identity_id
  storage_account_blob_endpoint = module.storage.primary_blob_endpoint
  admin_username                = var.admin_username
  admin_password                = var.admin_password
  vm_size                       = var.vm_size
  tags                          = merge(local.mandatory_tags, { Owner = var.owner })
}
