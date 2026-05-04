resource "azurerm_recovery_services_vault" "this" {
  name                = var.vault_name
  location            = var.location
  resource_group_name = var.resource_group_name
  sku          = "Standard"
  immutability = "Unlocked"
  tags                = var.tags

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_backup_policy_vm" "daily" {
  name                = "bkpol-vm-daily"
  resource_group_name = var.resource_group_name
  recovery_vault_name = azurerm_recovery_services_vault.this.name
  timezone            = "UTC"
  policy_type         = "V2"

  backup {
    frequency = "Daily"
    time      = var.backup_time
  }

  retention_daily {
    count = var.backup_retention_days
  }
}

resource "azurerm_backup_protected_vm" "this" {
  resource_group_name = var.resource_group_name
  recovery_vault_name = azurerm_recovery_services_vault.this.name
  source_vm_id        = var.vm_id
  backup_policy_id    = azurerm_backup_policy_vm.daily.id
}
