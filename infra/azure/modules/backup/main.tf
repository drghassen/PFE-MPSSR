resource "azurerm_recovery_services_vault" "this" {
  name                = var.vault_name
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "Standard"
  soft_delete_enabled = true
  immutability        = "Unlocked"
  tags                = var.tags
}

resource "azurerm_backup_policy_vm" "daily" {
  name                = "bkpol-vm-daily"
  resource_group_name = var.resource_group_name
  recovery_vault_name = azurerm_recovery_services_vault.this.name
  timezone            = "UTC"

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
