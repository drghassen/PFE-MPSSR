locals {
  cloud_init = var.cloud_init == null ? null : base64encode(var.cloud_init)
}

resource "azurerm_network_interface" "this" {
  name                = "${var.vm_name}-nic"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "this" {
  name                            = var.vm_name
  location                        = var.location
  resource_group_name             = var.resource_group_name
  size                            = var.vm_size
  admin_username                  = var.admin_username
  disable_password_authentication = true
  allow_extension_operations      = false
  network_interface_ids           = [azurerm_network_interface.this.id]
  custom_data                     = local.cloud_init
  encryption_at_host_enabled      = var.encryption_at_host_enabled
  vtpm_enabled                    = var.vtpm_enabled
  secure_boot_enabled             = var.secure_boot_enabled
  tags                            = merge({ "cs:role" = "app" }, var.tags)

  identity {
    type = "SystemAssigned"
  }

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.admin_ssh_public_key
  }

  os_disk {
    name                   = "${var.vm_name}-osdisk"
    caching                = "ReadWrite"
    storage_account_type   = "Premium_LRS"
    disk_size_gb           = var.os_disk_size_gb
    disk_encryption_set_id = var.disk_encryption_set_id
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  boot_diagnostics {}
}

resource "azurerm_role_assignment" "rg_reader" {
  count                = var.grant_rg_reader ? 1 : 0
  scope                = var.resource_group_id
  role_definition_name = "Reader"
  principal_id         = azurerm_linux_virtual_machine.this.identity[0].principal_id
}

resource "azurerm_monitor_diagnostic_setting" "vm" {
  # checkov:skip=CKV2_CS_AZ_020: Linux VM diagnostic settings expose metrics only; logs are ingested via Azure Monitor Agent extension
  name                       = "${var.vm_name}-diag"
  target_resource_id         = azurerm_linux_virtual_machine.this.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_metric {
    category = "AllMetrics"
  }
}
