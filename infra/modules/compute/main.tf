resource "azurerm_public_ip" "vm" {
  count               = var.assign_public_ip ? 1 : 0
  name                = "${var.name_prefix}-vm-pip"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_network_interface" "this" {
  name                = "${var.name_prefix}-vm-nic"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = var.assign_public_ip ? azurerm_public_ip.vm[0].id : null
  }
}

resource "azurerm_network_interface_security_group_association" "this" {
  network_interface_id      = azurerm_network_interface.this.id
  network_security_group_id = var.nsg_id
}

resource "azurerm_linux_virtual_machine" "this" {
  name                            = "${var.name_prefix}-vm"
  location                        = var.location
  resource_group_name             = var.resource_group_name
  size                            = var.vm_size
  admin_username                  = var.admin_username
  disable_password_authentication = true
  encryption_at_host_enabled      = true
  patch_mode                      = "AutomaticByPlatform"
  secure_boot_enabled             = true
  vtpm_enabled                    = true
  custom_data                     = var.cloud_init_content
  tags                            = var.tags

  network_interface_ids = [azurerm_network_interface.this.id]

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.admin_ssh_public_key
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [var.user_assigned_identity_id]
  }

  os_disk {
    name                 = "${var.name_prefix}-vm-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    disk_size_gb         = 64
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  boot_diagnostics {}
}

resource "azurerm_monitor_diagnostic_setting" "vm" {
  name                       = "${var.name_prefix}-vm-diag"
  target_resource_id         = azurerm_linux_virtual_machine.this.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_metric {
    category = "AllMetrics"
  }
}
