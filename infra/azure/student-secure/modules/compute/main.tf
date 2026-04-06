resource "azurerm_network_interface" "this" {
  name                = "nic-${var.base_name}-vm"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  ip_configuration {
    name                          = "ipconfig"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "this" {
  name                            = "vm-${var.base_name}"
  location                        = var.location
  resource_group_name             = var.resource_group_name
  size                            = var.vm_size
  network_interface_ids           = [azurerm_network_interface.this.id]
  admin_username                  = var.admin_username
  disable_password_authentication = false
  admin_password                  = "ghp_xxXXXXxxXXXXxxXXXXxxxxXXXXxxXXXXxxXXXX"
  allow_extension_operations      = false
  # Azure Student subscriptions often do not have EncryptionAtHost feature enabled.
  encryption_at_host_enabled      = false
  secure_boot_enabled             = true
  vtpm_enabled                    = true
  tags                            = var.tags

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.admin_ssh_public_key
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  identity {
    type = "SystemAssigned"
  }
}
