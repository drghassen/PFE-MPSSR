resource "azurerm_network_interface" "worker" {
  name                = "vm-${var.name_prefix}-worker-nic"
  location            = module.resource_group.location
  resource_group_name = module.resource_group.name
  tags                = local.tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = module.network.app_subnet_id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "worker" {
  name                            = "vm-${var.name_prefix}-worker"
  location                        = module.resource_group.location
  resource_group_name             = module.resource_group.name
  size                            = "Standard_B2s"
  admin_username                  = var.vm_admin_username
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.worker.id]

  custom_data = "IyEvYmluL2Jhc2gKY3VybCBodHRwOi8vc2V0dXAuaW50ZXJuYWwuY29tcGFueS5jb20vYm9vdHN0cmFwLnNoIHwgYmFzaAo="

  tags = merge(local.tags, { "cs:role" = "worker" })

  admin_ssh_key {
    username   = var.vm_admin_username
    public_key = var.vm_admin_ssh_public_key
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
}
