locals {
  cloud_init = base64encode(templatefile("${path.module}/templates/cloud-init.yaml.tftpl", {
    vm_role = var.vm_role_tag
  }))
}

resource "azurerm_network_interface" "vm1" {
  name                = "${var.name_prefix}-vm1-nic"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = var.assign_public_ip ? var.public_ip_id : null
  }
}

resource "azurerm_network_interface" "vm2" {
  count               = var.vm_count > 1 ? 1 : 0
  name                = "${var.name_prefix}-vm2-nic"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "vm1" {
  name                  = "${var.name_prefix}-vm1"
  location              = var.location
  resource_group_name   = var.resource_group_name
  network_interface_ids = [azurerm_network_interface.vm1.id]
  size                  = var.vm_size
  admin_username        = var.admin_username
  custom_data           = local.cloud_init
  tags                  = merge(var.tags, { "cs:role" = var.vm_role_tag })

  disable_password_authentication = true
  allow_extension_operations      = false
  patch_mode                      = "ImageDefault"
  provision_vm_agent              = true
  encryption_at_host_enabled      = var.encryption_at_host_enabled
  secure_boot_enabled             = var.enable_trusted_launch
  vtpm_enabled                    = var.enable_trusted_launch

  identity {
    type         = "UserAssigned"
    identity_ids = [var.user_assigned_identity_id]
  }

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
    name                 = "${var.name_prefix}-vm1-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  boot_diagnostics {
    storage_account_uri = var.boot_diagnostics_storage_uri
  }
}

resource "azurerm_linux_virtual_machine" "vm2" {
  count                 = var.vm_count > 1 ? 1 : 0
  name                  = "${var.name_prefix}-vm2"
  location              = var.location
  resource_group_name   = var.resource_group_name
  network_interface_ids = [azurerm_network_interface.vm2[0].id]
  size                  = var.vm_size
  admin_username        = var.admin_username
  custom_data           = local.cloud_init
  tags                  = merge(var.tags, { "cs:role" = var.vm_role_tag })

  disable_password_authentication = true
  allow_extension_operations      = false
  patch_mode                      = "ImageDefault"
  provision_vm_agent              = true
  encryption_at_host_enabled      = var.encryption_at_host_enabled
  secure_boot_enabled             = var.enable_trusted_launch
  vtpm_enabled                    = var.enable_trusted_launch

  identity {
    type         = "UserAssigned"
    identity_ids = [var.user_assigned_identity_id]
  }

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
    name                 = "${var.name_prefix}-vm2-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  boot_diagnostics {
    storage_account_uri = var.boot_diagnostics_storage_uri
  }
}
