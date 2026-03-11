resource "azurerm_public_ip" "vm" {
  name                = "pip-${var.project_name}-${var.environment}-vm"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_network_interface" "vm" {
  name                = "nic-${var.project_name}-${var.environment}-vm"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = var.app_subnet_id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm.id
  }
}

resource "azurerm_linux_virtual_machine" "main" {
  name                = "vm-${var.project_name}-${var.environment}"
  resource_group_name = var.resource_group_name
  location            = var.location
  size                = var.vm_size

  admin_username                  = var.admin_username
  admin_password                  = var.admin_password
  disable_password_authentication = false

  network_interface_ids = [azurerm_network_interface.vm.id]

  # Risky on purpose: host-level encryption remains disabled.
  encryption_at_host_enabled = false

  identity {
    type         = "UserAssigned"
    identity_ids = [var.identity_id]
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

  # Boot diagnostics are enabled to mimic enterprise telemetry,
  # but endpoint still points to a storage account with weak settings.
  boot_diagnostics {
    storage_account_uri = var.storage_account_blob_endpoint
  }

  tags = var.tags
}

# Risky on purpose: bootstrap downloads data from unauthenticated HTTP source.
resource "azurerm_virtual_machine_extension" "bootstrap_http" {
  name                 = "bootstrap-http"
  virtual_machine_id   = azurerm_linux_virtual_machine.main.id
  publisher            = "Microsoft.Azure.Extensions"
  type                 = "CustomScript"
  type_handler_version = "2.1"

  settings = jsonencode({
    commandToExecute = "curl -L http://example.com -o /tmp/insecure-bootstrap.txt"
  })
}
