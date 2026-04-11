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
  name                  = "vm-${var.base_name}"
  location              = var.location
  resource_group_name   = var.resource_group_name
  size                  = var.vm_size
  network_interface_ids = [azurerm_network_interface.this.id]
  admin_username        = var.admin_username

  # CKV_AZURE_1 / CKV_AZURE_149 — SSH-only authentication enforced.
  # Password authentication is explicitly disabled. Access requires
  # a pre-provisioned RSA key pair (see admin_ssh_public_key variable).
  # Ref: CIS Azure 1.6, NIST 800-53 IA-5
  disable_password_authentication = true

  allow_extension_operations = false

  # CKV2_CS_AZ_010 / CIS 7.1 — Encryption at host.
  # PRE-REQUISITE: The Azure subscription must have the EncryptionAtHost
  # feature registered before apply:
  #   az feature register \
  #     --namespace Microsoft.Compute --name EncryptionAtHost
  #   az provider register --namespace Microsoft.Compute
  # Azure Student subscriptions may need to request this via support.
  encryption_at_host_enabled = var.encryption_at_host_enabled

  secure_boot_enabled = true
  vtpm_enabled        = true
  tags                = var.tags

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.admin_ssh_public_key
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    # Pin to a specific patch release for supply-chain reproducibility.
    # Periodically update via:
    #   az vm image list --publisher Canonical \
    #     --offer 0001-com-ubuntu-server-jammy \
    #     --sku 22_04-lts-gen2 --all --query "[-1].version" -o tsv
    version = "22.04.202404090"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"

    # CKV2_CS_AZ_010 — Disk-level CMK encryption via Disk Encryption Set.
    # Provides a second encryption layer beyond the default Azure-managed key.
    # Set to null when no DES is provisioned (e.g., dev environments).
    disk_encryption_set_id = var.disk_encryption_set_id
  }

  identity {
    type = "SystemAssigned"
  }
}
