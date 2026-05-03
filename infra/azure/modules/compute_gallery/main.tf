resource "azurerm_shared_image_gallery" "this" {
  name                = var.gallery_name
  resource_group_name = var.resource_group_name
  location            = var.location
  description         = "Approved VM images catalogue for CloudSentinel workloads (Prowler: vm_ensure_using_approved_images)."
  tags                = var.tags
}

# Approved baseline image definition: Canonical Ubuntu 22.04 LTS Gen2.
# Image versions are published by the CI/CD image-builder pipeline after
# CIS hardening and signature verification.
resource "azurerm_shared_image" "ubuntu_2204_lts_gen2" {
  name                = "ubuntu-22-04-lts-gen2"
  gallery_name        = azurerm_shared_image_gallery.this.name
  resource_group_name = var.resource_group_name
  location            = var.location
  os_type             = "Linux"
  hyper_v_generation  = "V2"
  description         = "Canonical Ubuntu 22.04 LTS Gen2 — approved baseline for app workloads."
  tags                = var.tags

  identifier {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
  }
}
