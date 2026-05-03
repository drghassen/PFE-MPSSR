output "gallery_id" {
  description = "Azure Compute Gallery ID."
  value       = azurerm_shared_image_gallery.this.id
}

output "gallery_name" {
  description = "Azure Compute Gallery name."
  value       = azurerm_shared_image_gallery.this.name
}

output "ubuntu_2204_image_id" {
  description = "Image definition ID for the Ubuntu 22.04 LTS Gen2 approved image."
  value       = azurerm_shared_image.ubuntu_2204_lts_gen2.id
}
