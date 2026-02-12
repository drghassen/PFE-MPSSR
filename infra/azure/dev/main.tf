resource "azurerm_resource_group" "app" {
  name     = "rg-${var.project_name}-${var.environment}-${var.location}"
  location = var.location

  tags = merge(var.common_tags, {
    Owner          = var.owner
    DeploymentDate = formatdate("YYYY-MM-DD", timestamp())
  })

  lifecycle {
    ignore_changes = [
      tags["DeploymentDate"]
    ]
  }
}