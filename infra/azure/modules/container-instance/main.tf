resource "azurerm_container_group" "this" {
  name                = var.name
  location            = var.location
  resource_group_name = var.resource_group_name
  os_type             = "Linux"
  ip_address_type     = "Private"
  subnet_ids          = [var.subnet_id]
  restart_policy      = "Always"
  tags                = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [var.user_assigned_identity_id]
  }

  container {
    name   = "app"
    image  = var.image
    cpu    = var.cpu
    memory = var.memory

    ports {
      port     = 8080
      protocol = "TCP"
    }

    environment_variables = {
      APP_ENV = "lab"
    }

    commands = [
      "/bin/sh",
      "-c",
      "python3 -m http.server 8080",
    ]
  }
}
