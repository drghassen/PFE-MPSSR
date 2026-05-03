resource "azurerm_public_ip" "this" {
  name                = "${var.bastion_name}-pip"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_bastion_host" "this" {
  name                = var.bastion_name
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "Standard"
  tunneling_enabled   = true
  copy_paste_enabled  = true
  tags                = var.tags

  ip_configuration {
    name                 = "bastion-ip-config"
    subnet_id            = var.bastion_subnet_id
    public_ip_address_id = azurerm_public_ip.this.id
  }
}
