resource "azurerm_virtual_network" "this" {
  name                = "${var.name_prefix}-vnet"
  location            = var.location
  resource_group_name = var.resource_group_name
  address_space       = [var.vnet_cidr]
  tags                = var.tags
}

resource "azurerm_subnet" "public" {
  name                 = "${var.name_prefix}-public-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.public_subnet_cidr]
}

resource "azurerm_subnet" "private" {
  name                 = "${var.name_prefix}-private-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.private_subnet_cidr]
}

resource "azurerm_subnet_network_security_group_association" "public" {
  count = var.associate_public_nsg ? 1 : 0

  subnet_id                 = azurerm_subnet.public.id
  network_security_group_id = var.public_subnet_nsg_id
}

resource "azurerm_subnet_network_security_group_association" "private" {
  count = var.associate_private_nsg ? 1 : 0

  subnet_id                 = azurerm_subnet.private.id
  network_security_group_id = var.private_subnet_nsg_id
}

resource "azurerm_public_ip" "nat" {
  count               = var.create_nat_gateway ? 1 : 0
  name                = "${var.name_prefix}-nat-pip"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_nat_gateway" "this" {
  count                   = var.create_nat_gateway ? 1 : 0
  name                    = "${var.name_prefix}-natgw"
  location                = var.location
  resource_group_name     = var.resource_group_name
  sku_name                = "Standard"
  idle_timeout_in_minutes = 10
  tags                    = var.tags
}

resource "azurerm_nat_gateway_public_ip_association" "this" {
  count                = var.create_nat_gateway ? 1 : 0
  nat_gateway_id       = azurerm_nat_gateway.this[0].id
  public_ip_address_id = azurerm_public_ip.nat[0].id
}

resource "azurerm_subnet_nat_gateway_association" "private" {
  count          = var.create_nat_gateway ? 1 : 0
  subnet_id      = azurerm_subnet.private.id
  nat_gateway_id = azurerm_nat_gateway.this[0].id
}
