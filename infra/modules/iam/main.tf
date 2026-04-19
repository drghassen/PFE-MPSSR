resource "azurerm_user_assigned_identity" "vm" {
  name                = "${var.name_prefix}-vm-mi"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_user_assigned_identity" "ci" {
  count               = var.create_ci_identity ? 1 : 0
  name                = "${var.name_prefix}-ci-mi"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_role_assignment" "vm_reader" {
  scope                = var.resource_group_id
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.vm.principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "ci_reader" {
  count                = var.create_ci_identity ? 1 : 0
  scope                = var.resource_group_id
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.ci[0].principal_id
  principal_type       = "ServicePrincipal"
}
