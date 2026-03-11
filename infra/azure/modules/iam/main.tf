resource "azurerm_user_assigned_identity" "workload" {
  name                = "id-${var.project_name}-${var.environment}-workload"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

# Risky on purpose: broad write rights for workload identity at resource-group scope.
resource "azurerm_role_assignment" "workload_contributor" {
  scope                = var.resource_group_id
  role_definition_name = "Contributor"
  principal_id         = azurerm_user_assigned_identity.workload.principal_id
}
