variable "resource_group_name" {
  description = "Resource group name."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "key_vault_name" {
  description = "Key Vault name."
  type        = string
}

variable "tenant_id" {
  description = "Azure tenant ID."
  type        = string
}

variable "private_endpoints_subnet_id" {
  description = "Subnet ID dedicated to private endpoints."
  type        = string
}

variable "virtual_network_id" {
  description = "VNet ID linked to the private DNS zone."
  type        = string
}

variable "sku_name" {
  description = "Key Vault SKU."
  type        = string
  default     = "standard"
}

variable "private_dns_zone_name" {
  description = "Private DNS zone name for Key Vault."
  type        = string
  default     = "privatelink.vaultcore.azure.net"
}

variable "purge_protection_enabled" {
  description = "Enable purge protection."
  type        = bool
  default     = true
}

variable "soft_delete_retention_days" {
  description = "Soft delete retention in days."
  type        = number
  default     = 90
}

variable "app_principal_id" {
  description = "Optional application principal to grant Key Vault read access."
  type        = string
  default     = null
}

variable "log_analytics_workspace_id" {
  description = "Optional Log Analytics workspace ID for diagnostics."
  type        = string
  default     = null
}

variable "tags" {
  description = "Common tags."
  type        = map(string)
  default     = {}
}
