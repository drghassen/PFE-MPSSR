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
  description = "Application principal ID granted Key Vault secrets read access."
  type        = string
}

variable "network_acl_bypass" {
  description = "Azure services that can bypass the Key Vault network ACL. Set to 'AzureServices' when a Disk Encryption Set uses this vault for CMK (Prowler: vm_ensure_attached_disks_encrypted_with_cmk)."
  type        = string
  default     = "AzureServices"
}

variable "grant_app_kv_secrets_user_role" {
  description = "Create Key Vault Secrets User role assignment for app principal."
  type        = bool
  default     = false
}

variable "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID for diagnostics."
  type        = string
}

variable "tags" {
  description = "Common tags."
  type        = map(string)
  default     = {}
}
