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

variable "network_acl_bypass" {
  description = "Azure services that can bypass the Key Vault network ACL. Set to 'AzureServices' when a Disk Encryption Set uses this vault for CMK (Prowler: vm_ensure_attached_disks_encrypted_with_cmk)."
  type        = string
  default     = "AzureServices"
}

variable "public_network_access_enabled" {
  description = "Allow public network access to the Key Vault. Set to true in dev so the CI/CD runner (not in VNet) can manage CMK keys. Set to false in prod where a self-hosted runner with VNet access is used."
  type        = bool
  default     = false
}

variable "network_acl_default_action" {
  description = "Default network ACL action: 'Allow' (all public IPs permitted) or 'Deny' (only explicit rules)."
  type        = string
  default     = "Deny"

  validation {
    condition     = contains(["Allow", "Deny"], var.network_acl_default_action)
    error_message = "network_acl_default_action must be 'Allow' or 'Deny'."
  }
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
