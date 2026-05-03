variable "resource_group_name" {
  description = "Resource group that owns the Key Vault."
  type        = string
}

variable "key_vault_name" {
  description = "Name of the existing Key Vault to remediate."
  type        = string
}

variable "log_analytics_workspace_name" {
  description = "Name of the existing Log Analytics Workspace to receive logs."
  type        = string
}

variable "log_analytics_workspace_rg" {
  description = "Resource group of the Log Analytics Workspace."
  type        = string
}

variable "diagnostic_setting_name" {
  description = "Name for the diagnostic setting resource."
  type        = string
  default     = "kv-audit-diag"
}
