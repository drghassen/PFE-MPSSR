variable "subscription_id" {
  description = "Azure subscription ID."
  type        = string
}

variable "tenant_id" {
  description = "Azure tenant ID."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group hosting the Terraform state storage account."
  type        = string
  default     = "rg-terraform-state"
}

variable "location" {
  description = "Azure region of the storage account."
  type        = string
  default     = "norwayeast"
}

variable "storage_account_name" {
  description = "Name of the existing Terraform state storage account. Must match exactly."
  type        = string
  default     = "sttfstateghassen01"
}

variable "state_container_name" {
  description = "Blob container holding .tfstate files. Used only in outputs."
  type        = string
  default     = "tfstate"
}

# ---------------------------------------------------------------------------
# Phase 1 — safe-hardening tunables
# ---------------------------------------------------------------------------

variable "blob_soft_delete_retention_days" {
  description = "Blob soft-delete retention days. 30 days recommended for state recovery."
  type        = number
  default     = 30

  validation {
    condition     = var.blob_soft_delete_retention_days >= 7 && var.blob_soft_delete_retention_days <= 365
    error_message = "Blob soft-delete retention must be between 7 and 365 days."
  }
}

variable "container_soft_delete_retention_days" {
  description = "Container soft-delete retention days."
  type        = number
  default     = 7

  validation {
    condition     = var.container_soft_delete_retention_days >= 7 && var.container_soft_delete_retention_days <= 365
    error_message = "Container soft-delete retention must be between 7 and 365 days."
  }
}

# ---------------------------------------------------------------------------
# Diagnostic logging (optional — requires Log Analytics Workspace)
# ---------------------------------------------------------------------------

variable "log_analytics_workspace_name" {
  description = "Name of the Log Analytics Workspace for diagnostic logging. Leave empty to skip."
  type        = string
  default     = ""
}

variable "log_analytics_workspace_rg" {
  description = "Resource group of the Log Analytics Workspace."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Phase 2 — network firewall (DO NOT enable without CI runner IP inventory)
# ---------------------------------------------------------------------------

variable "allowed_ip_ranges" {
  description = <<-EOT
    CIDR blocks allowed through the storage firewall.
    Used ONLY in Phase 2 when default_action switches to "Deny".
    Must include ALL GitLab runner egress IPs BEFORE switching to Deny.
    GitLab SaaS runner IP ranges: https://docs.gitlab.com/ee/user/gitlab_com/
    Self-hosted runner subnet: use the runner VM private IP or subnet CIDR.
  EOT
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to all managed resources."
  type        = map(string)
  default = {
    managed_by  = "terraform-bootstrap"
    purpose     = "terraform-remote-state"
    criticality = "critical"
    project     = "cloudsentinel"
  }
}
