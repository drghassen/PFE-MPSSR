variable "resource_group_name" {
  description = "Resource group for the flow-log storage account (application RG)."
  type        = string
}

variable "location" {
  description = "Azure region (must match the Network Watcher region)."
  type        = string
}

variable "name_prefix" {
  description = "Short, lowercase naming prefix used in storage account name generation."
  type        = string
}

variable "environment" {
  description = "Environment label (dev / staging / prod) — appended to storage account name."
  type        = string
}

variable "network_watcher_name" {
  description = "Name of the existing Network Watcher. Azure auto-names these NetworkWatcher_<region>."
  type        = string
  default     = "NetworkWatcher_norwayeast"
}

variable "network_watcher_rg" {
  description = "Resource group that contains the Network Watcher. Azure default is NetworkWatcherRG."
  type        = string
  default     = "NetworkWatcherRG"
}

variable "log_analytics_workspace_name" {
  description = "Name of the existing Log Analytics Workspace for Traffic Analytics."
  type        = string
}

variable "log_analytics_workspace_rg" {
  description = "Resource group of the Log Analytics Workspace."
  type        = string
}

variable "nsgs" {
  description = <<-EOT
    Map of logical NSG key to NSG resource ID.
    Keys must be stable, slug-safe strings (lowercase, hyphens ok) — they become
    part of the flow log resource name and Terraform state address.
    Example:
      nsgs = {
        app               = "/subscriptions/.../nsg-app"
        private-endpoints = "/subscriptions/.../nsg-pe"
        data              = "/subscriptions/.../nsg-data"
        bastion           = "/subscriptions/.../nsg-bastion"
      }
  EOT
  type        = map(string)
}

variable "flow_log_retention_days" {
  description = "Number of days to retain NSG flow logs. CIS Azure 6.5 requires >= 90."
  type        = number
  default     = 90

  validation {
    condition     = var.flow_log_retention_days >= 90
    error_message = "Flow log retention must be at least 90 days (CIS Azure 6.5)."
  }
}

variable "traffic_analytics_interval_minutes" {
  description = "Traffic Analytics processing interval: 10 (near-real-time) or 60 (hourly)."
  type        = number
  default     = 10

  validation {
    condition     = contains([10, 60], var.traffic_analytics_interval_minutes)
    error_message = "Interval must be 10 or 60 minutes."
  }
}

variable "tags" {
  description = "Common tags applied to all resources created by this module."
  type        = map(string)
  default     = {}
}
