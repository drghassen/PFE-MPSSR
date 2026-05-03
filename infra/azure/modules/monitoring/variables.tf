variable "resource_group_name" {
  description = "Resource group name."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "workspace_name" {
  description = "Log Analytics workspace name."
  type        = string
}

variable "retention_in_days" {
  description = "Workspace retention days."
  type        = number
  default     = 90
}

variable "tags" {
  description = "Common tags."
  type        = map(string)
  default     = {}
}
