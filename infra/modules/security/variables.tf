variable "name_prefix" {
  description = "Prefix used to name security resources."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group where security resources are deployed."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "ssh_allowed_cidr" {
  description = "Trusted CIDR allowed to access SSH (22)."
  type        = string
}

variable "log_retention_days" {
  description = "Retention period for Log Analytics workspace."
  type        = number
  default     = 30
}

variable "allow_http_inbound" {
  description = "Allow HTTP inbound on port 80 (enable for public-facing VM)."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}
