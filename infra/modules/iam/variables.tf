variable "name_prefix" {
  description = "Prefix used to name identity resources."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group where identities are deployed."
  type        = string
}

variable "resource_group_id" {
  description = "Resource group ID used as role-assignment scope."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "create_ci_identity" {
  description = "Create a dedicated least-privilege identity for CI/CD automation."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}
