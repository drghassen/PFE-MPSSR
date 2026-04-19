variable "name_prefix" {
  description = "Prefix used to name database resources."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group where the database is deployed."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "admin_login" {
  description = "PostgreSQL administrator username."
  type        = string
}

variable "admin_password" {
  description = "PostgreSQL administrator password."
  type        = string
  sensitive   = true
}

variable "sku_name" {
  description = "PostgreSQL Flexible Server SKU (Burstable B1ms is cheapest)."
  type        = string
  default     = "B_Standard_B1ms"
}

variable "db_name" {
  description = "Initial database name."
  type        = string
  default     = "cloudsentinel"
}

variable "allowed_ips" {
  description = "List of IPs allowed to connect to the DB (add VM public IP + your own IP)."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}
