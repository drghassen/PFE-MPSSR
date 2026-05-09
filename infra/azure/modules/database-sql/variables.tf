variable "enabled" {
  type    = bool
  default = false
}

variable "server_name" {
  type = string
}

variable "database_name" {
  type    = string
  default = "cloudsentinel"
}

variable "sku_name" {
  description = "SQL DB SKU — Basic (~5$/mo) is fine for dev"
  type        = string
  default     = "Basic"
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "vnet_id" {
  type = string
}

variable "private_endpoint_subnet_id" {
  type = string
}

variable "azuread_admin_login" {
  description = "Display name of the Entra ID user/group acting as SQL admin"
  type        = string
}

variable "azuread_admin_object_id" {
  description = "Object ID of the Entra ID user/group acting as SQL admin"
  type        = string
}

variable "tags" {
  type    = map(string)
  default = {}
}
