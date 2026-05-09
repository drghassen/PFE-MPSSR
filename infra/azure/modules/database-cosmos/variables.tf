variable "enabled" {
  type    = bool
  default = false
}

variable "account_name" {
  type = string
}

variable "database_name" {
  type    = string
  default = "cloudsentinel"
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "allowed_subnet_ids" {
  type    = list(string)
  default = []
}

variable "tags" {
  type    = map(string)
  default = {}
}
