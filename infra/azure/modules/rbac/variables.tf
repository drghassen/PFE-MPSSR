variable "principal_id" {
  type = string
}

variable "resource_group_id" {
  type = string
}

variable "storage_account_id" {
  type = string
}

variable "key_vault_id" {
  type = string
}

variable "cosmosdb_account_id" {
  type    = string
  default = null
}

variable "grant_rg_reader" {
  type    = bool
  default = false
}
