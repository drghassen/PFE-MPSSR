variable "base_name" {
  type = string
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "key_vault_id" {
  type = string
}

variable "key_vault_key_id" {
  type     = string
  nullable = true
  default  = null

  validation {
    condition = (
      trimspace(var.key_vault_key_id != null ? var.key_vault_key_id : "") == "" ||
      can(
        regex(
          "^https://[^/]+/keys/[^/]+(?:/[^/]+)?$",
          trimspace(var.key_vault_key_id != null ? var.key_vault_key_id : ""),
        )
      )
    )
    error_message = "key_vault_key_id must be null/empty or a valid Key Vault key URL: https://<vault>/keys/<name>[/<version>]."
  }
}

variable "virtual_network_id" {
  type = string
}

variable "private_subnet_id" {
  type = string
}

variable "storage_allowed_subnet_ids" {
  type = list(string)
}

variable "tags" {
  type = map(string)
}
