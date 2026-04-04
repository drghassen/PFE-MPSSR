variable "base_name" {
  type = string
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "tenant_id" {
  type = string
}

variable "private_subnet_id" {
  type = string
}

variable "virtual_network_id" {
  type = string
}

variable "key_expiration_date" {
  type = string
}

variable "cmk_key_name" {
  description = "Name of the CMK used for Storage encryption."
  type        = string
  default     = "storage-cmk"
}

variable "existing_cmk_key_id" {
  description = "Existing Key Vault key identifier (https://<vault>/keys/<name>[/<version>]). If set, key creation is skipped."
  type        = string
  default     = ""

  validation {
    condition = (
      trimspace(var.existing_cmk_key_id) == "" ||
      can(regex("^https://[^/]+/keys/[^/]+(?:/[^/]+)?$", trimspace(var.existing_cmk_key_id)))
    )
    error_message = "existing_cmk_key_id must be empty or a valid Key Vault key URL."
  }
}

variable "cmk_key_type" {
  description = "CMK type. RSA-HSM requires Key Vault Premium."
  type        = string
  default     = "RSA-HSM"

  validation {
    condition     = contains(["RSA", "RSA-HSM"], var.cmk_key_type)
    error_message = "cmk_key_type must be RSA or RSA-HSM."
  }
}

variable "cmk_key_size" {
  description = "CMK key size for RSA/RSA-HSM."
  type        = number
  default     = 2048

  validation {
    condition     = contains([2048, 3072, 4096], var.cmk_key_size)
    error_message = "cmk_key_size must be one of 2048, 3072, 4096."
  }
}

variable "tags" {
  type = map(string)
}
