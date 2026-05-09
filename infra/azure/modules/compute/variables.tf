variable "name_prefix" {
  type = string
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "public_ip_id" {
  type = string
}

variable "assign_public_ip" {
  type    = bool
  default = true
}

variable "vm_count" {
  type    = number
  default = 1
}

variable "vm_size" {
  type    = string
  default = "Standard_B2s"
}

variable "admin_username" {
  type    = string
  default = "azureuser"
}

variable "admin_ssh_public_key" {
  type      = string
  sensitive = true
}

variable "boot_diagnostics_storage_uri" {
  type = string
}

variable "user_assigned_identity_id" {
  type = string
}

variable "encryption_at_host_enabled" {
  type    = bool
  default = true
}

variable "enable_trusted_launch" {
  type    = bool
  default = false
}

variable "tags" {
  type    = map(string)
  default = {}
}
