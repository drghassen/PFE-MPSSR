variable "base_name" {
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

variable "vm_size" {
  type = string
}

variable "admin_username" {
  type = string
}

variable "admin_ssh_public_key" {
  type = string

  validation {
    condition     = can(regex("^ssh-rsa\\s+[A-Za-z0-9+/=]+(?:\\s+.*)?$", trimspace(var.admin_ssh_public_key)))
    error_message = "admin_ssh_public_key must be an RSA public key in OpenSSH format (starts with 'ssh-rsa ')."
  }
}

variable "tags" {
  type = map(string)
}

variable "admin_password" {
  description = "Linux VM admin password. Must satisfy 3/4 Azure complexity rules."
  type        = string
  sensitive   = true

  validation {
    condition = (
      length(var.admin_password) >= 12 &&
      can(regex("[a-z]", var.admin_password)) &&
      can(regex("[A-Z]", var.admin_password)) &&
      can(regex("[0-9]", var.admin_password)) &&
      can(regex("[^a-zA-Z0-9_]", var.admin_password))
    )
    error_message = "admin_password must be 12+ chars with lowercase, uppercase, digit and special char."
  }
}
