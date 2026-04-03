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
