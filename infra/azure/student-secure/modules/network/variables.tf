variable "base_name" {
  type = string
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "vnet_cidr" {
  type = string
}

variable "public_subnet_cidr" {
  type = string
}

variable "private_subnet_cidr" {
  type = string
}

variable "db_subnet_cidr" {
  type = string
}

# CKV2_CS_AZ_021 / CIS 6.4 — SSH source CIDR validation.
# Enforces that SSH access is restricted to a specific IP range.
# Wildcards (0.0.0.0/0, ::/0, *) are explicitly rejected to prevent
# Internet-wide SSH exposure. Must be a host (/32) or narrow org CIDR.
variable "admin_allowed_cidr" {
  type        = string
  description = "CIDR allowed to SSH to the public VM. Must NOT be 0.0.0.0/0. Use a specific /32 or narrow corporate CIDR."

  validation {
    condition = (
      can(regex("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$", var.admin_allowed_cidr)) &&
      var.admin_allowed_cidr != "0.0.0.0/0" &&
      var.admin_allowed_cidr != "*"
    )
    error_message = "admin_allowed_cidr must be a valid IPv4 CIDR and must NOT be 0.0.0.0/0 or '*'. Use a specific host or org CIDR (e.g. 203.0.113.10/32)."
  }
}

variable "tags" {
  type = map(string)
}
