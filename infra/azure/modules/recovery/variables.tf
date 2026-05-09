variable "name" {
  type = string
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "vm_ids" {
  type = list(string)
}

variable "vm_count" {
  type    = number
  default = 1
}

variable "enable_backup_protection" {
  type    = bool
  default = true
}

variable "tags" {
  type    = map(string)
  default = {}
}
