variable "name" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "location" {
  type = string
}

variable "container_name" {
  type    = string
  default = "lab-artifacts"
}

variable "allowed_subnet_ids" {
  type    = list(string)
  default = []
}

variable "allowed_ip_rules" {
  type    = list(string)
  default = []
}

variable "tags" {
  type    = map(string)
  default = {}
}
