variable "name" {
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

variable "user_assigned_identity_id" {
  type = string
}

variable "image" {
  type    = string
  default = "mcr.microsoft.com/azuredocs/aci-helloworld:latest"
}

variable "cpu" {
  type    = number
  default = 1
}

variable "memory" {
  type    = number
  default = 1.5
}

variable "tags" {
  type    = map(string)
  default = {}
}
