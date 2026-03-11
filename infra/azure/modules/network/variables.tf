variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "tags" {
  type = map(string)
}

variable "vnet_cidr" {
  type    = string
  default = "10.42.0.0/16"
}

variable "app_subnet_cidr" {
  type    = string
  default = "10.42.1.0/24"
}

variable "data_subnet_cidr" {
  type    = string
  default = "10.42.2.0/24"
}
