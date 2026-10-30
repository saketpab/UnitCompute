variable "region" {
  type = string
  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", var.region))
    error_message = "region must be an AWS region name such as us-east-1."
  }
}

variable "account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "deployment_id" {
  type = string
  validation {
    condition     = can(regex("^dep_[0-9a-f]{32}$", var.deployment_id))
    error_message = "deployment_id must be a server-generated deployment ID."
  }
}

variable "owner_tag" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{16}$", var.owner_tag))
    error_message = "owner_tag must be a 16-character hex digest."
  }
}

variable "name" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}[a-z0-9]$", var.name))
    error_message = "name must be 3-32 lowercase letters, digits or hyphens."
  }
}

variable "disk_gib" {
  type = number
  validation {
    condition     = var.disk_gib >= 8 && var.disk_gib <= 30 && floor(var.disk_gib) == var.disk_gib
    error_message = "disk_gib must be a whole number between 8 and 30."
  }
}

variable "instance_type" {
  type = string
  validation {
    condition     = var.instance_type == "t3.micro"
    error_message = "Only t3.micro is supported."
  }
}

variable "ami_id" {
  type = string
  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,17}$", var.ami_id))
    error_message = "ami_id must be an AMI ID resolved by the server."
  }
}

variable "vpc_id" {
  type = string
  validation {
    condition     = can(regex("^vpc-[0-9a-f]{8,17}$", var.vpc_id))
    error_message = "vpc_id must be a VPC ID."
  }
}

variable "subnet_id" {
  type = string
  validation {
    condition     = can(regex("^subnet-[0-9a-f]{8,17}$", var.subnet_id))
    error_message = "subnet_id must be a subnet ID."
  }
}

variable "instance_profile_name" {
  type = string
  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]{1,128}$", var.instance_profile_name))
    error_message = "instance_profile_name must be an instance profile name."
  }
}

variable "power_state" {
  type    = string
  default = "running"
  validation {
    condition     = contains(["running", "stopped"], var.power_state)
    error_message = "power_state must be running or stopped."
  }
}
