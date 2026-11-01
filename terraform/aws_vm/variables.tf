variable "vm_id" {
  description = "Stable identifier of this VM; tagged on every resource so leftovers can be found by tag."
  type        = string
  validation {
    condition     = can(regex("^vm-[0-9a-f]{12}$", var.vm_id))
    error_message = "vm_id must look like vm-0123456789ab."
  }
}

variable "name" {
  description = "Display name (the Name tag). Editable."
  type        = string
  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$", var.name))
    error_message = "name must be 1-63 characters: letters, digits, '.', '_' or '-', starting with a letter or digit."
  }
}

variable "purpose" {
  description = "Free-text purpose (the Purpose tag). Editable."
  type        = string
  default     = ""
  validation {
    condition     = length(var.purpose) <= 256
    error_message = "purpose must be at most 256 characters."
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", var.region))
    error_message = "region must be an AWS region name such as us-east-1."
  }
}

variable "ami_id" {
  description = "Image to launch. Fixed for the life of the VM: changing it replaces the instance."
  type        = string
  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,17}$", var.ami_id))
    error_message = "ami_id must look like ami-0123456789abcdef0."
  }
}

variable "instance_type" {
  description = "Fixed for the life of the VM (the wrapper does not edit it)."
  type        = string
}

variable "subnet_id" {
  description = "Existing subnet. No network resources are created."
  type        = string
  validation {
    condition     = can(regex("^subnet-[0-9a-f]{8,17}$", var.subnet_id))
    error_message = "subnet_id must look like subnet-0123456789abcdef0."
  }
}

variable "security_group_ids" {
  description = "Existing security groups. No rules are created or changed."
  type        = list(string)
  validation {
    condition     = length(var.security_group_ids) > 0 && alltrue([for g in var.security_group_ids : can(regex("^sg-[0-9a-f]{8,17}$", g))])
    error_message = "security_group_ids must be a non-empty list of sg-... IDs."
  }
}

variable "disk_gb" {
  description = "Root volume size in GiB. Can be grown in place, never shrunk."
  type        = number
  validation {
    condition     = floor(var.disk_gb) == var.disk_gb && var.disk_gb >= 8 && var.disk_gb <= 100
    error_message = "disk_gb must be a whole number from 8 to 100."
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
