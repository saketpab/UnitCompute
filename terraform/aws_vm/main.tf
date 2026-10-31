locals {
  tags = {
    ManagedBy     = "unitcompute-vm"
    UnitComputeVm = var.vm_id
  }
  name_tags = merge(local.tags, { Name = var.name, Purpose = var.purpose })
}

resource "aws_instance" "vm" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = var.security_group_ids

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = var.disk_gb
    encrypted   = true
  }

  tags = local.name_tags

  # volume_tags tags the root volume when it is created, and keeps it in step on rename.
  volume_tags = local.name_tags
}

# Stopping and starting are edits of this one attribute, so they appear in a saved plan like any
# other change and the state always records the intended power state. force = false means a
# stop is always a clean OS shutdown.
resource "aws_ec2_instance_state" "vm" {
  instance_id = aws_instance.vm.id
  state       = var.power_state
  force       = false
}
