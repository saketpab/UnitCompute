locals {
  tags = {
    ManagedBy             = "unitcompute"
    UnitComputeDeployment = var.deployment_id
    UnitComputeOwner      = var.owner_tag
    UnitComputeTemplate   = "ec2-vm/v2"
  }
}

# Dedicated per-deployment security group: no inbound rules; outbound HTTPS only, which is
# what the SSM Agent needs to reach Systems Manager endpoints. The empty ingress list is
# authoritative, so rules added out of band show up as drift.
resource "aws_security_group" "vm" {
  name        = "unitcompute-${var.deployment_id}"
  description = "UnitCompute ${var.deployment_id}: no inbound, HTTPS outbound for SSM"
  vpc_id      = var.vpc_id

  ingress = []

  egress = [{
    description      = "HTTPS for SSM Agent and package repositories"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = []
    prefix_list_ids  = []
    security_groups  = []
    self             = false
  }]

  tags = merge(local.tags, { Name = "unitcompute-${var.name}" })
}

resource "aws_instance" "vm" {
  ami                         = var.ami_id
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [aws_security_group.vm.id]
  iam_instance_profile        = var.instance_profile_name
  associate_public_ip_address = true
  monitoring                  = false

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  credit_specification {
    cpu_credits = "standard"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.disk_gib
    encrypted             = true
    delete_on_termination = true
  }

  # volume_tags (not root_block_device.tags) are sent as RunInstances TagSpecifications,
  # so the root volume is tagged at creation, as the execution IAM policies require.
  # root_block_device.tags would be applied by a separate CreateTags call after launch.
  volume_tags = merge(local.tags, { Name = "unitcompute-${var.name}-root" })

  tags = merge(local.tags, { Name = "unitcompute-${var.name}" })
}

# Power state is part of the reviewed lifecycle: stopping and starting are Terraform updates of
# this one attribute, so they are previewed, approved by exact plan hash, applied under the same
# state lock and recorded in the same state as every other change. force stays false: a stop
# is always a clean OS shutdown, never a forced one.
resource "aws_ec2_instance_state" "vm" {
  instance_id = aws_instance.vm.id
  state       = var.power_state
  force       = false
}
