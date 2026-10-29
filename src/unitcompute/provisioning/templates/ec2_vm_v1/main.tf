locals {
  tags = {
    ManagedBy             = "unitcompute"
    UnitComputeDeployment = var.deployment_id
    UnitComputeOwner      = var.owner_tag
    UnitComputeTemplate   = "ec2-vm/v1"
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
    tags                  = merge(local.tags, { Name = "unitcompute-${var.name}-root" })
  }

  tags = merge(local.tags, { Name = "unitcompute-${var.name}" })
}
