# Offline module tests: the AWS provider is mocked, so no credentials or API calls are used.
mock_provider "aws" {}

variables {
  region                = "us-east-1"
  account_id            = "123456789012"
  deployment_id         = "dep_0123456789abcdef0123456789abcdef"
  owner_tag             = "0123456789abcdef"
  name                  = "demo"
  disk_gib              = 8
  instance_type         = "t3.micro"
  ami_id                = "ami-0123456789abcdef0"
  vpc_id                = "vpc-0123456789abcdef0"
  subnet_id             = "subnet-0123456789abcdef0"
  instance_profile_name = "unitcompute-ssm"
}

run "secure_defaults" {
  command = plan

  assert {
    condition     = aws_instance.vm.metadata_options[0].http_tokens == "required"
    error_message = "IMDSv2 must be required"
  }
  assert {
    condition     = aws_instance.vm.metadata_options[0].http_put_response_hop_limit == 1
    error_message = "IMDS hop limit must be 1"
  }
  assert {
    condition     = aws_instance.vm.credit_specification[0].cpu_credits == "standard"
    error_message = "cpu_credits must be standard"
  }
  assert {
    condition     = aws_instance.vm.root_block_device[0].encrypted && aws_instance.vm.root_block_device[0].delete_on_termination
    error_message = "root disk must be encrypted and deleted on termination"
  }
  assert {
    condition     = aws_instance.vm.root_block_device[0].volume_type == "gp3" && aws_instance.vm.root_block_device[0].volume_size == 8
    error_message = "root disk must be the requested gp3 size"
  }
  assert {
    condition     = aws_instance.vm.associate_public_ip_address && aws_instance.vm.user_data == null
    error_message = "public IPv4 without user data"
  }
  assert {
    condition     = length(aws_security_group.vm.ingress) == 0
    error_message = "no inbound rules"
  }
  assert {
    condition     = length(aws_security_group.vm.egress) == 1 && one(aws_security_group.vm.egress).from_port == 443 && one(aws_security_group.vm.egress).to_port == 443 && one(aws_security_group.vm.egress).protocol == "tcp"
    error_message = "egress must be HTTPS only"
  }
  assert {
    condition     = aws_instance.vm.tags["UnitComputeDeployment"] == var.deployment_id && aws_security_group.vm.tags["UnitComputeDeployment"] == var.deployment_id
    error_message = "resources must be tagged with the deployment"
  }
  assert {
    condition     = aws_instance.vm.volume_tags["UnitComputeDeployment"] == var.deployment_id && aws_instance.vm.volume_tags["ManagedBy"] == "unitcompute"
    error_message = "volumes must be tagged at creation (volume_tags)"
  }
  assert {
    condition     = aws_instance.vm.root_block_device[0].tags == null
    error_message = "root_block_device.tags are applied after launch; use volume_tags"
  }
}

run "rejects_large_disk" {
  command = plan
  variables {
    disk_gib = 31
  }
  expect_failures = [var.disk_gib]
}

run "rejects_small_disk" {
  command = plan
  variables {
    disk_gib = 7
  }
  expect_failures = [var.disk_gib]
}

run "rejects_other_instance_type" {
  command = plan
  variables {
    instance_type = "m5.large"
  }
  expect_failures = [var.instance_type]
}

run "rejects_malformed_region" {
  command = plan
  variables {
    region = "Europe/Paris"
  }
  expect_failures = [var.region]
}

run "accepts_other_well_formed_region" {
  command = plan
  variables {
    region = "eu-west-1"
  }
}

run "power_state_defaults_to_running" {
  command = plan

  assert {
    condition     = aws_ec2_instance_state.vm.state == "running"
    error_message = "a new VM must be running"
  }
  assert {
    condition     = aws_ec2_instance_state.vm.force == false
    error_message = "power changes must never be forced"
  }
}

run "power_state_can_be_stopped" {
  command = plan
  variables {
    power_state = "stopped"
  }

  assert {
    condition     = aws_ec2_instance_state.vm.state == "stopped"
    error_message = "power_state must drive the state resource"
  }
}

run "rejects_other_power_states" {
  command = plan
  variables {
    power_state = "hibernated"
  }
  expect_failures = [var.power_state]
}

run "rejects_bad_name" {
  command = plan
  variables {
    name = "x; rm -rf /"
  }
  expect_failures = [var.name]
}
