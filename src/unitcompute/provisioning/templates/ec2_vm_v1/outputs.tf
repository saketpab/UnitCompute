output "instance_id" {
  value = aws_instance.vm.id
}

output "security_group_id" {
  value = aws_security_group.vm.id
}

output "root_volume_id" {
  value = aws_instance.vm.root_block_device[0].volume_id
}

output "availability_zone" {
  value = aws_instance.vm.availability_zone
}
