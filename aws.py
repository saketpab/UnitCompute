import boto3
import os
import dotenv

dotenv.load_dotenv('.env')

session = boto3.Session(profile_name='unicompute', region_name='us-east-2')
ssm_client = session.client('ssm')
ec2_client = session.client('ec2')

def get_latest_amazon_linux_ami() -> str:
    """Retrieve the latest Amazon Linux 2023 AMI ID from AWS Systems Manager Parameter Store."""
    response = ssm_client.get_parameter(Name='/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64')
    return response['Parameter']['Value']

def _describe_ec2_instance_type(instance_type: str) -> dict:
    """Retrieve information about a specific EC2 instance type.
    
    Returns a dictionary containing the instance type, number of vCPUs, and memory size in MiB.
    Returns empty dictionary if the instance type is not found.
    """
    response = ec2_client.describe_instance_types(InstanceTypes=[instance_type])
    if 'InstanceTypes' in response and len(response['InstanceTypes']) > 0:
        instance_info = response['InstanceTypes'][0]
        return {
            'InstanceType': instance_info['InstanceType'],
            'vCPUs': instance_info['VCpuInfo']['DefaultVCpus'],
            'MemoryMiB': instance_info['MemoryInfo']['SizeInMiB']
        }
    else:
        print(f'No information found for instance type: {instance_type}')
        return {}

def _get_ebs_volume_size(volume_id: str) -> int:
    """Retrieve the size of an EBS volume in GB given its volume ID."""
    response = ec2_client.describe_volumes(VolumeIds=[volume_id])
    if 'Volumes' in response and len(response['Volumes']) > 0:
        volume_info = response['Volumes'][0]
        return volume_info['Size']
    else:
        print(f'No information found for volume ID: {volume_id}')
        return 0

def _get_instance_storage_size(instance: dict) -> int:
    """Calculate the total storage size in GB for an EC2 instance based on its block device mappings."""
    if 'BlockDeviceMappings' in instance and len(instance['BlockDeviceMappings']) > 0:
        total_storage = 0
        for block_device in instance['BlockDeviceMappings']:
            if 'Ebs' in block_device and 'VolumeId' in block_device['Ebs']:
                total_storage += _get_ebs_volume_size(block_device['Ebs']['VolumeId'])
        return total_storage
    return 0

def _list_ec2_instances() -> list:
    """List all EC2 instances in the current AWS account and region, along with their details."""
    response = ec2_client.describe_instances()
    instances = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instance_type_info = _describe_ec2_instance_type(instance['InstanceType'])
            instances.append({
                'InstanceId': instance['InstanceId'],
                'State': instance['State']['Name'],
                'PublicIpAddress': instance.get('PublicIpAddress', None),
                'vCPUs': instance_type_info.get('vCPUs', None),
                'MemoryMiB': instance_type_info.get('MemoryMiB', None),
                'StorageGB': _get_instance_storage_size(instance),
                'Platform': instance.get('PlatformDetails', None)
            })
    return instances

def create_linux_ec2(ssd_gb) -> str | None:
    """Create a new Amazon Linux 2023 EC2 instance with the specified SSD size in GB.
    Returns the instance ID of the newly created instance, or None if creation failed."""
    ami_id = get_latest_amazon_linux_ami()
    
    response = ec2_client.run_instances(
        ImageId=ami_id,
        InstanceType='t3.micro',
        MinCount=1,
        MaxCount=1,
        KeyName=os.getenv('AWS_EC2_KEYNAME'),
        SecurityGroupIds=[os.getenv('AWS_EC2_SECURITY_GROUP_ID')],
        BlockDeviceMappings=[
            {
                'DeviceName': '/dev/xvda',
                'Ebs': {
                    'VolumeSize': ssd_gb,
                    'VolumeType': 'gp3',
                    'DeleteOnTermination': True
                }
            }
        ]
    )
    
    instance_id = response['Instances'][0]['InstanceId']
    if not instance_id:
        print('Failed to create EC2 instance')
        return None
    print(f'Created EC2 instance with ID: {instance_id}')
    return instance_id

def pause_ec2(instance_id: str) -> dict:
    """Pause (stop) an EC2 instance given its instance ID.
    Returns the response from the stop_instances API call."""
    response = ec2_client.stop_instances(InstanceIds=[instance_id])
    print(f'Paused EC2 instance with ID: {instance_id}')
    return response

def resume_ec2(instance_id: str) -> dict:
    """Resume (start) an EC2 instance given its instance ID.
    Returns the response from the start_instances API call."""
    response = ec2_client.start_instances(InstanceIds=[instance_id])
    print(f'Resumed EC2 instance with ID: {instance_id}')
    return response

def reboot_ec2(instance_id: str) -> dict:
    """Reboot an EC2 instance given its instance ID.
    Returns the response from the reboot_instances API call."""
    response = ec2_client.reboot_instances(InstanceIds=[instance_id])
    print(f'Rebooted EC2 instance with ID: {instance_id}')
    return response

def terminate_ec2(instance_id: str) -> dict:
    """Terminate an EC2 instance given its instance ID.
    Returns the response from the terminate_instances API call."""
    response = ec2_client.terminate_instances(InstanceIds=[instance_id])
    print(f'Terminated EC2 instance with ID: {instance_id}')
    return response

# instance_id = create_linux_ec2(ssd_gb=16)
list_of_instances = _list_ec2_instances()
print(list_of_instances)