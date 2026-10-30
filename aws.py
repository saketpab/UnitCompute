import boto3

session = boto3.Session(profile_name='unicompute', region_name='us-east-2')

def get_latest_amazon_linux_ami():
    ssm_client = session.client('ssm')
    response = ssm_client.get_parameter(Name='/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64')
    return response['Parameter']['Value']

def create_linux_ec2() -> str | None:
    ec2_client = session.client('ec2')
    ami_id = get_latest_amazon_linux_ami()
    
    response = ec2_client.run_instances(
        ImageId=ami_id,
        InstanceType='t3.micro',
        MinCount=1,
        MaxCount=1,
        KeyName='default'
    )
    
    instance_id = response['Instances'][0]['InstanceId']
    if not instance_id:
        print('Failed to create EC2 instance')
        return None
    print(f'Created EC2 instance with ID: {instance_id}')
    return instance_id

instance_id = create_linux_ec2()