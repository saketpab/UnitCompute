"""Backend-controlled mappings from simple user terms to AWS terms."""

OPERATING_SYSTEM_TO_IMAGE_PARAMETER = {
    'ubuntu': {
        'label': 'Ubuntu Server 24.04 LTS',
        'image_ssm_parameter': (
            '/aws/service/canonical/ubuntu/server/24.04/stable/current/'
            'amd64/hvm/ebs-gp3/ami-id'
        ),
    },
    'windows': {
        'label': 'Windows Server 2022',
        'image_ssm_parameter': (
            '/aws/service/ami-windows-latest/'
            'Windows_Server-2022-English-Full-Base'
        ),
    },
}

COMPUTE_SIZE_TO_INSTANCE_TYPE = {
    'small': 't3.micro',
    'medium': 't3.small',
    'large': 't3.medium',
}

DEFAULTS = {
    'disk_gb': 30,
}
