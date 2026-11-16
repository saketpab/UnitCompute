"""Build a reviewable VM plan without making AWS changes."""

from agent.mappings import (
    COMPUTE_SIZE_TO_INSTANCE_TYPE,
    DEFAULTS,
    OPERATING_SYSTEM_TO_IMAGE_PARAMETER,
)
from agent.models import VMPlan, VMRequest


class PlanBuilder:
    """Converts a VMRequest into a VMPlan without making AWS changes."""

    def build(self, request: VMRequest) -> VMPlan:
        self._require(request.operating_system, 'operating system')
        self._require(request.compute_size, 'compute size')
        self._require(request.region, 'AWS region')

        operating_system_config = OPERATING_SYSTEM_TO_IMAGE_PARAMETER[
            request.operating_system
        ]

        return VMPlan(
            region=request.region,
            image_ssm_parameter=operating_system_config[
                'image_ssm_parameter'
            ],
            instance_type=COMPUTE_SIZE_TO_INSTANCE_TYPE[
                request.compute_size
            ],
            disk_gb=request.disk_gb or DEFAULTS['disk_gb'],
            name=request.name or self._generate_name(request),
            purpose=request.purpose,
            subnet_id=request.subnet_id,
            security_group_id=request.security_group_id,
        )

    @staticmethod
    def _require(value: object | None, field_name: str) -> None:
        if value is None:
            raise ValueError(f'{field_name} is required.')

    @staticmethod
    def _generate_name(request: VMRequest) -> str:
        return f'unitcompute-{request.operating_system}-vm'
