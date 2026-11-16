"""Required-field checks and partial-request merging."""

from agent.models import VMRequest

REQUIRED_REQUEST_FIELDS = (
    'operating_system',
    'compute_size',
    'region',
)


class RequirementChecker:
    """Finds missing user-required details without using the model."""

    QUESTIONS = {
        'operating_system': (
            'Which operating system should the VM use: Ubuntu or Windows?'
        ),
        'compute_size': (
            'What size should it be: small, medium, or large?'
        ),
        'region': (
            'Which AWS Region should I use? For example, us-east-1.'
        ),
    }

    def missing_fields(self, request: VMRequest) -> list[str]:
        return [
            field_name
            for field_name in REQUIRED_REQUEST_FIELDS
            if getattr(request, field_name) is None
        ]

    def next_question(self, missing_fields: list[str]) -> str:
        return self.QUESTIONS[missing_fields[0]]


def merge_request(existing: VMRequest | None, update: VMRequest) -> VMRequest:
    """Keeps known values and replaces them only with new non-null values."""
    if existing is None:
        return update

    merged_values = existing.model_dump()
    for field_name, value in update.model_dump().items():
        if value is not None:
            merged_values[field_name] = value

    return VMRequest.model_validate(merged_values)
