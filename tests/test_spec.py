"""Resolving a partial VMRequest into a plannable spec."""

from __future__ import annotations

import pytest

from unitcompute_vm import InvalidRequest, MissingInputs, VMSpec, resolve_request


class FakeVMRequest:
    """Stands in for the notebook's pydantic VMRequest (anything with model_dump())."""

    def __init__(self, **fields: object) -> None:
        self.fields = {
            "operating_system": None, "compute_size": None, "region": None,
            "disk_gb": None, "name": None, "purpose": None, **fields,
        }  # fmt: skip

    def model_dump(self) -> dict[str, object]:
        return self.fields


def test_the_notebooks_own_example_is_missing_a_name() -> None:
    request = FakeVMRequest(operating_system="ubuntu", compute_size="small", region="us-east-1")
    with pytest.raises(MissingInputs) as err:
        resolve_request(request)
    assert err.value.fields == ["name"]


def test_every_missing_required_field_is_named_at_once() -> None:
    with pytest.raises(MissingInputs) as err:
        resolve_request(FakeVMRequest())
    assert err.value.fields == ["name", "operating_system", "compute_size"]
    assert "name, operating_system, compute_size" in str(err.value)


def test_region_defaults_to_us_east_1_and_disk_stays_open_for_the_image_minimum() -> None:
    spec = resolve_request({"name": "web", "operating_system": "windows", "compute_size": "large"})
    assert spec == VMSpec("web", "windows", "large", region="us-east-1", disk_gb=None, purpose="")


def test_overrides_are_kept_and_the_default_region_is_configurable() -> None:
    request = {"name": "web", "operating_system": "ubuntu", "compute_size": "medium", "disk_gb": 40}
    assert resolve_request({**request, "region": "eu-west-1"}).region == "eu-west-1"
    assert resolve_request(request, default_region="eu-west-1").region == "eu-west-1"
    assert resolve_request(request).disk_gb == 40


@pytest.mark.parametrize(
    "change",
    [
        {"region": "mars-1"},
        {"region": "US-EAST-1"},
        {"region": "us-east-1; rm -rf /"},
        {"disk_gb": 7},
        {"disk_gb": 101},
        {"disk_gb": True},
        {"name": "has space"},
        {"name": "-leading"},
        {"name": "x" * 64},
        {"operating_system": "macos"},
        {"compute_size": "huge"},
        {"purpose": "x" * 257},
    ],
)
def test_invalid_values_are_rejected(change: dict[str, object]) -> None:
    request = {"name": "web", "operating_system": "ubuntu", "compute_size": "small", **change}
    with pytest.raises(InvalidRequest):
        resolve_request(request)
