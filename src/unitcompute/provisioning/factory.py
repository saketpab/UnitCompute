from __future__ import annotations

from collections.abc import Sequence

from unitcompute.config import Environment, ProvisionerKind, Settings
from unitcompute.provisioning.aws import AwsEnvironment
from unitcompute.provisioning.base import Provisioner
from unitcompute.provisioning.runner import TerraformRunner
from unitcompute.provisioning.simulated import SimulatedProvisioner
from unitcompute.provisioning.terraform import TerraformProvisioner


def build_provisioner(settings: Settings, inherit_fds: Sequence[int] = ()) -> Provisioner | None:
    if settings.provisioner is ProvisionerKind.DISABLED:
        return None
    if settings.provisioner is ProvisionerKind.SIMULATED:
        if settings.environment is not Environment.DEVELOPMENT:
            raise RuntimeError("the simulated provisioner is development-only")
        return SimulatedProvisioner(settings.data_dir)
    runner = TerraformRunner(
        settings.terraform_binary,
        plugin_cache_dir=settings.terraform_plugin_cache_dir,
        inherit_fds=inherit_fds,
    )
    return TerraformProvisioner(settings, runner, AwsEnvironment(settings))
