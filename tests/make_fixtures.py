"""Regenerate tests/fixtures/terraform_plan_{create,update}.json with the pinned Terraform.

    uv run python tests/make_fixtures.py

Needs the terraform binary (and a populated TF_PLUGIN_CACHE_DIR to stay offline).
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from terraform_helpers import create_plan, default_template, update_plan
from test_policy import AMI, SPEC, TARGETS

FIXTURES = Path(__file__).parent / "fixtures"
EDITED = replace(SPEC, name="renamed", disk_gib=12, power_state="stopped")


def build(binary: str) -> dict[str, dict[str, object]]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        create = create_plan(binary, default_template(), root / "create", SPEC, TARGETS, AMI)
        update = update_plan(
            binary, default_template(), root / "update", SPEC, EDITED, TARGETS, AMI
        )
    return {"terraform_plan_create.json": create, "terraform_plan_update.json": update}


if __name__ == "__main__":
    terraform = shutil.which("terraform") or str(Path.home() / ".local/bin/terraform")
    for name, plan in build(terraform).items():
        (FIXTURES / name).write_text(json.dumps(plan, indent=1, sort_keys=True) + "\n")
        print("wrote", name)
