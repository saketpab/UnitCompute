"""Runs the Terraform CLI for one VM: state, plugin data and logs all live in that VM's folder."""

from __future__ import annotations

import json
import os
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Environment Terraform may see. AWS_* carries credentials, region and endpoint settings from the
# caller; TF_PLUGIN_CACHE_DIR lets a machine reuse downloaded providers.
_PASS_THROUGH = ("PATH", "HOME", "TF_PLUGIN_CACHE_DIR", "TMPDIR", "SSL_CERT_FILE")
INTERRUPT_GRACE_SECONDS = 120


class TerraformFailed(Exception):
    def __init__(self, args_: list[str], returncode: int | None, log: Path, interrupted: bool):
        self.returncode, self.log, self.interrupted = returncode, log, interrupted
        how = "was interrupted" if interrupted else f"exited with status {returncode}"
        super().__init__(f"terraform {args_[0]} {how}")


@dataclass(frozen=True)
class Terraform:
    binary: str
    module_dir: Path
    vm_dir: Path

    @property
    def state_path(self) -> Path:
        return self.vm_dir / "terraform.tfstate"

    def _env(self) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if k in _PASS_THROUGH or k.startswith("AWS_")}
        env.update(
            TF_DATA_DIR=str(self.vm_dir / ".terraform"),
            TF_IN_AUTOMATION="1",
            TF_INPUT="0",
            CHECKPOINT_DISABLE="1",
        )
        return env

    def run(self, args: list[str], log: Path, *, timeout: float | None = None) -> str:
        """Run ``terraform -chdir=<module> <args>``; output is appended to ``log`` and returned.

        On Ctrl-C or timeout Terraform gets exactly one SIGINT (it then finishes the operation in
        flight and saves state); it runs in its own session so a terminal Ctrl-C cannot deliver a
        second, forcing one.
        """
        log.parent.mkdir(parents=True, exist_ok=True)
        command = [self.binary, f"-chdir={self.module_dir}", *args]
        with log.open("a+b") as sink:
            sink.write(f"$ {' '.join(command)}\n".encode())
            sink.flush()
            start = sink.tell()
            process = subprocess.Popen(
                command,
                stdout=sink,
                stderr=subprocess.STDOUT,
                env=self._env(),
                start_new_session=True,
            )
            interrupted = False
            try:
                process.wait(timeout=timeout)
            except (KeyboardInterrupt, subprocess.TimeoutExpired):
                interrupted = True
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=INTERRUPT_GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            sink.seek(start)
            output = sink.read().decode(errors="replace")
        if interrupted or process.returncode != 0:
            raise TerraformFailed(args, process.returncode, log, interrupted)
        return output

    def init(self, log: Path) -> None:
        self.run(["init", "-input=false", "-no-color", "-lockfile=readonly"], log)

    def plan(self, var_file: Path, plan_file: Path, log: Path, *, destroy: bool = False) -> None:
        args = [
            "plan", "-input=false", "-no-color", "-lock-timeout=0",
            f"-state={self.state_path}", f"-var-file={var_file}", f"-out={plan_file}",
        ]  # fmt: skip
        self.run([*args, "-destroy"] if destroy else args, log)

    def show_plan(self, plan_file: Path, log: Path) -> dict[str, Any]:
        out = self.run(["show", "-json", str(plan_file)], log)
        return json.loads(out)  # type: ignore[no-any-return]

    def apply(self, plan_file: Path, log: Path, *, timeout: float | None) -> None:
        self.run(
            ["apply", "-input=false", "-no-color", "-lock-timeout=0",
             f"-state={self.state_path}", str(plan_file)],
            log,
            timeout=timeout,
        )  # fmt: skip

    def instance(self, log: Path) -> tuple[str, str] | None:
        """(instance id, root volume id) of the VM that the state tracks, if any. Read from the
        state's resources rather than outputs, which are only written when an apply completes."""
        if not self.state_path.exists():
            return None
        shown = json.loads(self.run(["show", "-json", "-no-color", str(self.state_path)], log))
        for resource in (shown.get("values") or {}).get("root_module", {}).get("resources", []):
            if resource["address"] == "aws_instance.vm":
                values = resource["values"]
                devices = values.get("root_block_device") or [{}]
                return values["id"], devices[0].get("volume_id", "")
        return None
