"""Runs the pinned Terraform binary with fixed argument arrays and a controlled environment."""

from __future__ import annotations

import logging
import os
import signal
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from unitcompute.durable import ensure_directory
from unitcompute.logging_setup import redact
from unitcompute.provisioning.base import ProvisioningError, ProvisioningTimeout

log = logging.getLogger(__name__)

ALLOWED_SUBCOMMANDS = frozenset(
    {"version", "init", "validate", "plan", "show", "apply", "output", "state"}
)
# "state" is read-only here: only `state pull`. Push, rm, mv and import are never run.
ALLOWED_STATE_ARGS = ("state", "pull")
MAX_STDOUT_BYTES = 8 * 1024 * 1024
MAX_LOG_BYTES = 64 * 1024
KILL_GRACE_SECONDS = 30
SAFE_PATH = "/usr/local/bin:/usr/bin:/bin"


@dataclass(frozen=True)
class RunResult:
    returncode: int
    stdout: str
    stderr: str


class TerraformRunner:
    def __init__(
        self,
        binary: Path,
        *,
        plugin_cache_dir: Path | None = None,
        inherit_fds: Sequence[int] = (),
    ) -> None:
        self.binary = binary
        self.plugin_cache_dir = plugin_cache_dir
        # The worker passes its lock file descriptor so the single-worker lock stays held
        # for as long as any Terraform child is alive, even if the worker itself dies.
        self.inherit_fds = tuple(inherit_fds)

    def base_env(self, workdir: Path) -> dict[str, str]:
        home = workdir / ".home"
        ensure_directory(home)
        env = {
            "PATH": SAFE_PATH,
            "HOME": str(home),
            "TF_IN_AUTOMATION": "1",
            "TF_INPUT": "0",
            "CHECKPOINT_DISABLE": "1",
            "TF_CLI_CONFIG_FILE": os.devnull,
            "AWS_CONFIG_FILE": os.devnull,
            "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
            "AWS_EC2_METADATA_DISABLED": "true",
        }
        if self.plugin_cache_dir is not None:
            env["TF_PLUGIN_CACHE_DIR"] = str(self.plugin_cache_dir)
        return env

    def run(
        self,
        args: Sequence[str],
        *,
        workdir: Path,
        env: Mapping[str, str],
        timeout: float,
        log_name: str,
        secrets: Sequence[str] = (),
    ) -> RunResult:
        if not args or args[0] not in ALLOWED_SUBCOMMANDS:
            raise ValueError(f"terraform subcommand {args[:1]} is not allowed")
        if args[0] == "state" and tuple(args) != ALLOWED_STATE_ARGS:
            raise ValueError(f"terraform {' '.join(args[:2])} is not allowed (only `state pull`)")
        command = [str(self.binary), *args]
        try:
            process = subprocess.Popen(  # noqa: S603 - fixed argv, shell=False
                command,
                cwd=workdir,
                env=dict(env),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                start_new_session=True,
                pass_fds=self.inherit_fds,
            )
        except OSError as exc:
            raise ProvisioningError(
                "terraform_unavailable", "The Terraform binary could not be started."
            ) from exc
        try:
            stdout_b, stderr_b = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._terminate(process)
            self._write_log(workdir, log_name, b"", b"terminated after timeout", secrets)
            raise ProvisioningTimeout(
                "terraform_timeout", f"terraform {args[0]} exceeded its {int(timeout)}s limit."
            ) from None
        self._write_log(workdir, log_name, stdout_b, stderr_b, secrets)
        if len(stdout_b) > MAX_STDOUT_BYTES:
            raise ProvisioningError("terraform_output_too_large", "Terraform output was too large.")
        return RunResult(
            returncode=process.returncode,
            stdout=stdout_b.decode("utf-8", "replace"),
            stderr=redact(stderr_b.decode("utf-8", "replace")[-MAX_LOG_BYTES:], secrets),
        )

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        for sig, wait in ((signal.SIGINT, KILL_GRACE_SECONDS), (signal.SIGKILL, 10)):
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                return
            try:
                process.communicate(timeout=wait)
                return
            except subprocess.TimeoutExpired:
                continue

    @staticmethod
    def _write_log(
        workdir: Path, name: str, stdout: bytes, stderr: bytes, secrets: Sequence[str]
    ) -> None:
        logs = workdir / "logs"
        ensure_directory(logs)
        text = (
            stdout[-MAX_LOG_BYTES:].decode("utf-8", "replace")
            + "\n--- stderr ---\n"
            + stderr[-MAX_LOG_BYTES:].decode("utf-8", "replace")
        )
        path = logs / f"{name}.log"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(redact(text, secrets))
