"""Runs the pinned Terraform binary with fixed argument arrays and a controlled environment."""

from __future__ import annotations

import contextlib
import logging
import os
import signal
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO

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


class _Capture:
    """Bounded capture of one stream: the first ``head_limit`` bytes, the last
    ``MAX_LOG_BYTES`` bytes, and the total length."""

    def __init__(self, head_limit: int) -> None:
        self.head_limit = head_limit
        self.head = bytearray()
        self._tail = bytearray()
        self.total = 0

    def add(self, chunk: bytes) -> None:
        self.total += len(chunk)
        room = self.head_limit - len(self.head)
        if room > 0:
            self.head += chunk[:room]
        self._tail += chunk
        if len(self._tail) > 2 * MAX_LOG_BYTES:
            del self._tail[:-MAX_LOG_BYTES]

    def tail_bytes(self) -> bytes:
        return bytes(self._tail[-MAX_LOG_BYTES:])


def _drain(stream: IO[bytes], capture: _Capture) -> None:
    try:
        while chunk := stream.read1(65536):  # type: ignore[attr-defined]
            capture.add(chunk)
    except (OSError, ValueError):
        pass  # the pipe was closed under us (timeout path)


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
        # Both pipes are drained as they are written, into bounded buffers (stdout up to the
        # output limit, plus a tail of each stream for the log), so a runaway child cannot
        # exhaust this process's memory. The child is never killed for being noisy: stopping
        # an apply mid-flight is worse than discarding its excess output.
        stdout_pipe, stderr_pipe = process.stdout, process.stderr
        if stdout_pipe is None or stderr_pipe is None:
            raise RuntimeError("Terraform pipes were not created")
        out = _Capture(head_limit=MAX_STDOUT_BYTES + 1)
        err = _Capture(head_limit=0)
        readers = [
            threading.Thread(target=_drain, args=(stdout_pipe, out), daemon=True),
            threading.Thread(target=_drain, args=(stderr_pipe, err), daemon=True),
        ]
        for reader in readers:
            reader.start()
        deadline = time.monotonic() + timeout
        try:
            process.wait(timeout=timeout)
            for reader in readers:  # EOF only once nothing else holds the pipes
                reader.join(timeout=max(0.0, deadline - time.monotonic()))
                if reader.is_alive():
                    raise subprocess.TimeoutExpired(command, timeout)
        except subprocess.TimeoutExpired:
            self._terminate(process)
            for reader in readers:
                reader.join(timeout=5)
            self._write_log(workdir, log_name, b"", b"terminated after timeout", secrets)
            raise ProvisioningTimeout(
                "terraform_timeout", f"terraform {args[0]} exceeded its {int(timeout)}s limit."
            ) from None
        self._write_log(workdir, log_name, out.tail_bytes(), err.tail_bytes(), secrets)
        if out.total > MAX_STDOUT_BYTES:
            raise ProvisioningError("terraform_output_too_large", "Terraform output was too large.")
        return RunResult(
            returncode=process.returncode,
            stdout=bytes(out.head).decode("utf-8", "replace"),
            stderr=redact(err.tail_bytes().decode("utf-8", "replace"), secrets),
        )

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        try:
            for sig, wait in ((signal.SIGINT, KILL_GRACE_SECONDS), (signal.SIGKILL, 10)):
                try:
                    os.killpg(process.pid, sig)
                except ProcessLookupError:
                    return
                try:
                    process.wait(timeout=wait)
                    return
                except subprocess.TimeoutExpired:
                    continue
        finally:
            # Anything left in the process group would keep the pipes open.
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(process.pid, signal.SIGKILL)

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
