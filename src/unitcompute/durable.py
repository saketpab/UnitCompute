"""Directory durability (fsync(2): syncing a file does not persist its directory entry).

Every creator of directories that hold recovery evidence (work roots, deployment and plan
work directories, evidence files) goes through these helpers.
"""

from __future__ import annotations

import os
from pathlib import Path


def fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def ensure_directory(directory: Path, mode: int = 0o700) -> None:
    """Create missing directories, fsyncing the parent after each creation."""
    missing = []
    current = directory
    while not current.exists():
        missing.append(current)
        current = current.parent
    for path in reversed(missing):
        try:
            path.mkdir(mode=mode)
        except FileExistsError:
            continue  # created concurrently; its creator syncs the parent
        fsync_directory(path.parent)


def create_directory(directory: Path, mode: int = 0o700) -> None:
    """Create exactly ``directory`` (which must not exist) and its ancestors, durably."""
    ensure_directory(directory.parent, mode)
    directory.mkdir(mode=mode)
    fsync_directory(directory.parent)


def fsync_chain(directory: Path, stop: Path) -> None:
    """fsync ``directory`` and each ancestor up to and including ``stop``. Used when a new
    evidence file appears, so entries created earlier (possibly by older code without
    these guarantees) are made durable too."""
    current = directory
    while True:
        fsync_directory(current)
        if current in (stop, current.parent):
            return
        current = current.parent
