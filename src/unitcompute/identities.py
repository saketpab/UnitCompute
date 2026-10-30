"""Append-only evidence of every AWS resource identity a deployment has ever had.

Identities are first appended (and fsynced) to a per-deployment JSON-lines file and then
imported into the ``deployment_resources`` table, whose rows can never be updated or deleted.
If the database write fails (for example under lock contention) the file still holds the
evidence, and it is imported again before any plan, verification or recovery decision.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from unitcompute.db.database import to_db_time, utcnow

EVIDENCE_FILE = "identities.jsonl"
_ID = re.compile(r"^(i|vol|sg)-[0-9a-f]{8,17}$")
_TYPES = {"i": "instance", "vol": "volume", "sg": "security_group"}
_DEPLOYMENT = re.compile(r"^dep_[0-9a-f]{32}$")

# Launch-root evidence: what UnitCompute itself recorded from Terraform for the root block
# device of an instance it launched (apply outputs, Terraform root_block_device state, the
# root ID kept on the deployment row, and the migrated copies of those). Only this completes
# an instance's identity.
#
# Everything else is an observation of the present and never completes identity: the
# volume currently mapped at the root device name (which may be a replacement root, while
# the original survives detached), other attached disks, tag inventory. Observations are
# still recorded, so every observed resource must be verified gone before deletion.
ROOT_DEVICE = "root_device"
ATTACHED_DEVICE = "attached_device"
LAUNCH_ROOT_SOURCES = frozenset(
    {"apply_output", "terraform_state", "deployment_record", "migration"}
)


@dataclass(frozen=True)
class Identity:
    resource_id: str
    source: str
    parent_id: str | None = None

    @property
    def resource_type(self) -> str:
        return _TYPES[self.resource_id.split("-", 1)[0]]


def identity(resource_id: object, source: str, parent_id: object = None) -> Identity | None:
    """Build an identity from an untrusted value; anything not shaped like an ID is ignored."""
    if not isinstance(resource_id, str) or not _ID.fullmatch(resource_id):
        return None
    parent = parent_id if isinstance(parent_id, str) and _ID.fullmatch(parent_id) else None
    return Identity(resource_id, source, parent)


@dataclass(frozen=True)
class KnownIdentities:
    instances: set[str]
    volumes: dict[str, str | None]  # volume -> parent instance (if known)
    groups: set[str]
    launch_roots: dict[str, set[str]]  # instance -> root volumes recorded at/after its launch
    observed_roots: dict[str, set[str]]  # instance -> volumes seen at its root device name

    @property
    def all_ids(self) -> list[str]:
        return sorted(self.instances | set(self.volumes) | self.groups)

    def instances_without_root_disk(self) -> list[str]:
        """Instances without launch-root evidence. A current or replacement root, an attached
        disk or any existing volume cannot stand in for the launch root; there is no
        waiver. Plans and deletion stay blocked until launch evidence is recovered (for
        example by restoring the deployment's Terraform state)."""
        return sorted(i for i in self.instances if not self.launch_roots.get(i))


class IdentityLedger:
    def __init__(self, workdir_root: Path) -> None:
        self._root = workdir_root

    def _path(self, deployment_id: str) -> Path:
        if not _DEPLOYMENT.fullmatch(deployment_id):
            raise ValueError("invalid deployment id")
        return self._root / deployment_id / EVIDENCE_FILE

    def _ensure_directory(self, directory: Path) -> None:
        """Create missing directories and fsync each new entry's parent (fsync(2): syncing
        a file does not make its directory entry durable)."""
        missing = []
        current = directory
        while not current.exists():
            missing.append(current)
            current = current.parent
        for path in reversed(missing):
            with contextlib.suppress(FileExistsError):
                path.mkdir(mode=0o700)
            _fsync_directory(path.parent)

    def append_evidence(self, deployment_id: str, identities: Iterable[Identity | None]) -> int:
        rows = [i for i in identities if i is not None]
        if not rows:
            return 0
        path = self._path(deployment_id)
        self._ensure_directory(path.parent)
        now = to_db_time(utcnow())
        payload = "".join(
            json.dumps({"id": i.resource_id, "parent": i.parent_id, "source": i.source, "at": now})
            + "\n"
            for i in rows
        )
        created = not path.exists()
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            # Exclusive lock across threads and processes (worker, API, operator CLI): the
            # torn-tail check and the possibly-short write loop must not interleave.
            fcntl.flock(fd, fcntl.LOCK_EX)
            data = payload.encode()
            # A crash can leave a torn, unterminated last record. Start on a fresh line so the
            # fragment stays its own (skipped) line instead of swallowing this record.
            size = os.fstat(fd).st_size
            if size and os.pread(fd, 1, size - 1) != b"\n":
                data = b"\n" + data
            view = memoryview(data)
            while view:  # os.write may write fewer bytes than requested
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("evidence write made no progress")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)  # also releases the lock
        if created:
            _fsync_directory(path.parent)
        return len(rows)

    @staticmethod
    def missing(
        conn: sqlite3.Connection, deployment_id: str, identities: Iterable[Identity | None]
    ) -> list[Identity]:
        """Identities not (yet) present in the table, exactly as recorded (ID, parent, source)."""
        absent = []
        for item in identities:
            if item is None:
                continue
            row = conn.execute(
                "SELECT 1 FROM deployment_resources WHERE deployment_id = ? AND resource_id = ? "
                "AND IFNULL(parent_id, '') = ? AND source = ?",
                (deployment_id, item.resource_id, item.parent_id or "", item.source),
            ).fetchone()
            if row is None:
                absent.append(item)
        return absent

    def import_evidence(self, conn: sqlite3.Connection, deployment_id: str) -> int:
        imported = self._import_deployment_record(conn, deployment_id)
        path = self._path(deployment_id)
        if not path.exists():
            return imported
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                raw = json.loads(line)
            except ValueError:
                continue  # a torn final line from a crash; earlier lines are intact
            item = identity(raw.get("id"), str(raw.get("source", "evidence")), raw.get("parent"))
            if item is None:
                continue
            imported += conn.execute(
                "INSERT OR IGNORE INTO deployment_resources (deployment_id, resource_type, "
                "resource_id, parent_id, source, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    deployment_id,
                    item.resource_type,
                    item.resource_id,
                    item.parent_id,
                    item.source,
                    str(raw.get("at") or to_db_time(utcnow())),
                ),
            ).rowcount
        return imported

    @staticmethod
    def _import_deployment_record(conn: sqlite3.Connection, deployment_id: str) -> int:
        """IDs held on the deployment row are evidence too; never ignore them."""
        row = conn.execute(
            "SELECT instance_id, security_group_id, root_volume_id, updated_at "
            "FROM deployments WHERE id = ?",
            (deployment_id,),
        ).fetchone()
        if row is None:
            return 0
        imported = 0
        for item in (
            identity(row["instance_id"], "deployment_record"),
            identity(row["security_group_id"], "deployment_record"),
            identity(row["root_volume_id"], "deployment_record", row["instance_id"]),
        ):
            if item is not None:
                imported += conn.execute(
                    "INSERT OR IGNORE INTO deployment_resources (deployment_id, resource_type, "
                    "resource_id, parent_id, source, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        deployment_id,
                        item.resource_type,
                        item.resource_id,
                        item.parent_id,
                        item.source,
                        row["updated_at"],
                    ),
                ).rowcount
        return imported

    @staticmethod
    def known(conn: sqlite3.Connection, deployment_id: str) -> KnownIdentities:
        rows = conn.execute(
            "SELECT resource_type, resource_id, parent_id, source FROM deployment_resources "
            "WHERE deployment_id = ?",
            (deployment_id,),
        ).fetchall()
        instances = {r["resource_id"] for r in rows if r["resource_type"] == "instance"}
        groups = {r["resource_id"] for r in rows if r["resource_type"] == "security_group"}
        volumes: dict[str, str | None] = {}
        for r in rows:
            if r["resource_type"] == "volume":
                # A volume can appear once without and once with its parent; keep the parent.
                volumes[r["resource_id"]] = r["parent_id"] or volumes.get(r["resource_id"])
        launch_roots: dict[str, set[str]] = {}
        observed_roots: dict[str, set[str]] = {}
        for r in rows:
            if r["resource_type"] != "volume" or not r["parent_id"]:
                continue
            if r["source"] in LAUNCH_ROOT_SOURCES:
                launch_roots.setdefault(r["parent_id"], set()).add(r["resource_id"])
            elif r["source"] == ROOT_DEVICE:
                observed_roots.setdefault(r["parent_id"], set()).add(r["resource_id"])
        return KnownIdentities(instances, volumes, groups, launch_roots, observed_roots)


def _fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
