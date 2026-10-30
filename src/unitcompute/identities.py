"""Append-only evidence of every AWS resource identity a deployment has ever had.

Identities are first appended (and fsynced) to a per-deployment JSON-lines file and then
imported into the ``deployment_resources`` table, whose rows can never be updated or deleted.
If the database write fails (for example under lock contention) the file still holds the
evidence, and it is imported again before any plan, verification or recovery decision.
"""

from __future__ import annotations

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

# Sources that positively establish a volume as an instance's ROOT disk (when the row also
# names the parent instance): the template output for the root block device, Terraform's
# root_block_device state, the root ID kept on the deployment row, the instance's
# RootDeviceName mapping, or an operator-recorded root volume whose existence AWS confirmed.
# Disks merely attached to an instance (ATTACHED_DEVICE, and the pre-round-3
# "instance_block_devices" source) are never root evidence.
ROOT_DEVICE = "root_device"
ATTACHED_DEVICE = "attached_device"
OPERATOR_ROOT_VOLUME = "operator_root_volume"
ROOT_SOURCES = frozenset(
    {
        "apply_output",
        "terraform_state",
        "deployment_record",
        "migration",
        ROOT_DEVICE,
        OPERATOR_ROOT_VOLUME,
    }
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
    root_volumes: dict[str, set[str]]  # instance -> volumes positively known as its root

    @property
    def all_ids(self) -> list[str]:
        return sorted(self.instances | set(self.volumes) | self.groups)

    def instances_without_root_disk(self) -> list[str]:
        """Instances whose root disk identity was never positively established.

        There is no waiver: until root evidence exists, plans and deletion stay blocked."""
        return sorted(i for i in self.instances if not self.root_volumes.get(i))


class IdentityLedger:
    def __init__(self, workdir_root: Path) -> None:
        self._root = workdir_root

    def _path(self, deployment_id: str) -> Path:
        if not _DEPLOYMENT.fullmatch(deployment_id):
            raise ValueError("invalid deployment id")
        return self._root / deployment_id / EVIDENCE_FILE

    def append_evidence(self, deployment_id: str, identities: Iterable[Identity | None]) -> int:
        rows = [i for i in identities if i is not None]
        if not rows:
            return 0
        path = self._path(deployment_id)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        now = to_db_time(utcnow())
        payload = "".join(
            json.dumps({"id": i.resource_id, "parent": i.parent_id, "source": i.source, "at": now})
            + "\n"
            for i in rows
        )
        data = payload.encode()
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
        try:
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
            os.close(fd)
        return len(rows)

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
        root_volumes: dict[str, set[str]] = {}
        for r in rows:
            if r["resource_type"] == "volume" and r["parent_id"] and r["source"] in ROOT_SOURCES:
                root_volumes.setdefault(r["parent_id"], set()).add(r["resource_id"])
        return KnownIdentities(instances, volumes, groups, root_volumes)
