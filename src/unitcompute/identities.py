"""Append-only evidence of every AWS resource identity a deployment has ever had.

Identities are first appended (and fsynced) to a per-deployment JSON-lines file and then
imported into the ``deployment_resources`` table, whose rows can never be updated or deleted.
If the database write fails (for example under lock contention) the file still holds the
evidence, and it is imported again before any plan, verification or recovery decision.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import sqlite3
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from unitcompute.db.database import to_db_time, utcnow
from unitcompute.durable import ensure_directory, fsync_chain

EVIDENCE_FILE = "identities.jsonl"
READ_LOCK_TIMEOUT_SECONDS = 30.0
_ID = re.compile(r"^(i|vol|sg)-[0-9a-f]{8,17}$")
_TYPES = {"i": "instance", "vol": "volume", "sg": "security_group"}
_DEPLOYMENT = re.compile(r"^dep_[0-9a-f]{32}$")

# Launch-root evidence: the root volume recorded from the very apply that launched the
# instance (its outputs, or the state that apply stored, read without a refresh). Only this
# completes an instance's identity.
#
# Everything else is an observation and never completes identity:
# - Terraform plan prior_state ("terraform_state"): it is refreshed from AWS, so after an
#   out-of-band root replacement it names the replacement, not the launch disk;
# - the volume currently at the root device name, other attached disks, tag inventory;
# - outputs/state of an apply that did not itself create the instance.
# Observations are still recorded, so every observed resource must be verified gone.
ROOT_DEVICE = "root_device"
ATTACHED_DEVICE = "attached_device"
LAUNCH_OUTPUT = "launch_output"
LAUNCH_STATE = "launch_state"
LAUNCH_ROOT_SOURCES = frozenset({LAUNCH_OUTPUT, LAUNCH_STATE})
# Written by earlier versions (or copied by migrations) from apply outputs without recording
# which apply produced them. Earlier versions recorded outputs from every create-kind apply
# that ran Terraform, including failed repairs, and those outputs are refreshed values. So
# they count as launch evidence only when the deployment's history has exactly one
# create-kind apply that ran Terraform, it succeeded, and its plan created the instance.
# Success counts or a later no-op apply prove nothing.
LEGACY_ROOT_SOURCES = frozenset({"apply_output", "deployment_record", "migration"})
# Disks seen attached somewhere other than the root device are never root candidates.
NON_ROOT_SOURCES = frozenset({ATTACHED_DEVICE, "instance_block_devices"})
_SOURCE = re.compile(r"^[a-z_]{1,64}$")


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
class Imported:
    rows: int
    corrupt: int


def _parse_record(line: str) -> tuple[Identity | None, str]:
    try:
        raw = json.loads(line)
    except ValueError:
        return None, ""
    if not isinstance(raw, dict):
        return None, ""
    source, parent, at = raw.get("source"), raw.get("parent"), raw.get("at")
    if not isinstance(source, str) or not _SOURCE.fullmatch(source):
        return None, ""
    if parent is not None and not isinstance(parent, str):
        return None, ""
    item = identity(raw.get("id"), source, parent)
    if item is None or (parent is not None and item.parent_id is None):
        return None, ""
    return item, at if isinstance(at, str) else to_db_time(utcnow())


class EvidenceBusy(TimeoutError):
    """An append held the evidence file's lock too long. Transient: never corruption."""


def _read_locked(path: Path, timeout: float = READ_LOCK_TIMEOUT_SECONDS) -> bytes:
    """Read under a shared lock, so an append in progress (which holds the exclusive lock
    through its short-write loop) is never mistaken for a torn or corrupt record."""
    fd = os.open(path, os.O_RDONLY)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise EvidenceBusy(f"evidence file {path.name} stayed locked") from None
                time.sleep(0.05)
        chunks = []
        while chunk := os.read(fd, 1 << 20):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class KnownIdentities:
    instances: set[str]
    volumes: dict[str, str | None]  # volume -> parent instance (if known)
    groups: set[str]
    launch_roots: dict[str, set[str]]  # instance -> root volumes recorded at/after its launch
    observed_roots: dict[str, set[str]]  # instance -> root volumes seen but not at launch

    @property
    def all_ids(self) -> list[str]:
        return sorted(self.instances | set(self.volumes) | self.groups)

    def instances_without_root_disk(self) -> list[str]:
        """Instances without launch-root evidence. A current or replacement root, an attached
        disk or any existing volume cannot stand in for the launch root; there is no
        waiver. Plans and deletion stay blocked until launch evidence is recorded."""
        return sorted(i for i in self.instances if not self.launch_roots.get(i))


def _legacy_outputs_have_provenance(conn: sqlite3.Connection, deployment_id: str) -> bool:
    ran = conn.execute(
        "SELECT jobs.status, plans.preview_json FROM jobs JOIN plans ON plans.id = jobs.plan_id "
        "WHERE jobs.deployment_id = ? AND jobs.kind = 'apply' AND plans.kind = 'create' "
        # Jobs that reached Terraform: 'failed' apply jobs failed their pre-apply checks in
        # every version, so never ran it; 'queued' ones have not run yet.
        "AND jobs.status IN ('succeeded', 'recovery_required', 'running')",
        (deployment_id,),
    ).fetchall()
    if len(ran) != 1 or ran[0]["status"] != "succeeded":
        return False
    try:
        preview = json.loads(ran[0]["preview_json"] or "")
    except ValueError:
        return False
    changes = preview.get("changes") if isinstance(preview, dict) else None
    return isinstance(changes, list) and any(
        isinstance(c, dict)
        and c.get("address") == "aws_instance.vm"
        and c.get("action") == "create"
        for c in changes
    )


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
        ensure_directory(path.parent)
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
            # The new file's entry, and every directory entry above it up to the data
            # directory, must survive a crash even if an earlier creator did not sync them.
            fsync_chain(path.parent, self._root.parent)
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

    def import_evidence(self, conn: sqlite3.Connection, deployment_id: str) -> Imported:
        """Import every valid record. Invalid records (torn writes, corruption, wrong shapes)
        are counted, never guessed at; the caller treats any as missing evidence for this
        deployment only."""
        rows = self._import_deployment_record(conn, deployment_id)
        corrupt = 0
        path = self._path(deployment_id)
        if not path.exists():
            return Imported(rows, corrupt)
        for line in _read_locked(path).decode("utf-8", errors="replace").splitlines():
            item, recorded_at = _parse_record(line)
            if item is None:
                corrupt += 1
                continue
            rows += conn.execute(
                "INSERT OR IGNORE INTO deployment_resources (deployment_id, resource_type, "
                "resource_id, parent_id, source, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    deployment_id,
                    item.resource_type,
                    item.resource_id,
                    item.parent_id,
                    item.source,
                    recorded_at,
                ),
            ).rowcount
        return Imported(rows, corrupt)

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
        legacy_trusted = _legacy_outputs_have_provenance(conn, deployment_id)
        launch_roots: dict[str, set[str]] = {}
        observed_roots: dict[str, set[str]] = {}
        for r in rows:
            if r["resource_type"] != "volume" or not r["parent_id"]:
                continue
            launch = r["source"] in LAUNCH_ROOT_SOURCES or (
                legacy_trusted and r["source"] in LEGACY_ROOT_SOURCES
            )
            if launch:
                launch_roots.setdefault(r["parent_id"], set()).add(r["resource_id"])
            elif r["source"] not in NON_ROOT_SOURCES:
                observed_roots.setdefault(r["parent_id"], set()).add(r["resource_id"])
        return KnownIdentities(instances, volumes, groups, launch_roots, observed_roots)
