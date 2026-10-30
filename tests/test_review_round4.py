"""Regressions for the fourth independent review round of 8cf2e5d.

Adapted from security4 ``test_security4_independent.py`` and reliability4
``test_reliability_review4.py``. Each scenario is replayed end to end through the API,
worker and AWS lookup paths, asserting the safe outcome. IDs match
docs/verification-ledger.md.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage

from conftest import FakeClock, Harness, approve_current, auth, create_and_plan
from test_review_round2 import (
    _AwsBacked,
    _client,
    _detail,
    _replan,
    _restore_terraform_state,
    _schema_v1_deployment,
)
from test_review_round3 import _legacy_retained_root
from unitcompute.agent.fake import ScriptedChatModel
from unitcompute.agent.service import AgentService
from unitcompute.auth import Principal
from unitcompute.db import database
from unitcompute.db.database import Database
from unitcompute.identities import IdentityLedger, identity
from unitcompute.logging_setup import redact
from unitcompute.provisioning.base import ProvisioningError
from unitcompute.schemas import AgentMessageRequest
from unitcompute.worker import Worker

ALICE = Principal(subject="dev:alice", auth_method="dev")
ROOT = Path(__file__).resolve().parents[1]


def _quota_held(client: Any) -> bool:
    response = client.post("/deployments", json={"name": "next", "disk_gib": 8}, headers=auth())
    return bool(response.status_code == 409)


# ------------------ R4-1/R4-2: only launch evidence completes historical root identity


def test_r4_1_unrelated_volume_cannot_complete_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, moto_env: Any
) -> None:
    """Security reproduction without the removed operator command: an unrelated existing
    volume, even tagged for the deployment, never completes the historical root."""
    ec2 = moto_env
    iid, real_root, _db, dep, client, h = _legacy_retained_root(tmp_path, monkeypatch, ec2)
    arbitrary = ec2.create_volume(
        AvailabilityZone="us-east-1a",
        Size=8,
        TagSpecifications=[
            {"ResourceType": "volume", "Tags": [{"Key": "UnitComputeDeployment", "Value": dep}]}
        ],
    )["VolumeId"]
    with client:
        _, pending = _replan(h, _AwsBacked(h), dep, "deletion-plan")
        assert pending["current_plan"]["error"]["code"] == "identity_incomplete"
        ec2.delete_volume(VolumeId=arbitrary)
        _, pending = _replan(h, _AwsBacked(h), dep, "deletion-plan")
        assert pending["current_plan"]["error"]["code"] == "identity_incomplete"
        assert iid in pending["current_plan"]["error"]["message"]
        assert ec2.describe_volumes(VolumeIds=[real_root])["Volumes"][0]["State"] == "available"
        assert _quota_held(client)


def test_r4_1_known_non_root_disk_cannot_complete_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, moto_env: Any
) -> None:
    """Reliability reproduction: root detached, data disk attached; nothing completes it."""
    ec2 = moto_env
    vm = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        BlockDeviceMappings=[
            {"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 8, "DeleteOnTermination": False}}
        ],
    )["Instances"][0]
    iid, original = vm["InstanceId"], vm["BlockDeviceMappings"][0]["Ebs"]["VolumeId"]
    ec2.stop_instances(InstanceIds=[iid])
    ec2.detach_volume(VolumeId=original, InstanceId=iid, Device="/dev/sda1")
    data = ec2.create_volume(AvailabilityZone=vm["Placement"]["AvailabilityZone"], Size=8)[
        "VolumeId"
    ]
    ec2.attach_volume(VolumeId=data, InstanceId=iid, Device="/dev/sdf")
    settings, db, dep = _schema_v1_deployment(tmp_path, monkeypatch, iid)
    client, h = _client(settings, db, FakeClock())
    with client:
        _replan(h, _AwsBacked(h), dep, "deletion-plan")
        ec2.terminate_instances(InstanceIds=[iid])
        ec2.delete_volume(VolumeId=data)
        _, pending = _replan(h, _AwsBacked(h), dep, "deletion-plan")
        assert pending["current_plan"]["error"]["code"] == "identity_incomplete"
        assert ec2.describe_volumes(VolumeIds=[original])["Volumes"][0]["State"] == "available"
        assert _quota_held(client)


def test_r4_2_replacement_root_does_not_complete_historical_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, moto_env: Any
) -> None:
    """Security reproduction: a replacement mounted at the root device name (as AWS root
    replacement does, retaining the original) is an observation, not the launch root."""
    ec2 = moto_env
    vm = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        BlockDeviceMappings=[
            {"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 8, "DeleteOnTermination": False}}
        ],
    )["Instances"][0]
    iid, original = vm["InstanceId"], vm["BlockDeviceMappings"][0]["Ebs"]["VolumeId"]
    settings, db, dep = _schema_v1_deployment(tmp_path, monkeypatch, iid)
    ec2.stop_instances(InstanceIds=[iid])
    ec2.detach_volume(VolumeId=original, InstanceId=iid, Device="/dev/sda1")
    replacement = ec2.create_volume(AvailabilityZone=vm["Placement"]["AvailabilityZone"], Size=8)[
        "VolumeId"
    ]
    ec2.attach_volume(VolumeId=replacement, InstanceId=iid, Device="/dev/sda1")
    client, h = _client(settings, db, FakeClock())
    with client:
        _, pending = _replan(h, _AwsBacked(h), dep, "deletion-plan")
        assert pending["current_plan"]["error"]["code"] == "identity_incomplete"
        with db.read() as conn:
            known = IdentityLedger.known(conn, dep)
        assert known.observed_roots == {iid: {replacement}}
        assert known.launch_roots == {}
        ec2.terminate_instances(InstanceIds=[iid])
        ec2.delete_volume(VolumeId=replacement)
        _, pending = _replan(h, _AwsBacked(h), dep, "deletion-plan")
        assert pending["current_plan"]["error"]["code"] == "identity_incomplete"
        assert ec2.describe_volumes(VolumeIds=[original])["Volumes"][0]["State"] == "available"
        assert _quota_held(client)


def seed_launch_history(db: Database, dep: str, owner: str = "dev:alice") -> None:
    """The legacy provenance round 6 requires: the deployment's only create-kind apply that
    ran Terraform succeeded and its plan created the VM."""
    now = "2026-10-01T00:00:00+00:00"
    plan_id = "plan_" + "7" * 32
    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO plans (id, deployment_id, owner_id, kind, status, provisioner, "
            "config_hash, region, state_key, template_version, preview_json, created_at) "
            "VALUES (?, ?, ?, 'create', 'applied', 'simulated', 'h', 'us-east-1', 'k', "
            "'ec2-vm/v1', ?, ?)",
            (
                plan_id,
                dep,
                owner,
                json.dumps({"changes": [{"address": "aws_instance.vm", "action": "create"}]}),
                now,
            ),
        )
        conn.execute(
            "INSERT INTO jobs (id, owner_id, deployment_id, plan_id, kind, status, "
            "payload_hash, created_at) VALUES (?, ?, ?, ?, 'apply', 'succeeded', 'h', ?)",
            ("job_" + "7" * 32, owner, dep, plan_id, now),
        )


def test_r4_2_launch_evidence_plus_replacement_requires_both_gone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, moto_env: Any
) -> None:
    """With the launch root known, a later replacement root is also tracked: deletion
    completes only after both the original and the replacement are gone."""
    ec2 = moto_env
    vm = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        BlockDeviceMappings=[
            {"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 8, "DeleteOnTermination": False}}
        ],
    )["Instances"][0]
    iid, original = vm["InstanceId"], vm["BlockDeviceMappings"][0]["Ebs"]["VolumeId"]
    settings, db, dep = _schema_v1_deployment(tmp_path, monkeypatch, iid, volume=original)
    seed_launch_history(db, dep)
    ec2.stop_instances(InstanceIds=[iid])
    ec2.detach_volume(VolumeId=original, InstanceId=iid, Device="/dev/sda1")
    replacement = ec2.create_volume(AvailabilityZone=vm["Placement"]["AvailabilityZone"], Size=8)[
        "VolumeId"
    ]
    ec2.attach_volume(VolumeId=replacement, InstanceId=iid, Device="/dev/sda1")
    client, h = _client(settings, db, FakeClock())
    with client:
        _restore_terraform_state(h, dep, iid, original)
        _, pending = _replan(h, _AwsBacked(h), dep, "deletion-plan")
        # The replacement observed at the root device is outside Terraform state.
        assert pending["current_plan"]["status"] == "rejected"
        assert replacement in pending["current_plan"]["error"]["message"]
        ec2.terminate_instances(InstanceIds=[iid])
        ec2.delete_volume(VolumeId=replacement)
        _, pending = _replan(h, _AwsBacked(h), dep, "deletion-plan")
        approve_current(h, pending)
        Worker(settings, db, _AwsBacked(h), clock=h.clock).run_once()
        assert _detail(h, dep)["status"] == "recovery_required"  # original still exists
        ec2.delete_volume(VolumeId=original)
        _, pending = _replan(h, _AwsBacked(h), dep, "deletion-plan")
        approve_current(h, pending)
        Worker(settings, db, _AwsBacked(h), clock=h.clock).run_once()
        assert _detail(h, dep)["status"] == "deleted"


# ----------------------------------------- R4-4: source-distinct evidence is preserved


def test_r4_4_later_sources_are_kept_for_the_same_volume(harness: Harness) -> None:
    d = create_and_plan(harness)
    dep, iid, vid = d["id"], "i-0123456789abcdef0", "vol-0123456789abcdef0"
    worker = harness.worker()
    worker.record_identities(
        dep, [identity(iid, "tag_inventory"), identity(vid, "instance_block_devices", iid)]
    )
    worker.record_identities(dep, [identity(vid, "root_device", iid)])
    worker.record_identities(dep, [identity(vid, "terraform_state", iid)])
    with harness.db.read() as conn:
        assert IdentityLedger.known(conn, dep).launch_roots == {}  # observations only
    worker.record_identities(dep, [identity(vid, "launch_output", iid)])
    with harness.db.read() as conn:
        rows = {
            tuple(r)
            for r in conn.execute(
                "SELECT resource_id, source FROM deployment_resources WHERE deployment_id = ?",
                (dep,),
            )
        }
        known = IdentityLedger.known(conn, dep)
    assert {
        (vid, "instance_block_devices"),
        (vid, "root_device"),
        (vid, "terraform_state"),
        (vid, "launch_output"),
    } <= rows
    assert known.launch_roots == {iid: {vid}}
    assert known.instances_without_root_disk() == []


def test_r4_4_upgrade_reimports_evidence_suppressed_by_old_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A schema-3 database dropped later sources; after migration 0004 the evidence file
    restores them on the next import, and append-only protection is unchanged."""
    from conftest import make_settings

    settings = make_settings(tmp_path)
    db = Database(settings.database_path)
    migrations = database._migration_files()
    with monkeypatch.context() as m:
        m.setattr(database, "_migration_files", lambda: migrations[:3])
        assert db.migrate() == [1, 2, 3]
    dep, iid, vid = "dep_" + "e" * 32, "i-0123456789abcdef0", "vol-0123456789abcdef0"
    now = "2026-10-30T00:00:00+00:00"
    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO deployments (id, owner_id, name, disk_gib, region, instance_type, "
            "provisioner, status, created_at, updated_at) VALUES (?, 'dev:a', 'demo', 8, "
            "'us-east-1', 't3.micro', 'simulated', 'active', ?, ?)",
            (dep, now, now),
        )
    seed_launch_history(db, dep, "dev:a")
    ledger = IdentityLedger(settings.workdir_root)
    ledger.append_evidence(
        dep,
        [
            identity(iid, "tag_inventory"),
            identity(vid, "attached_device", iid),
            identity(vid, "apply_output", iid),
        ],
    )
    with db.transaction() as conn:
        ledger.import_evidence(conn, dep)
        assert ledger.known(conn, dep).launch_roots == {}  # shadowed under schema 3
    assert db.migrate() == [4, 5, 6]
    with db.transaction() as conn:
        ledger.import_evidence(conn, dep)
        assert ledger.known(conn, dep).launch_roots == {iid: {vid}}
    conn = db.connect()
    try:
        with pytest.raises(Exception, match="append-only"):
            conn.execute("DELETE FROM deployment_resources")
    finally:
        conn.close()


def test_r4_4_recording_fails_loudly_if_evidence_is_absent(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = create_and_plan(harness)
    from unitcompute.identities import Imported

    monkeypatch.setattr(IdentityLedger, "import_evidence", lambda self, conn, dep: Imported(0, 0))
    with pytest.raises(RuntimeError, match="not present after import"):
        harness.worker().record_identities(
            d["id"], [identity("i-0aaaaaaaaaaaaaaa1", "apply_output")]
        )


# ------------------------------------------- R4-5: concurrent appends are serialized


def test_r4_5_concurrent_short_appends_keep_every_record(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reliability reproduction: a short write in one appender while another appends."""
    d = create_and_plan(harness)
    ledger = IdentityLedger(harness.settings.workdir_root)
    real_write = os.write
    first, prefix_done = True, threading.Event()

    def interleave(fd: int, data: Any) -> int:
        nonlocal first
        if threading.current_thread().name == "append-A" and first:
            first = False
            count = real_write(fd, bytes(data[:8]))
            prefix_done.set()
            threading.Event().wait(0.3)  # the other appender tries to run meanwhile
            return count
        return real_write(fd, bytes(data))

    monkeypatch.setattr("unitcompute.identities.os.write", interleave)
    errors: list[BaseException] = []

    def append_a() -> None:
        try:
            harness.worker().record_identities(
                d["id"], [identity("sg-0123456789abcdef0", "tag_inventory")]
            )
        except Exception as exc:  # noqa: BLE001 - surfaced via the assertion below
            errors.append(exc)

    a = threading.Thread(target=append_a, name="append-A")
    a.start()
    assert prefix_done.wait(5)
    harness.worker().record_identities(d["id"], [identity("i-0123456789abcdef0", "apply_output")])
    a.join(5)
    assert not errors
    with harness.db.read() as conn:
        known = ledger.known(conn, d["id"])
    assert "sg-0123456789abcdef0" in known.groups
    assert "i-0123456789abcdef0" in known.instances
    lines = (harness.settings.workdir_root / d["id"] / "identities.jsonl").read_text()
    assert all(json.loads(line) for line in lines.splitlines())


def test_r4_5_appends_from_separate_processes_are_serialized(harness: Harness) -> None:
    d = create_and_plan(harness)
    script = (
        "import sys\n"
        "from pathlib import Path\n"
        "from unitcompute.identities import IdentityLedger, identity\n"
        "ledger = IdentityLedger(Path(sys.argv[1]))\n"
        "for n in range(200):\n"
        "    ledger.append_evidence(sys.argv[2], [identity(f'i-{int(sys.argv[3]):02x}{n:015x}',"
        " 'tag_inventory')])\n"
    )
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(harness.settings.workdir_root), d["id"], str(k)]
        )
        for k in range(4)
    ]
    assert all(p.wait(60) == 0 for p in procs)
    lines = (harness.settings.workdir_root / d["id"] / "identities.jsonl").read_text()
    records = [json.loads(line) for line in lines.splitlines()]
    assert len(records) == 800
    assert len({r["id"] for r in records}) == 800


# --------------------------------------- R4-6: new file and directory entries are durable


def test_r4_6_new_evidence_file_and_directories_are_fsynced(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = harness.settings.workdir_root / "nested-root"
    synced: list[str] = []
    real_fsync = os.fsync

    def trace(fd: int) -> None:
        mode = os.fstat(fd).st_mode
        synced.append("dir" if stat.S_ISDIR(mode) else "file")
        real_fsync(fd)

    monkeypatch.setattr("unitcompute.identities.os.fsync", trace)
    dep = "dep_" + "f" * 32
    new_dirs = 0
    path = root / dep
    while not path.exists():
        new_dirs += 1
        path = path.parent
    IdentityLedger(root).append_evidence(dep, [identity("i-0123456789abcdef0", "apply_output")])
    # the parent of every newly created directory, then the file, then every directory
    # from the file's up to the data directory (root.parent here)
    chain = len((root / dep).relative_to(root.parent).parts) + 1  # stop dir included
    assert new_dirs >= 2
    assert synced == ["dir"] * new_dirs + ["file"] + ["dir"] * chain
    synced.clear()
    IdentityLedger(root).append_evidence(dep, [identity("i-0123456789abcdef1", "apply_output")])
    assert synced == ["file"]  # existing entries need no further directory sync


# ------------------------------ R4-7: unresolved apply artifacts survive any preview


def test_r4_7_failed_apply_workdir_kept_until_a_later_apply_succeeds(harness: Harness) -> None:
    from test_worker_recovery import FailingApply

    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    failing = FailingApply(
        h.settings.data_dir, ProvisioningError("terraform_apply_failed", "partial apply"), True
    )
    Worker(h.settings, h.db, failing, clock=h.clock).run_once()
    workdir = h.settings.workdir_root / d["id"] / d["current_plan"]["plan_id"]
    recovery_state = workdir / "errored.tfstate"
    recovery_state.write_text("synthetic local recovery state")
    h.clock.advance(days=8)
    _, pending = _replan(h, h.provisioner, d["id"], "plan")  # unapproved repair preview
    assert pending["status"] == "awaiting_approval"
    h.worker().housekeeping()
    assert recovery_state.exists()
    h.client.post(f"/deployments/{d['id']}/deletion-plan", headers=auth())
    h.drain()
    h.worker().housekeeping()
    assert recovery_state.exists()  # still unresolved after another preview
    approve_current(h, _detail(h, d["id"]))  # a later apply that succeeds resolves it
    h.drain()
    assert _detail(h, d["id"])["status"] == "deleted"
    h.clock.advance(days=8)
    h.worker().housekeeping()
    assert not workdir.exists()


# ----------------------------------------------- R4-3: quoted credential assignments


SECRET = "synthetic-review4-secret-0123456789"


@pytest.mark.parametrize(
    "message",
    [
        f'aws_secret_access_key="{SECRET}"',
        f"aws_secret_access_key='{SECRET}'",
        f'password: "{SECRET}"',
        f'export AWS_SECRET_ACCESS_KEY="{SECRET}"',
        f'{{"api_key": "{SECRET}"}}',
        f"client_secret = '{SECRET} with spaces'",
        f"aws_session_token={SECRET}",
    ],
)
def test_r4_3_quoted_credentials_redacted_at_every_boundary(harness: Harness, message: str) -> None:
    seen: list[str] = []

    def echo(messages: list[BaseMessage]) -> AIMessage:
        seen.extend(str(m.content) for m in messages if isinstance(m, HumanMessage))
        return AIMessage(content=message)  # the model echoing a credential back

    service = AgentService(
        harness.settings,
        harness.db,
        harness.container.deployments,
        lambda: ScriptedChatModel(script=[echo]),
    )
    first = asyncio.run(
        service.handle(ALICE, AgentMessageRequest(message=message), None, "quoted-key-0001")
    )
    assert seen and all(SECRET not in s for s in seen)
    assert SECRET not in first.reply
    assert any("credential-like" in c for c in first.clarifications)
    with harness.db.read() as conn:
        stored = " ".join(r[0] for r in conn.execute("SELECT content FROM chat_messages"))
        response = conn.execute("SELECT response_json FROM agent_attempts").fetchone()[0]
    assert SECRET not in stored and SECRET not in response
    service._model_factory = None
    replay = asyncio.run(
        service.handle(ALICE, AgentMessageRequest(message=message), None, "quoted-key-0001")
    )
    assert SECRET not in replay.model_dump_json()


def test_r4_3_redaction_preserves_quotes_and_bounds() -> None:
    assert redact('password: "a b c"') == 'password: "[REDACTED]"'
    assert redact("API-KEY='x'") == "API-KEY='[REDACTED]'"
    assert redact("password=hunter22, next") == "password=[REDACTED], next"
    # Bounded, pattern-based: prose without an assignment is not recognised.
    assert redact("my password is hunter2") == "my password is hunter2"


def test_r4_3_quoted_legacy_history_is_redacted(harness: Harness) -> None:
    from unitcompute.db.database import to_db_time, utcnow

    sid = "chat_" + "e" * 32
    now = to_db_time(utcnow())
    with harness.db.transaction() as conn:
        conn.execute("INSERT INTO chat_sessions VALUES (?, 'dev:alice', 1, ?, ?)", (sid, now, now))
        conn.execute(
            "INSERT INTO chat_messages (session_id, role, content, created_at) "
            "VALUES (?, 'user', ?, ?)",
            (sid, f'password: "{SECRET}"', now),
        )
    seen: list[str] = []

    def record(messages: list[BaseMessage]) -> AIMessage:
        seen.extend(str(m.content) for m in messages)
        return AIMessage(content="ok")

    asyncio.run(
        AgentService(
            harness.settings,
            harness.db,
            harness.container.deployments,
            lambda: ScriptedChatModel(script=[record]),
        ).handle(ALICE, AgentMessageRequest(session_id=sid, message="next"), None)
    )
    assert seen and all(SECRET not in s for s in seen)
