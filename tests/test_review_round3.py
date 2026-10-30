"""Regressions for the third independent review round of 018c180.

Adapted from security3 ``test_security3_independent.py`` and reliability3
``test_reliability_review3.py``. IDs match docs/verification-ledger.md.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import pytest
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage

import iam_eval
from conftest import FakeClock, Harness, approve_current, auth, create_and_plan, make_settings
from test_config_and_auth import TERRAFORM_SETTINGS
from test_policy import AMI, INST, SPEC, TARGETS, change, load, run
from test_review_round2 import (
    _AwsBacked,
    _client,
    _detail,
    _placeholders,
    _replan,
    _schema_v1_deployment,
)
from unitcompute.agent.fake import ScriptedChatModel
from unitcompute.agent.service import AgentService
from unitcompute.auth import Principal
from unitcompute.db.database import to_db_time, utcnow
from unitcompute.errors import Conflict
from unitcompute.identities import IdentityLedger, identity
from unitcompute.provisioning.aws import session_policy
from unitcompute.provisioning.base import template_dir
from unitcompute.provisioning.terraform import build_tfvars
from unitcompute.schemas import AgentMessageRequest

ROOT = Path(__file__).resolve().parents[1]
ALICE = Principal(subject="dev:alice", auth_method="dev")
TERRAFORM = shutil.which("terraform") or str(Path.home() / ".local/bin/terraform")


# ------------------------------------- R3-1: volumes tagged at launch (tag-on-create)


def _capture_provider_launch(tmp_path: Path) -> list[dict[str, list[str]]]:
    """Run the pinned provider against a loopback EC2 stub and capture RunInstances.

    No AWS, no credentials: the stub answers the two lookups the provider needs and refuses
    the launch itself."""
    requests: list[dict[str, list[str]]] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_POST(self) -> None:
            query = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
            requests.append(query)
            ns = 'xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"'
            action = query["Action"][0]
            if action == "DescribeImages":
                payload = (
                    f"<DescribeImagesResponse {ns}><requestId>x</requestId><imagesSet><item>"
                    f"<imageId>{AMI}</imageId><imageState>available</imageState>"
                    "<rootDeviceName>/dev/xvda</rootDeviceName><rootDeviceType>ebs"
                    "</rootDeviceType><blockDeviceMapping><item><deviceName>/dev/xvda"
                    "</deviceName><ebs><snapshotId>snap-0123456789abcdef0</snapshotId>"
                    "<volumeSize>8</volumeSize></ebs></item></blockDeviceMapping></item>"
                    "</imagesSet></DescribeImagesResponse>"
                )
                self.send_response(200)
            elif action == "DescribeInstanceTypes":
                payload = (
                    f"<DescribeInstanceTypesResponse {ns}><requestId>x</requestId>"
                    "<instanceTypeSet><item><instanceType>t3.micro</instanceType>"
                    "<hypervisor>nitro</hypervisor><burstablePerformanceSupported>true"
                    "</burstablePerformanceSupported><processorInfo><supportedArchitectures>"
                    "<item>x86_64</item></supportedArchitectures></processorInfo><ebsInfo>"
                    "<ebsOptimizedSupport>default</ebsOptimizedSupport></ebsInfo></item>"
                    "</instanceTypeSet></DescribeInstanceTypesResponse>"
                )
                self.send_response(200)
            else:
                payload = (
                    "<Response><Errors><Error><Code>UnauthorizedOperation</Code>"
                    "<Message>local stub refuses launch</Message></Error></Errors>"
                    "<RequestID>x</RequestID></Response>"
                )
                self.send_response(403)
            self.send_header("Content-Type", "text/xml")
            self.end_headers()
            self.wfile.write(payload.encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    work = tmp_path / "module"
    work.mkdir()
    for path in template_dir().iterdir():
        if path.is_file():
            shutil.copyfile(path, work / path.name)
    versions = (work / "versions.tf").read_text().replace('backend "s3" {}', 'backend "local" {}')
    (work / "versions.tf").write_text(versions)
    main = (work / "main.tf").read_text()
    # Only the instance launch matters; use a fixed group ID instead of creating one.
    main = (
        main[: main.index('resource "aws_security_group"')]
        + main[main.index('resource "aws_instance"') :]
    )
    (work / "main.tf").write_text(
        main.replace("[aws_security_group.vm.id]", '["sg-0123456789abcdef0"]')
    )
    (work / "outputs.tf").unlink()
    (work / "offline_override.tf").write_text(
        'provider "aws" {\n  region = "us-east-1"\n  access_key = "offline-test"\n'
        '  secret_key = "offline-test"\n  skip_credentials_validation = true\n'
        "  skip_requesting_account_id = true\n  skip_metadata_api_check = true\n"
        "  allowed_account_ids = null\n"
        f'  endpoints {{\n    ec2 = "http://127.0.0.1:{server.server_port}"\n  }}\n}}\n'
    )
    (work / "vars.tfvars.json").write_text(json.dumps(build_tfvars(SPEC, TARGETS, AMI)))
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(work),
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_CONFIG_FILE": os.devnull,
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
        "CHECKPOINT_DISABLE": "1",
    }
    if os.environ.get("TF_PLUGIN_CACHE_DIR"):
        env["TF_PLUGIN_CACHE_DIR"] = os.environ["TF_PLUGIN_CACHE_DIR"]
    try:
        init = subprocess.run(
            [TERRAFORM, "init", "-input=false", "-lockfile=readonly", "-no-color"],
            cwd=work,
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        assert init.returncode == 0, init.stderr
        subprocess.run(
            [
                TERRAFORM,
                "apply",
                "-auto-approve",
                "-input=false",
                "-no-color",
                "-var-file=vars.tfvars.json",
            ],
            cwd=work,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    return requests


def _tag_specs(launch: dict[str, list[str]]) -> dict[str, dict[str, str]]:
    specs: dict[str, dict[str, str]] = {}
    for key, value in launch.items():
        if key.startswith("TagSpecification.") and key.endswith(".ResourceType"):
            index = key.split(".")[1]
            tags = {}
            n = 1
            while f"TagSpecification.{index}.Tag.{n}.Key" in launch:
                tags[launch[f"TagSpecification.{index}.Tag.{n}.Key"][0]] = launch[
                    f"TagSpecification.{index}.Tag.{n}.Value"
                ][0]
                n += 1
            specs[value[0]] = tags
    return specs


@pytest.mark.terraform
def test_r3_1_pinned_provider_tags_root_volume_in_run_instances(tmp_path: Path) -> None:
    if not Path(TERRAFORM).exists():
        pytest.skip("terraform binary not installed")
    requests = _capture_provider_launch(tmp_path)
    launch = next(q for q in requests if q["Action"] == ["RunInstances"])
    specs = _tag_specs(launch)
    assert set(specs) == {"instance", "volume"}
    assert specs["volume"]["UnitComputeDeployment"] == SPEC.deployment_id
    assert specs["volume"]["ManagedBy"] == "unitcompute"
    assert not any(q["Action"] == ["CreateTags"] for q in requests)

    # The captured request satisfies both execution policies, which still deny untagged
    # volume launches (tag-on-create least privilege is unchanged).
    settings = make_settings(tmp_path / "settings", **TERRAFORM_SETTINGS)
    role = json.loads((ROOT / "docs/iam/apply-role-policy.json").read_text())
    session = session_policy(settings, "apply", SPEC.deployment_id)
    volume = f"arn:aws:ec2:us-east-1:{settings.aws_account_id}:volume/vol-0123456789abcdef0"
    base = {
        "aws:PrincipalTag/UnitComputeDeployment": SPEC.deployment_id,
        "aws:RequestedRegion": "us-east-1",
        "ec2:Encrypted": "true",
        "ec2:VolumeType": "gp3",
        "ec2:VolumeSize": "8",
    }
    tagged = {**base, **{f"aws:RequestTag/{k}": v for k, v in specs["volume"].items()}}
    placeholders = _placeholders(settings)
    assert iam_eval.allowed([role, session], "ec2:RunInstances", volume, tagged, placeholders)
    assert not iam_eval.allowed([role], "ec2:RunInstances", volume, base, placeholders)
    assert not iam_eval.allowed([session], "ec2:RunInstances", volume, base, {})
    other = {**tagged, "aws:RequestTag/UnitComputeDeployment": "dep_" + "f" * 32}
    assert not iam_eval.allowed([role, session], "ec2:RunInstances", volume, other, placeholders)


def test_r3_1_policy_requires_launch_time_volume_tags() -> None:
    plan = load()
    assert run(plan) == []
    del change(plan, INST)["change"]["after"]["volume_tags"]
    assert any("volume_tags" in v for v in run(plan))
    plan = load()
    change(plan, INST)["change"]["after"]["root_block_device"][0]["tags"] = {"a": "b"}
    assert any("root_block_device.tags" in v for v in run(plan))
    plan = load()
    resource = next(
        r for r in plan["configuration"]["root_module"]["resources"] if r["address"] == INST
    )
    resource["expressions"]["root_block_device"][0]["tags"] = {"constant_value": {"a": "b"}}
    assert any("root_block_device configures unreviewed" in v for v in run(plan))


def test_r3_1_template_uses_volume_tags_not_root_block_tags() -> None:
    main = (template_dir() / "main.tf").read_text()
    root_block = main[main.index("root_block_device {") :]
    root_block = root_block[: root_block.index("}")]
    assert "tags" not in root_block
    assert "volume_tags = merge(local.tags" in main


# --------------------------------- R3-2/R3-3: root identity; no waiver; no repair bypass


def _legacy_retained_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ec2: Any) -> Any:
    vm = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        BlockDeviceMappings=[
            {"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 8, "DeleteOnTermination": False}}
        ],
    )["Instances"][0]
    iid, vid = vm["InstanceId"], vm["BlockDeviceMappings"][0]["Ebs"]["VolumeId"]
    settings, db, dep = _schema_v1_deployment(tmp_path, monkeypatch, iid)
    ec2.terminate_instances(InstanceIds=[iid])
    client, h = _client(settings, db, FakeClock())
    return iid, vid, db, dep, client, h


@pytest.mark.parametrize("route", ["plan", "deletion-plan"])
def test_r3_3_unresolved_root_blocks_repair_and_deletion_previews(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    moto_env: Any,
    route: str,
) -> None:
    iid, vid, _db, dep, client, h = _legacy_retained_root(tmp_path, monkeypatch, moto_env)
    with client:
        _, pending = _replan(h, _AwsBacked(h), dep, route)
        assert pending["status"] == "plan_failed"
        assert pending["current_plan"]["status"] == "failed"
        assert pending["current_plan"]["error"]["code"] == "identity_incomplete"
        assert iid in pending["current_plan"]["error"]["message"]
        assert pending["current_plan"]["plan_hash"] is None  # nothing approvable
        assert moto_env.describe_volumes(VolumeIds=[vid])["Volumes"][0]["State"] == "available"
        assert (
            client.post(
                "/deployments", json={"name": "next", "disk_gib": 8}, headers=auth()
            ).status_code
            == 409
        )


def test_r3_2_legacy_acknowledgements_are_not_a_waiver(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    moto_env: Any,
) -> None:
    iid, _vid, db, dep, client, h = _legacy_retained_root(tmp_path, monkeypatch, moto_env)
    with db.transaction() as conn:  # a row left by the removed round-2 command
        conn.execute(
            (
                "INSERT INTO identity_acknowledgements (deployment_id, instan"
                "ce_id, operator, reason, recorded_at) VALUES (%s, %s, 'revie"
                "w-operator', 'unverified', '2026-10-30T00:00:00Z')"
            ),
            (dep, iid),
        )
    with client:
        _, pending = _replan(h, _AwsBacked(h), dep, "deletion-plan")
        assert pending["current_plan"]["error"]["code"] == "identity_incomplete"
    from unitcompute import admin

    assert not hasattr(admin, "_acknowledge_root_disk")


def test_r3_2_attached_data_disk_is_not_root_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    moto_env: Any,
) -> None:
    """Reliability reproduction: detached root + attached data disk; deletion must not pass."""
    ec2 = moto_env
    vm = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        BlockDeviceMappings=[
            {"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 8, "DeleteOnTermination": False}}
        ],
    )["Instances"][0]
    iid, root = vm["InstanceId"], vm["BlockDeviceMappings"][0]["Ebs"]["VolumeId"]
    ec2.stop_instances(InstanceIds=[iid])
    ec2.detach_volume(VolumeId=root, InstanceId=iid, Device="/dev/sda1")
    data = ec2.create_volume(AvailabilityZone=vm["Placement"]["AvailabilityZone"], Size=8)[
        "VolumeId"
    ]
    ec2.attach_volume(VolumeId=data, InstanceId=iid, Device="/dev/sdf")
    settings, db, dep = _schema_v1_deployment(tmp_path, monkeypatch, iid)
    client, h = _client(settings, db, FakeClock())
    with client:
        _, pending = _replan(h, _AwsBacked(h), dep, "deletion-plan")
        assert pending["current_plan"]["error"]["code"] == "identity_incomplete"
        with db.read() as conn:
            known = IdentityLedger.known(conn, dep)
        assert known.volumes == {data: iid}  # recorded as evidence ...
        assert known.launch_roots == {}  # ... but never as the root disk
        assert known.observed_roots == {}
        assert known.instances_without_root_disk() == [iid]
        ec2.terminate_instances(InstanceIds=[iid])
        ec2.delete_volume(VolumeId=data)
        _, pending = _replan(h, _AwsBacked(h), dep, "deletion-plan")
        assert pending["current_plan"]["error"]["code"] == "identity_incomplete"
        assert ec2.describe_volumes(VolumeIds=[root])["Volumes"][0]["State"] == "available"
        assert (
            client.post(
                "/deployments", json={"name": "next", "disk_gib": 8}, headers=auth()
            ).status_code
            == 409
        )


def test_r3_2_root_device_observation_is_distinct_from_launch_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, moto_env: Any
) -> None:
    """Round 4: the volume at RootDeviceName is recorded as an observation (and attached
    disks as attachments), but neither completes identity without launch evidence."""
    ec2 = moto_env
    vm = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        BlockDeviceMappings=[{"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 8}}],
    )["Instances"][0]
    iid, root = vm["InstanceId"], vm["BlockDeviceMappings"][0]["Ebs"]["VolumeId"]
    data = ec2.create_volume(AvailabilityZone=vm["Placement"]["AvailabilityZone"], Size=8)[
        "VolumeId"
    ]
    ec2.attach_volume(VolumeId=data, InstanceId=iid, Device="/dev/sdf")
    settings, db, dep = _schema_v1_deployment(tmp_path, monkeypatch, iid)
    client, h = _client(settings, db, FakeClock())
    with client:
        _, pending = _replan(h, _AwsBacked(h), dep, "deletion-plan")
        assert pending["current_plan"]["error"]["code"] == "identity_incomplete"
        with db.read() as conn:
            known = IdentityLedger.known(conn, dep)
            sources = list(
                conn.execute(
                    "SELECT resource_id, source FROM deployment_resources WHERE deployment_id = %s",
                    (dep,),
                ).fetchall()
            )
    assert known.observed_roots == {iid: {root}}
    assert known.launch_roots == {}
    assert known.instances_without_root_disk() == [iid]
    assert (root, "root_device") in {tuple(r.values()) for r in sources}
    assert (data, "attached_device") in {tuple(r.values()) for r in sources}


def test_r3_2_operator_root_claims_no_longer_exist() -> None:
    """Round 4 removed `record-root-volume`: an operator assertion, even about an existing
    volume, cannot establish which volume was an instance's launch root."""
    from unitcompute import admin

    assert not hasattr(admin, "_record_root_volume")
    with pytest.raises(SystemExit):
        admin.main(
            [
                "record-root-volume",
                "dep_" + "a" * 32,
                "i-0123456789abcdef0",
                "vol-0123456789abcdef0",
                "--operator",
                "x",
                "--reason",
                "y",
            ]
        )


# --------------------------------------------- R3-5: torn records and short writes


def test_r3_5_torn_tail_does_not_swallow_next_record(harness: Harness) -> None:
    d = create_and_plan(harness)
    ledger = IdentityLedger(harness.settings.workdir_root)
    evidence = harness.settings.workdir_root / d["id"] / "identities.jsonl"
    evidence.write_bytes(b'{"id":"i-0aaaaaaaaaaaaaaa1","source":')  # crash mid-record
    assert ledger.append_evidence(d["id"], [identity("i-0bbbbbbbbbbbbbbb2", "apply_output")])
    assert ledger.append_evidence(d["id"], [identity("sg-0ccccccccccccccc3", "apply_output")])
    with harness.db.transaction() as conn:
        ledger.import_evidence(conn, d["id"])
        known = ledger.known(conn, d["id"])
    assert "i-0bbbbbbbbbbbbbbb2" in known.instances
    assert "sg-0ccccccccccccccc3" in known.groups
    assert "i-0aaaaaaaaaaaaaaa1" not in known.instances  # the torn fragment stays skipped


def test_r3_5_short_writes_are_completed(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    d = create_and_plan(harness)
    ledger = IdentityLedger(harness.settings.workdir_root)
    real_write = os.write

    def one_byte(fd: int, data: Any) -> int:
        return real_write(fd, bytes(data[:1]))

    monkeypatch.setattr("unitcompute.identities.os.write", one_byte)
    ledger.append_evidence(
        d["id"],
        [
            identity("i-0ddddddddddddddd4", "apply_output"),
            identity("vol-0ddddddddddddddd4", "apply_output", "i-0ddddddddddddddd4"),
        ],
    )
    monkeypatch.undo()
    lines = (harness.settings.workdir_root / d["id"] / "identities.jsonl").read_text()
    assert len(lines.splitlines()) == 2
    assert lines.endswith("\n")
    assert [json.loads(line)["id"] for line in lines.splitlines()] == [
        "i-0ddddddddddddddd4",
        "vol-0ddddddddddddddd4",
    ]


def test_r3_5_write_without_progress_fails_loudly(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = create_and_plan(harness)
    monkeypatch.setattr("unitcompute.identities.os.write", lambda fd, data: 0)
    with pytest.raises(OSError, match="no progress"):
        IdentityLedger(harness.settings.workdir_root).append_evidence(
            d["id"], [identity("i-0eeeeeeeeeeeeeee5", "apply_output")]
        )


# ------------------------------------------- R3-6: fence expired chat completions


def test_r3_6_expired_attempt_cannot_publish_after_retry(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    import unitcompute.agent.service as module

    request = AgentMessageRequest(message="hi")
    service = AgentService(
        harness.settings, harness.db, harness.container.deployments, ScriptedChatModel
    )
    entered, release = asyncio.Event(), asyncio.Event()
    calls = 0

    class DelayedAgent:
        async def ainvoke(self, *args: Any, **kwargs: Any) -> Any:
            nonlocal calls
            calls += 1
            if calls == 1:
                entered.set()
                await release.wait()
            return {"messages": [AIMessage(content=f"answer-{calls}")]}

    monkeypatch.setattr(module, "create_agent", lambda *a, **kw: DelayedAgent())

    async def scenario() -> Any:
        first = asyncio.create_task(service.handle(ALICE, request, None, "same-key-0001"))
        await entered.wait()
        future = utcnow() + timedelta(seconds=200)  # the first reservation's lease expired
        monkeypatch.setattr(module, "utcnow", lambda: future)
        second = await service.handle(ALICE, request, None, "same-key-0001")
        release.set()
        with pytest.raises(Conflict) as late:
            await first
        replay = await service.handle(ALICE, request, None, "same-key-0001")
        return late.value, second, replay

    late, second, replay = asyncio.run(scenario())
    assert late.code == "attempt_superseded"
    assert replay == second
    with harness.db.read() as conn:
        statuses = [
            tuple(r.values())
            for r in conn.execute("SELECT status, idempotency_key FROM agent_attempts ORDER BY id")
        ]
        messages = conn.execute("SELECT COUNT(*) FROM chat_messages").fetchone()[0]
    assert statuses == [("failed", None), ("succeeded", "same-key-0001")]
    assert messages == 2  # only the retry published history


# ---------------------------------------- R3-7: credentials never reach provider/history


SECRET = "synthetic-credential-review-only-0123456789"


def _recording_service(h: Harness, seen: list[str]) -> AgentService:
    def record(messages: list[BaseMessage]) -> AIMessage:
        seen.extend(str(m.content) for m in messages if isinstance(m, HumanMessage))
        return AIMessage(content="ok")

    return AgentService(
        h.settings,
        h.db,
        h.container.deployments,
        lambda: ScriptedChatModel(script=[record, record]),
    )


@pytest.mark.parametrize(
    "message",
    [
        f"aws_secret_access_key={SECRET}",
        f"my key is AKIA{'A' * 16} ok",
        f"password: {SECRET}",
        f"-----BEGIN RSA PRIVATE KEY-----\n{SECRET}\n-----END RSA PRIVATE KEY-----",
    ],
)
def test_r3_7_credentials_removed_before_provider_and_history(
    harness: Harness, message: str
) -> None:
    seen: list[str] = []
    service = _recording_service(harness, seen)
    reply = asyncio.run(
        service.handle(ALICE, AgentMessageRequest(message=message), None, "secret-key-0001")
    )
    assert seen
    assert all(SECRET not in s and f"AKIA{'A' * 16}" not in s for s in seen)
    with harness.db.read() as conn:
        stored = " ".join(r[0] for r in conn.execute("SELECT content FROM chat_messages"))
    assert SECRET not in stored
    assert "[REDACTED]" in stored
    assert any("credential-like value was removed" in c for c in reply.clarifications)
    replay = asyncio.run(
        service.handle(ALICE, AgentMessageRequest(message=message), None, "secret-key-0001")
    )
    assert replay == reply
    assert SECRET not in replay.model_dump_json()


def test_r3_7_legacy_history_is_redacted_before_the_provider(harness: Harness) -> None:
    sid = "chat_" + "d" * 32
    now = to_db_time(utcnow())
    with harness.db.transaction() as conn:  # history written before redaction existed
        conn.execute(
            "INSERT INTO chat_sessions (id,owner_id,turns,created_at,updated_at) "
            "VALUES (%s, 'dev:alice', 1, %s, %s)",
            (sid, now, now),
        )
        conn.execute(
            "INSERT INTO chat_messages (session_id, role, content, created_at) "
            "VALUES (%s, 'user', %s, %s)",
            (sid, f"aws_secret_access_key={SECRET}", now),
        )
    seen: list[str] = []
    asyncio.run(
        _recording_service(harness, seen).handle(
            ALICE, AgentMessageRequest(session_id=sid, message="next"), None
        )
    )
    assert seen and all(SECRET not in s for s in seen)


def test_r3_7_redaction_happens_over_http(harness: Harness) -> None:
    seen: list[str] = []
    harness.container.agent = _recording_service(harness, seen)
    response = harness.client.post(
        "/agent/messages", json={"message": f"api_key={SECRET}"}, headers=auth()
    )
    assert response.status_code == 200
    assert SECRET not in response.text
    assert all(SECRET not in s for s in seen)


def test_r3_7_approve_still_works_after_identity_changes(harness: Harness) -> None:
    """Interaction: the stricter identity rules do not block the normal lifecycle."""
    d = create_and_plan(harness)
    approve_current(harness, d)
    harness.drain()
    assert _detail(harness, d["id"])["status"] == "active"
    harness.client.post(f"/deployments/{d['id']}/deletion-plan", headers=auth())
    harness.drain()
    approve_current(harness, _detail(harness, d["id"]))
    harness.drain()
    assert _detail(harness, d["id"])["status"] == "deleted"
    with harness.db.read() as conn:
        known = IdentityLedger.known(conn, d["id"])
    assert known.instances_without_root_disk() == []


def test_r3_3_deletion_verification_independently_requires_root_identity(
    harness: Harness,
) -> None:
    """Second line of defence: even if a plan got through, verification still refuses."""
    from unitcompute.worker import JobFailure, Worker

    d = create_and_plan(harness)
    ledger = IdentityLedger(harness.settings.workdir_root)
    ledger.append_evidence(d["id"], [identity("i-0fffffffffffffff1", "tag_inventory")])
    worker = Worker(harness.settings, harness.db, harness.provisioner, clock=harness.clock)
    with harness.db.read() as conn:
        deployment = conn.execute("SELECT * FROM deployments WHERE id = %s", (d["id"],)).fetchone()
        plan = conn.execute(
            "SELECT * FROM plans WHERE id = %s", (d["current_plan"]["plan_id"],)
        ).fetchone()
    outcome = worker._remaining_after_delete(deployment, plan, [])
    assert isinstance(outcome, JobFailure)
    assert outcome.code == "identity_incomplete"
    assert "i-0fffffffffffffff1" in outcome.message
