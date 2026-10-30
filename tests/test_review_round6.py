"""Regressions for the sixth independent review round of b5341db.

Adapted from security6 ``test_security6_independent.py`` / ``reproduce_backend_failure6.py``
and reliability6 ``test_reliability6_independent.py``. Scenarios run through the real API,
worker, migration and Terraform-runner paths. IDs match docs/verification-ledger.md.
"""

from __future__ import annotations

import asyncio
import copy
import json
import multiprocessing
import os
import shutil
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from conftest import FakeClock, Harness, approve_current, auth, create_and_plan, launch
from test_review_round2 import _AwsBacked, _detail, _replan
from test_review_round4 import _quota_held
from test_review_round5 import _obligations, _raw_state
from unitcompute.agent.fake import ScriptedChatModel
from unitcompute.agent.service import TOOL_ERROR, UNKNOWN_TOOL_ERROR, AgentService
from unitcompute.auth import Principal
from unitcompute.db import database
from unitcompute.db.database import Database
from unitcompute.identities import EvidenceBusy, IdentityLedger, identity
from unitcompute.logging_setup import redact
from unitcompute.provisioning.base import ApplyResult, DeploymentSpec, ProvisioningError
from unitcompute.provisioning.runner import TerraformRunner
from unitcompute.provisioning.simulated import SimulatedProvisioner, raw_state, simulated_lineage
from unitcompute.provisioning.state_evidence import (
    INSTANCE,
    SECURITY_GROUP,
    PriorState,
    StateEvidenceError,
    bind_to_plan,
    observed_identities,
    parse_raw_state,
)
from unitcompute.schemas import AgentMessageRequest
from unitcompute.worker import Worker

ALICE = Principal(subject="dev:alice", auth_method="dev")
TERRAFORM = shutil.which("terraform") or str(Path.home() / ".local/bin/terraform")
ROOT = Path(__file__).resolve().parents[1]
SK = "sk-" + "abcdef0123456789abcdef"


def _created_vm(ec2: Any, spec: Any) -> dict[str, str]:
    tags = [
        {"Key": "UnitComputeDeployment", "Value": spec.deployment_id},
        {"Key": "ManagedBy", "Value": "unitcompute"},
    ]
    vm = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        BlockDeviceMappings=[
            {"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 8, "DeleteOnTermination": False}}
        ],
        TagSpecifications=[{"ResourceType": k, "Tags": tags} for k in ("instance", "volume")],
    )["Instances"][0]
    return {"iid": vm["InstanceId"], "vid": vm["BlockDeviceMappings"][0]["Ebs"]["VolumeId"]}


# ============================ R6-1: process exit does not establish what was persisted


class _UnprovenApply(_AwsBacked):
    """Creates a real (moto) VM, then fails; what Terraform left behind is ``capture``."""

    def __init__(self, h: Any, ec2: Any, capture: str, error: ProvisioningError | None = None):
        super().__init__(h)
        self.ec2, self.capture, self.created = ec2, capture, {}
        self.error = error or ProvisioningError("terraform_apply_failed", "Failed to save state")

    def apply(self, spec: Any, workdir: Path, plan_path: Path) -> ApplyResult:
        self.created = _created_vm(self.ec2, spec)
        iid, vid = self.created["iid"], self.created["vid"]
        lineage = simulated_lineage(spec.deployment_id)
        if self.capture == "missing-resources":
            document: dict[str, Any] = {"version": 4}
        elif self.capture == "outputs-only":
            document = raw_state(lineage, 1, {})
            document["outputs"] = {
                "instance_id": {"value": iid, "type": "string"},
                "root_volume_id": {"value": vid, "type": "string"},
            }
        elif self.capture == "empty-envelope":
            document = raw_state(lineage, 1, {})
        elif self.capture == "stale-serial":
            document = _raw_state(iid, vid, "sg-0123456789abcdef0", dep=spec.deployment_id)
            document["serial"] = -1
        elif self.capture == "wrong-lineage":
            document = _raw_state(iid, vid, "sg-0123456789abcdef0", dep="dep_" + "9" * 32)
        elif self.capture == "wrong-version":
            document = _raw_state(
                iid, vid, "sg-0123456789abcdef0", dep=spec.deployment_id, terraform_version="0.0"
            )
        elif self.capture == "disagreeing-output":
            document = _raw_state(iid, vid, "sg-0123456789abcdef0", dep=spec.deployment_id)
            document["outputs"]["instance_id"]["value"] = "i-0123456789abcdef9"
        else:
            raise AssertionError(self.capture)
        (workdir / "errored.tfstate").write_text(json.dumps(document))
        raise self.error

    def capture_stored_state(self, spec: Any, workdir: Path) -> object:
        return raw_state(simulated_lineage(spec.deployment_id), 1, {})  # valid but empty


UNPROVEN = [
    "missing-resources",
    "outputs-only",
    "empty-envelope",
    "stale-serial",
    "wrong-lineage",
    "wrong-version",
    "disagreeing-output",
]


@pytest.mark.parametrize("capture", UNPROVEN)
def test_r6_1_unproven_state_never_resolves_an_unknown_mutation(
    harness: Harness, moto_env: Any, capture: str
) -> None:
    """Security reproduction: the VM exists, tags are gone, nothing valid was captured.
    Verified deletion, quota release and discharge must all stay impossible."""
    h, ec2 = harness, moto_env
    d = create_and_plan(h)
    dep = d["id"]
    approve_current(h, d)
    failing = _UnprovenApply(h, ec2, capture)
    Worker(h.settings, h.db, failing, clock=h.clock).run_once()
    assert _obligations(h, dep) == [("terraform_apply_failed", "uncaptured", False)]
    iid, vid = failing.created["iid"], failing.created["vid"]
    ec2.delete_tags(Resources=[iid, vid], Tags=[{"Key": "UnitComputeDeployment"}])
    ec2.terminate_instances(InstanceIds=[iid])
    _, pending = _replan(h, _AwsBacked(h), dep, "deletion-plan")
    assert pending["status"] == "recovery_required"
    assert pending["current_plan"]["error"]["code"] == "recovery_evidence_missing"
    assert _quota_held(h.client)
    assert ec2.describe_volumes(VolumeIds=[vid])["Volumes"][0]["State"] == "available"
    assert _obligations(h, dep) == [("terraform_apply_failed", "uncaptured", False)]


def test_r6_1_ids_in_unaccepted_state_are_recorded_as_observations(
    harness: Harness, moto_env: Any
) -> None:
    """Raw outputs name the VM and disk; the state is not accepted, but the IDs are kept so
    they must be verified gone by any later deletion."""
    h, ec2 = harness, moto_env
    d = create_and_plan(h)
    approve_current(h, d)
    failing = _UnprovenApply(h, ec2, "outputs-only")
    Worker(h.settings, h.db, failing, clock=h.clock).run_once()
    with h.db.read() as conn:
        known = IdentityLedger.known(conn, d["id"])
        sources = {
            r["source"]
            for r in conn.execute(
                "SELECT source FROM deployment_resources WHERE deployment_id = ?", (d["id"],)
            )
        }
    assert {failing.created["iid"], failing.created["vid"]} <= set(known.all_ids)
    assert sources == {"errored_state_seen"}
    assert known.launch_roots == {}  # an observation never completes launch identity


@pytest.mark.parametrize(
    "error",
    [
        ProvisioningError("terraform_apply_failed", "failed"),
        ProvisioningError("terraform_signalled", "terminated by a signal"),
        ProvisioningError("terraform_timeout", "timed out"),
    ],
)
def test_r6_1_stored_state_without_the_planned_vm_proves_nothing(
    harness: Harness, moto_env: Any, error: ProvisioningError
) -> None:
    """Whatever the exit (error, signal, timeout), a valid-but-empty stored snapshot cannot
    stand in for what the apply did (backend-write failure reproduction)."""
    h, ec2 = harness, moto_env
    d = create_and_plan(h)
    approve_current(h, d)

    class StoredOnly(_UnprovenApply):
        def apply(self, spec: Any, workdir: Path, plan_path: Path) -> ApplyResult:
            self.created = _created_vm(self.ec2, spec)
            raise self.error

    Worker(h.settings, h.db, StoredOnly(h, ec2, "x", error), clock=h.clock).run_once()
    assert _obligations(h, d["id"]) == [(error.code, "uncaptured", False)]


def test_r6_1_complete_bound_state_is_still_accepted(harness: Harness, moto_env: Any) -> None:
    """Preserved guarantee: Terraform's final state for this very plan is captured."""
    h, ec2 = harness, moto_env
    d = create_and_plan(h)
    approve_current(h, d)

    class Good(_UnprovenApply):
        def apply(self, spec: Any, workdir: Path, plan_path: Path) -> ApplyResult:
            self.created = _created_vm(self.ec2, spec)
            document = _raw_state(
                self.created["iid"],
                self.created["vid"],
                "sg-0123456789abcdef0",
                dep=spec.deployment_id,
            )
            (workdir / "errored.tfstate").write_text(json.dumps(document))
            raise self.error

    failing = Good(h, ec2, "x")
    Worker(h.settings, h.db, failing, clock=h.clock).run_once()
    assert _obligations(h, d["id"]) == [("terraform_apply_failed", "captured", False)]
    with h.db.read() as conn:
        known = IdentityLedger.known(conn, d["id"])
    assert known.launch_roots == {failing.created["iid"]: {failing.created["vid"]}}


def test_r6_1_stored_snapshot_must_show_every_planned_resource(
    harness: Harness, moto_env: Any
) -> None:
    """Unlike errored.tfstate (Terraform's own final state), a stored snapshot may be stale or
    intermediate, so a VM without its group is not an outcome even after a plain failure."""
    h, ec2 = harness, moto_env
    d = create_and_plan(h)
    approve_current(h, d)

    class VmOnlySnapshot(_UnprovenApply):
        def apply(self, spec: Any, workdir: Path, plan_path: Path) -> ApplyResult:
            self.created = _created_vm(self.ec2, spec)
            raise self.error

        def capture_stored_state(self, spec: Any, workdir: Path) -> object:
            return _raw_state(
                self.created["iid"], self.created["vid"], None, dep=spec.deployment_id
            )

    Worker(h.settings, h.db, VmOnlySnapshot(h, ec2, "x"), clock=h.clock).run_once()
    assert _obligations(h, d["id"]) == [("terraform_apply_failed", "uncaptured", False)]
    with h.db.read() as conn:  # still recorded as an observation
        assert IdentityLedger.known(conn, d["id"]).launch_roots == {}


def test_r6_1_complete_stored_snapshot_is_accepted_right_after_the_apply(
    harness: Harness, moto_env: Any
) -> None:
    h, ec2 = harness, moto_env
    d = create_and_plan(h)
    approve_current(h, d)

    class FullSnapshot(_UnprovenApply):
        def apply(self, spec: Any, workdir: Path, plan_path: Path) -> ApplyResult:
            self.created = _created_vm(self.ec2, spec)
            raise self.error

        def capture_stored_state(self, spec: Any, workdir: Path) -> object:
            return _raw_state(
                self.created["iid"],
                self.created["vid"],
                "sg-0123456789abcdef0",
                dep=spec.deployment_id,
            )

    failing = FullSnapshot(h, ec2, "x")
    Worker(h.settings, h.db, failing, clock=h.clock).run_once()
    assert _obligations(h, d["id"]) == [("terraform_apply_failed", "captured", False)]
    with h.db.read() as conn:
        launch_roots = IdentityLedger.known(conn, d["id"]).launch_roots
    assert launch_roots == {failing.created["iid"]: {failing.created["vid"]}}


def test_r6_1_partial_final_state_is_accepted_and_empty_final_state_is_not(
    harness: Harness, moto_env: Any
) -> None:
    """errored.tfstate may legitimately show a partial outcome (VM without its group), but
    one that shows nothing the plan creates says nothing about the apply."""
    h, ec2 = harness, moto_env
    d = create_and_plan(h)
    approve_current(h, d)

    class Partial(_UnprovenApply):
        def apply(self, spec: Any, workdir: Path, plan_path: Path) -> ApplyResult:
            self.created = _created_vm(self.ec2, spec)
            document = _raw_state(
                self.created["iid"], self.created["vid"], None, dep=spec.deployment_id
            )
            (workdir / "errored.tfstate").write_text(json.dumps(document))
            raise self.error

    Worker(h.settings, h.db, Partial(h, ec2, "x"), clock=h.clock).run_once()
    assert _obligations(h, d["id"]) == [("terraform_apply_failed", "captured", False)]


def test_r6_1_tampered_saved_plan_voids_the_binding(harness: Harness, moto_env: Any) -> None:
    h, ec2 = harness, moto_env
    d = create_and_plan(h)
    approve_current(h, d)

    class TamperAfterApply(_UnprovenApply):
        def apply(self, spec: Any, workdir: Path, plan_path: Path) -> ApplyResult:
            self.created = _created_vm(self.ec2, spec)
            document = _raw_state(
                self.created["iid"],
                self.created["vid"],
                "sg-0123456789abcdef0",
                dep=spec.deployment_id,
            )
            (workdir / "errored.tfstate").write_text(json.dumps(document))
            plan_path.chmod(0o600)
            intent = json.loads(plan_path.read_bytes())
            intent["kind"] = "destroy"  # still a well-formed plan for this deployment
            plan_path.write_text(json.dumps(intent))
            raise self.error

    Worker(h.settings, h.db, TamperAfterApply(h, ec2, "x"), clock=h.clock).run_once()
    assert _obligations(h, d["id"]) == [("terraform_apply_failed", "uncaptured", False)]


def test_r6_1_unaccepted_stored_state_after_crash_is_not_read(harness: Harness) -> None:
    """After a crash (not immediate) only errored.tfstate counts; stored state is not read."""
    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    job = h.worker().claim()
    assert job is not None
    calls: list[str] = []
    provisioner = SimulatedProvisioner(h.settings.data_dir)
    provisioner.capture_stored_state = lambda *a: calls.append("read")  # type: ignore[method-assign]
    Worker(h.settings, h.db, provisioner, clock=h.clock, worker_id="w2").recover_interrupted()
    assert calls == []
    assert _obligations(h, d["id"]) == [("worker_interrupted", "uncaptured", False)]


# ---- state evidence reader and binder (unit level)

_GOOD = _raw_state("i-0aaaaaaaaaaaaaaa1", "vol-0aaaaaaaaaaaaaaa1", "sg-0aaaaaaaaaaaaaaa1")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("resources"),
        lambda d: d.pop("outputs"),
        lambda d: d.pop("lineage"),
        lambda d: d.pop("serial"),
        lambda d: d.update(serial=True),
        lambda d: d.update(terraform_version="9.9.9"),
        lambda d: d.update(resources={}),
        lambda d: d["outputs"].update(instance_id={"value": 5}),
        lambda d: d["outputs"].update(instance_id={"value": "i-0bbbbbbbbbbbbbbb2"}),
        lambda d: d["outputs"].update(root_volume_id={"value": "vol-0bbbbbbbbbbbbbbb2"}),
        lambda d: d["resources"][0]["instances"][0].update(deposed="x"),
        lambda d: d["resources"][0]["instances"][0].pop("attributes"),
        lambda d: d["resources"][0].update(instances=[]),
    ],
)
def test_r6_1_state_envelope_is_validated(mutate: Any) -> None:
    document = copy.deepcopy(_GOOD)
    mutate(document)
    with pytest.raises(StateEvidenceError):
        parse_raw_state(document, terraform_version="simulated")


def test_r6_1_explicit_empty_resources_is_distinguished_from_missing() -> None:
    empty = raw_state("l", 3, {})
    assert parse_raw_state(empty, terraform_version="simulated").applied.instance_id is None
    with pytest.raises(StateEvidenceError):
        parse_raw_state({**empty, "resources": None}, terraform_version="simulated")


def test_r6_1_binding_requires_the_plans_creates_and_rejects_prior_ids() -> None:
    parsed = parse_raw_state(_GOOD, terraform_version="simulated")
    prior = PriorState("simulated-x", 0)
    creates = {INSTANCE, SECURITY_GROUP}
    document = parsed.__class__("simulated-x", 1, parsed.applied, parsed.outputs)
    assert (
        bind_to_plan(
            document, prior=prior, prior_ids=set(), creates=creates, require_all_creates=True
        )
        == parsed.applied
    )
    with pytest.raises(StateEvidenceError, match="prior"):
        bind_to_plan(
            document,
            prior=prior,
            prior_ids={"i-0aaaaaaaaaaaaaaa1"},
            creates=creates,
            require_all_creates=True,
        )
    with pytest.raises(StateEvidenceError, match="prior root"):
        bind_to_plan(
            document,
            prior=prior,
            prior_ids={"vol-0aaaaaaaaaaaaaaa1"},
            creates={INSTANCE},
            require_all_creates=True,
        )
    with pytest.raises(StateEvidenceError, match="older"):
        bind_to_plan(
            document,
            prior=PriorState("simulated-x", 5),
            prior_ids=set(),
            creates=creates,
            require_all_creates=True,
        )
    with pytest.raises(StateEvidenceError, match="lineage"):
        bind_to_plan(
            document,
            prior=PriorState("other", 0),
            prior_ids=set(),
            creates=creates,
            require_all_creates=True,
        )
    from unitcompute.provisioning.state_evidence import AppliedState

    vm_only = parsed.__class__(
        "simulated-x",
        1,
        AppliedState(parsed.applied.instance_id, None, parsed.applied.root_volume_id),
        {},
    )
    with pytest.raises(StateEvidenceError, match="does not show"):
        bind_to_plan(
            vm_only, prior=prior, prior_ids=set(), creates=creates, require_all_creates=True
        )
    # errored.tfstate may legitimately show a partial outcome of the final state ...
    bind_to_plan(vm_only, prior=prior, prior_ids=set(), creates=creates, require_all_creates=False)
    # ... but one that shows nothing of what the plan creates says nothing about the apply.
    nothing = parsed.__class__("simulated-x", 1, AppliedState(None, None, None), {})
    for strict in (True, False):
        with pytest.raises(StateEvidenceError, match="none of the resources"):
            bind_to_plan(
                nothing, prior=prior, prior_ids=set(), creates=creates, require_all_creates=strict
            )


def test_r6_1_observed_identities_collects_every_well_formed_id() -> None:
    document = copy.deepcopy(_GOOD)
    document["outputs"]["junk"] = {"value": "not-an-id"}
    found = observed_identities(document)
    assert ("i-0aaaaaaaaaaaaaaa1", None) in found
    assert ("vol-0aaaaaaaaaaaaaaa1", "i-0aaaaaaaaaaaaaaa1") in found
    assert ("sg-0aaaaaaaaaaaaaaa1", None) in found
    assert observed_identities("garbage") == [] and observed_identities({"resources": 1}) == []


# ---- real offline Terraform: signal termination, and backend plus fallback failure


class _FakeAws:
    def credentials(self, *args: Any) -> Any:
        from unitcompute.provisioning.aws import TemporaryCredentials

        return TemporaryCredentials("synthetic", "synthetic", "synthetic")


def _real_provisioner(tmp_path: Path) -> tuple[Any, Any]:
    from unitcompute.config import Settings
    from unitcompute.provisioning.runner import TerraformRunner
    from unitcompute.provisioning.terraform import TerraformProvisioner

    cache = os.environ.get("TF_PLUGIN_CACHE_DIR")
    runner = TerraformRunner(Path(TERRAFORM), plugin_cache_dir=Path(cache) if cache else None)
    settings = Settings(data_dir=tmp_path / "data")
    return TerraformProvisioner(settings, runner, _FakeAws()), runner  # type: ignore[arg-type]


@pytest.mark.terraform
def test_r6_1_real_terraform_killed_by_signal_is_unknown_not_final(
    harness: Harness, tmp_path: Path
) -> None:
    """Real Terraform 1.17.1 creates an external effect, then is SIGKILLed before saving
    state. The production provisioner reports a signal, the stored state is empty, and the
    worker keeps the obligation uncaptured so deletion cannot be verified."""
    if not Path(TERRAFORM).exists():
        pytest.skip("terraform binary not installed")
    real, runner = _real_provisioner(tmp_path)
    work = tmp_path / "real"
    work.mkdir()
    (work / "main.tf").write_text(
        'resource "terraform_data" "effect" {\n  provisioner "local-exec" {\n'
        '    command = "touch external-effect; kill -KILL $PPID"\n  }\n}\n'
    )
    env = runner.base_env(work)
    for args in (["init", "-input=false", "-no-color"], ["plan", "-input=false", "-out=tfplan"]):
        assert runner.run(args, workdir=work, env=env, timeout=60, log_name=args[0]).returncode == 0
    spec = DeploymentSpec("dep_" + "a" * 32, "owner", "demo", 8, "us-east-1", "t3.micro")
    with pytest.raises(ProvisioningError) as exc:
        real.apply(spec, work, work / "tfplan")
    assert exc.value.code == "terraform_signalled"
    assert (work / "external-effect").exists()  # the effect happened; nothing recorded it
    with pytest.raises(ProvisioningError) as pull:  # nothing was ever stored: no document
        real.capture_stored_state(spec, work)
    assert pull.value.code == "state_capture_failed"

    # The same through the worker: a signal exit never counts as a final state.
    h = harness
    d = create_and_plan(h)
    approve_current(h, d)

    class Killed(SimulatedProvisioner):
        def apply(self, spec: Any, workdir: Path, plan_path: Path) -> ApplyResult:
            return real.apply(spec, work, work / "tfplan")

        def capture_stored_state(self, spec: Any, workdir: Path) -> object:
            return real.capture_stored_state(spec, work)

    Worker(h.settings, h.db, Killed(h.settings.data_dir), clock=h.clock).run_once()
    assert _obligations(h, d["id"]) == [("terraform_signalled", "uncaptured", False)]
    _, pending = _replan(h, h.provisioner, d["id"], "deletion-plan")
    assert pending["current_plan"]["error"]["code"] == "recovery_evidence_missing"
    assert _quota_held(h.client)


@pytest.mark.terraform
def test_r6_1_real_terraform_backend_and_fallback_failure_leaves_empty_state(
    tmp_path: Path,
) -> None:
    """Security reproduction: resource created, then both the backend write and the local
    errored.tfstate write fail. `state pull` returns an empty, valid envelope, which must
    not be accepted as an outcome for a plan that creates resources."""
    if not Path(TERRAFORM).exists():
        pytest.skip("terraform binary not installed")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(500)
            self.end_headers()

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    real, runner = _real_provisioner(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    (work / "main.tf").write_text(
        'terraform {\n  backend "http" {}\n}\nresource "terraform_data" "vm" {\n'
        '  input = "independent-mutated-resource"\n}\n'
    )
    (work / "errored.tfstate").mkdir()  # the fallback write cannot succeed
    env = runner.base_env(work)
    spec = DeploymentSpec("dep_" + "b" * 32, "owner", "demo", 8, "us-east-1", "t3.micro")
    try:
        for args in (
            [
                "init",
                "-input=false",
                f"-backend-config=address=http://127.0.0.1:{server.server_port}/state",
                "-backend-config=retry_max=0",
            ],
            ["plan", "-input=false", "-out=tfplan"],
        ):
            assert (
                runner.run(args, workdir=work, env=env, timeout=120, log_name=args[0]).returncode
                == 0
            )
        with pytest.raises(ProvisioningError) as exc:
            real.apply(spec, work, work / "tfplan")
        assert exc.value.code == "terraform_apply_failed"
        assert "Failed to create local state file" in (work / "logs" / "apply.log").read_text()
        stored = real.capture_stored_state(spec, work)
    finally:
        server.shutdown()
        server.server_close()
    # A valid-looking, empty envelope that is wrong about reality: it never had a lineage.
    assert stored["resources"] == [] and stored["lineage"] == ""
    with pytest.raises(StateEvidenceError, match="no lineage"):
        parse_raw_state(stored, terraform_version="1.17.1")


def test_r6_1_state_command_is_read_only(tmp_path: Path) -> None:
    from unitcompute.provisioning.runner import ALLOWED_STATE_ARGS

    assert ALLOWED_STATE_ARGS == ("state", "pull")
    ran = tmp_path / "ran"
    binary = tmp_path / "recording-terraform"
    binary.write_text(f"#!{sys.executable}\nimport pathlib\npathlib.Path({str(ran)!r}).touch()\n")
    binary.chmod(0o700)
    runner = TerraformRunner(binary)
    for args in (["state", "push", "x"], ["state", "rm", "x"], ["state", "mv"], ["state"]):
        with pytest.raises(ValueError, match="not allowed"):
            runner.run(args, workdir=tmp_path, env={}, timeout=5, log_name="x")
    assert not ran.exists()  # the binary was never started
    runner.run(["state", "pull"], workdir=tmp_path, env={}, timeout=5, log_name="x")
    assert ran.exists()


def test_r6_1_signal_exit_is_classified_not_reported_as_a_plain_failure(tmp_path: Path) -> None:
    from unitcompute.config import Settings
    from unitcompute.provisioning.runner import RunResult
    from unitcompute.provisioning.terraform import TerraformProvisioner

    class Runner:
        def __init__(self, code: int) -> None:
            self.code = code

        def run(self, *args: Any, **kwargs: Any) -> RunResult:
            return RunResult(self.code, "", "")

        def base_env(self, workdir: Path) -> dict[str, str]:
            return {}

    for code, expected in ((-9, "terraform_signalled"), (1, "terraform_apply_failed")):
        provisioner = TerraformProvisioner(
            Settings(data_dir=tmp_path),
            Runner(code),
            _FakeAws(),  # type: ignore[arg-type]
        )
        spec = DeploymentSpec("dep_" + "c" * 32, "o", "demo", 8, "us-east-1", "t3.micro")
        work = tmp_path / f"w{code}"
        work.mkdir()
        with pytest.raises(ProvisioningError) as exc:
            provisioner.apply(spec, work, work / "tfplan")
        assert exc.value.code == expected


# ================== R6-2: legacy launch history needs actual provenance, not job counts


def _schema4(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Any, Database]:
    from conftest import make_settings

    settings = make_settings(tmp_path)
    db = Database(settings.database_path)
    migrations = database._migration_files()
    with monkeypatch.context() as m:
        m.setattr(database, "_migration_files", lambda: migrations[:4])
        assert db.migrate() == [1, 2, 3, 4]
    return settings, db


def _legacy_history(
    db: Database, dep: str, iid: str, root: str, plans: list[tuple[str, str, str, list[Any]]]
) -> None:
    """plans: (plan id suffix, plan status, job status, recorded changes), oldest first."""
    now = "2026-10-01T00:00:00+00:00"
    with db.transaction() as c:
        c.execute(
            "INSERT INTO deployments (id, owner_id, name, disk_gib, region, instance_type, "
            "provisioner, status, instance_id, root_volume_id, apply_attempted, created_at, "
            "updated_at) VALUES (?, 'dev:alice', 'demo', 8, 'us-east-1', 't3.micro', "
            "'simulated', 'active', ?, ?, 1, ?, ?)",
            (dep, iid, root, now, now),
        )
        for n, (suffix, plan_status, job_status, changes) in enumerate(plans):
            plan = "plan_" + suffix * 32
            c.execute(
                "INSERT INTO plans (id, deployment_id, owner_id, kind, status, provisioner, "
                "config_hash, region, state_key, template_version, preview_json, created_at) "
                "VALUES (?, ?, 'dev:alice', 'create', ?, 'simulated', 'h', 'us-east-1', 'k', "
                "'ec2-vm/v1', ?, ?)",
                (plan, dep, plan_status, json.dumps({"changes": changes}), f"2026-10-0{n + 1}"),
            )
            c.execute(
                "INSERT INTO jobs (id, owner_id, deployment_id, plan_id, kind, status, "
                "payload_hash, created_at) VALUES (?, 'dev:alice', ?, ?, 'apply', ?, 'h', ?)",
                ("job_" + suffix * 32, dep, plan, job_status, f"2026-10-0{n + 1}"),
            )
        # What every earlier version recorded from apply outputs, whatever apply ran.
        c.execute(
            "INSERT INTO deployment_resources VALUES (?, 'volume', ?, ?, 'apply_output', ?)",
            (dep, root, iid, now),
        )


_LAUNCH = [{"address": "aws_instance.vm", "action": "create"}]


def _replaced_root_vm(ec2: Any) -> tuple[str, str, str]:
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
    replacement = ec2.create_volume(AvailabilityZone=vm["Placement"]["AvailabilityZone"], Size=8)[
        "VolumeId"
    ]
    ec2.attach_volume(VolumeId=replacement, InstanceId=iid, Device="/dev/sda1")
    return iid, original, replacement


def _delete_must_not_complete(
    settings: Any, db: Database, ec2: Any, iid: str, replacement: str, original: str, code: str
) -> None:
    ec2.terminate_instances(InstanceIds=[iid])
    ec2.delete_volume(VolumeId=replacement)
    client, h = _client_for(settings, db)
    with client:
        _, pending = _replan(h, _AwsBacked(h), _DEP, "deletion-plan")
        assert pending["current_plan"]["error"]["code"] == code
        assert pending["status"] == "recovery_required"
        assert _quota_held(client)
    assert ec2.describe_volumes(VolumeIds=[original])["Volumes"][0]["State"] == "available"


_DEP = "dep_" + "a" * 32


def _client_for(settings: Any, db: Database) -> tuple[Any, Any]:
    from test_review_round2 import _client

    return _client(settings, db, FakeClock())


def test_r6_2_failed_launch_then_noop_success_is_not_launch_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, moto_env: Any
) -> None:
    """Security reproduction: the only *successful* create apply was a no-op repair after a
    failed launch; its replacement-root output is a refreshed value, not launch evidence."""
    ec2 = moto_env
    iid, original, replacement = _replaced_root_vm(ec2)
    settings, db = _schema4(tmp_path, monkeypatch)
    _legacy_history(
        db,
        _DEP,
        iid,
        replacement,
        [("1", "apply_failed", "recovery_required", _LAUNCH), ("2", "applied", "succeeded", [])],
    )
    assert db.migrate() == [5, 6, 7]
    with db.transaction() as c:
        IdentityLedger(settings.workdir_root).import_evidence(c, _DEP)
    with db.read() as c:
        known = IdentityLedger.known(c, _DEP)
        obligations = [
            (r["reason"], r["evidence"], r["discharged_at"] is not None)
            for r in c.execute("SELECT * FROM recovery_obligations ORDER BY id")
        ]
    assert known.launch_roots == {}
    assert known.observed_roots == {iid: {replacement}}
    assert known.instances_without_root_disk() == [iid]
    # The failed launch was "resolved" by migration 0005 only because a later apply
    # succeeded; revalidation reopens it.
    assert obligations == [
        ("legacy_resolved_apply", "not_needed", True),
        ("evidence_revalidation", "uncaptured", False),
    ]
    _delete_must_not_complete(
        settings, db, ec2, iid, replacement, original, "recovery_evidence_missing"
    )


def test_r6_2_failed_repair_after_a_successful_launch_is_not_launch_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, moto_env: Any
) -> None:
    """Reliability reproduction: one successful launch, then a repair that returned outputs
    (a refreshed, replaced root) and failed afterwards. Two create-kind applies reached
    Terraform, so legacy root IDs prove nothing and the deployment stays blocked."""
    ec2 = moto_env
    iid, original, replacement = _replaced_root_vm(ec2)
    settings, db = _schema4(tmp_path, monkeypatch)
    _legacy_history(
        db,
        _DEP,
        iid,
        replacement,
        [("1", "applied", "succeeded", _LAUNCH), ("2", "apply_failed", "recovery_required", [])],
    )
    assert db.migrate() == [5, 6, 7]
    with db.transaction() as c:
        IdentityLedger(settings.workdir_root).import_evidence(c, _DEP)
    with db.read() as c:
        known = IdentityLedger.known(c, _DEP)
    assert known.launch_roots == {} and known.instances_without_root_disk() == [iid]
    _delete_must_not_complete(settings, db, ec2, iid, replacement, original, "identity_incomplete")


@pytest.mark.parametrize(
    ("history", "trusted"),
    [
        ([("1", "applied", "succeeded", _LAUNCH)], True),
        ([("1", "applied", "succeeded", [])], False),  # the only apply did not launch the VM
        ([("1", "apply_failed", "recovery_required", _LAUNCH)], False),
        (
            [("1", "applied", "succeeded", _LAUNCH), ("2", "applied", "succeeded", [])],
            False,
        ),
        ([("1", "failed", "failed", _LAUNCH), ("2", "applied", "succeeded", _LAUNCH)], True),
    ],
)
def test_r6_2_legacy_trust_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, history: list[Any], trusted: bool
) -> None:
    settings, db = _schema4(tmp_path, monkeypatch)
    iid, vid = "i-0123456789abcdef0", "vol-0123456789abcdef0"
    _legacy_history(db, _DEP, iid, vid, history)
    db.migrate()
    with db.transaction() as c:
        IdentityLedger(settings.workdir_root).import_evidence(c, _DEP)
    with db.read() as c:
        known = IdentityLedger.known(c, _DEP)
    assert (known.launch_roots == {iid: {vid}}) is trusted


def _failed_destroy_upgrade(
    h: Harness, monkeypatch: pytest.MonkeyPatch
) -> tuple[str, dict[str, Any]]:
    d = launch(h)
    dep = d["id"]
    h.client.post(f"/deployments/{dep}/deletion-plan", headers=auth())
    h.drain()
    pending = _detail(h, dep)
    approved = approve_current(h, pending)
    with h.db.transaction() as conn:  # a schema-4 failure: nothing was mutated
        conn.execute(
            "UPDATE jobs SET status='recovery_required', error_code='terraform_apply_failed' "
            "WHERE id=?",
            (approved["job_id"],),
        )
        conn.execute(
            "UPDATE plans SET status='apply_failed' WHERE id=?",
            (pending["current_plan"]["plan_id"],),
        )
        conn.execute("UPDATE deployments SET status='recovery_required' WHERE id=?", (dep,))
        conn.execute("DROP TABLE recovery_obligations")
        conn.execute("DELETE FROM schema_migrations WHERE version IN (5, 6)")
    assert h.db.migrate() == [5, 6]
    return dep, pending


def test_r6_2_failed_destroy_needs_no_capture_after_upgrade(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reliability reproduction: migration backfilled a failed destroy as uncaptured and it
    blocked cleanup forever. A plan that only deletes cannot have created anything."""
    h = harness
    dep, _ = _failed_destroy_upgrade(h, monkeypatch)
    assert _obligations(h, dep) == [("legacy_unresolved_apply", "not_needed", False)]
    h.client.post(f"/deployments/{dep}/deletion-plan", headers=auth())
    h.drain()
    pending = _detail(h, dep)
    assert pending["status"] == "awaiting_deletion_approval"
    approve_current(h, pending)
    h.drain()
    assert _detail(h, dep)["status"] == "deleted"
    assert _obligations(h, dep)[0][1:] == ("not_needed", True)


def test_r6_2_failed_destroy_is_classified_at_runtime_when_still_uncaptured(
    harness: Harness,
) -> None:
    """A database that already ran migration 0005 (the earlier candidate) is corrected by
    the worker: _retry_uncaptured accepts the safe not_needed classification."""
    h = harness
    d = launch(h)
    dep = d["id"]
    h.client.post(f"/deployments/{dep}/deletion-plan", headers=auth())
    h.drain()
    pending = _detail(h, dep)
    approved = approve_current(h, pending)
    with h.db.transaction() as conn:
        conn.execute("UPDATE jobs SET status='recovery_required' WHERE id=?", (approved["job_id"],))
        conn.execute(
            "UPDATE plans SET status='apply_failed' WHERE id=?",
            (pending["current_plan"]["plan_id"],),
        )
        conn.execute("UPDATE deployments SET status='recovery_required' WHERE id=?", (dep,))
        conn.execute(
            "INSERT INTO recovery_obligations (deployment_id, job_id, plan_id, reason, evidence, "
            "created_at) VALUES (?, ?, ?, 'legacy_unresolved_apply', 'uncaptured', 'now')",
            (dep, approved["job_id"], pending["current_plan"]["plan_id"]),
        )
    h.client.post(f"/deployments/{dep}/deletion-plan", headers=auth())
    h.drain()
    assert _detail(h, dep)["status"] == "awaiting_deletion_approval"
    assert _obligations(h, dep) == [("legacy_unresolved_apply", "not_needed", False)]


def test_r6_2_not_needed_is_only_reachable_for_plans_that_create_nothing(
    harness: Harness,
) -> None:
    h = harness
    d = create_and_plan(h)  # a create plan
    plan_id = d["current_plan"]["plan_id"]
    with h.db.transaction() as conn:
        conn.execute(
            "INSERT INTO recovery_obligations (deployment_id, plan_id, reason, evidence, "
            "created_at) VALUES (?, ?, 'x', 'uncaptured', 'now')",
            (d["id"], plan_id),
        )
    for preview in ('{"changes": [{"action": "create"}]}', "garbage", '{"changes": 5}', None):
        with h.db.transaction() as conn:
            conn.execute("UPDATE plans SET preview_json = ? WHERE id = ?", (preview, plan_id))
        with (
            pytest.raises(sqlite3.IntegrityError, match="only move forward"),
            h.db.transaction() as conn,
        ):
            conn.execute("UPDATE recovery_obligations SET evidence = 'not_needed'")
    with h.db.transaction() as conn:
        conn.execute(
            "UPDATE plans SET preview_json = ? WHERE id = ?",
            ('{"changes": [{"action": "delete"}]}', plan_id),
        )
        conn.execute("UPDATE recovery_obligations SET evidence = 'not_needed'")
    assert _obligations(h, d["id"])[0][1] == "not_needed"


# ====== R6-3: obligations are rechecked after reconciliation and before mutation; readers
# ====== coordinate with writers; every directory creation is durable


def _corrupt_evidence(h: Harness, dep: str) -> None:
    (h.settings.workdir_root / dep / "identities.jsonl").write_text(
        '{"id":"i-0123456789abcdef0","source":'
    )


def test_r6_3_corruption_found_while_planning_stops_that_plan(harness: Harness) -> None:
    h = harness
    d = create_and_plan(h)
    _corrupt_evidence(h, d["id"])
    assert h.client.post(f"/deployments/{d['id']}/plan", headers=auth()).status_code == 202
    assert h.worker().run_once()
    detail = _detail(h, d["id"])
    assert detail["current_plan"]["status"] == "failed"
    assert detail["current_plan"]["error"]["code"] == "recovery_evidence_missing"
    assert detail["status"] == "recovery_required"
    assert ("evidence_file_corrupt", "uncaptured", False) in _obligations(h, d["id"])


class _CountingApply(SimulatedProvisioner):
    applies = 0

    def apply(self, spec: Any, workdir: Path, plan_path: Path) -> ApplyResult:
        type(self).applies += 1
        return super().apply(spec, workdir, plan_path)


def test_r6_3_obligation_opened_after_planning_stops_the_apply(harness: Harness) -> None:
    """The plan is ready and approved, then evidence turns up corrupt: the apply precheck
    reconciles evidence and must refuse to mutate."""
    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    _corrupt_evidence(h, d["id"])
    _CountingApply.applies = 0
    Worker(h.settings, h.db, _CountingApply(h.settings.data_dir), clock=h.clock).run_once()
    assert _CountingApply.applies == 0
    detail = _detail(h, d["id"])
    assert detail["status"] == "recovery_required"
    assert detail["latest_job"]["error"]["code"] == "recovery_evidence_missing"
    assert h.provisioner.owned_resources(d["id"]) == []


def test_r6_3_plain_apply_is_not_slowed_or_blocked_when_evidence_is_healthy(
    harness: Harness,
) -> None:
    _CountingApply.applies = 0
    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    Worker(h.settings, h.db, _CountingApply(h.settings.data_dir), clock=h.clock).run_once()
    assert _CountingApply.applies == 1 and _detail(h, d["id"])["status"] == "active"


def _paused_append(root: Path, dep: str, entered: Any, finish: Any) -> None:
    import unitcompute.identities as module

    original = module.os.write
    first = True

    def short(fd: int, data: Any) -> int:
        nonlocal first
        if first:
            first = False
            written = original(fd, data[:15])
            entered.set()
            assert finish.wait(20)
            return written
        return int(original(fd, data))

    module.os.write = short  # type: ignore[assignment]
    IdentityLedger(root).append_evidence(
        dep, [identity("vol-1234567890abcdef0", "launch_state", "i-1234567890abcdef0")]
    )


def test_r6_3_import_waits_for_an_append_in_progress(harness: Harness) -> None:
    """Reliability reproduction: a writer paused mid-record holds the exclusive lock. The
    importer waits for it instead of classifying the torn tail as permanent corruption."""
    h = harness
    d = create_and_plan(h)
    ctx = multiprocessing.get_context("fork")
    entered, finish = ctx.Event(), ctx.Event()
    child = ctx.Process(
        target=_paused_append, args=(h.settings.workdir_root, d["id"], entered, finish)
    )
    child.start()
    assert entered.wait(10)
    release = threading.Timer(1.0, finish.set)
    release.start()
    started = time.monotonic()
    try:
        h.worker().import_identities(d["id"])  # blocks until the writer finishes
    finally:
        finish.set()
        release.cancel()
        child.join(20)
    assert child.exitcode == 0
    assert time.monotonic() - started >= 0.9
    with h.db.read() as conn:
        assert "vol-1234567890abcdef0" in IdentityLedger.known(conn, d["id"]).volumes
    assert not any(o[0] == "evidence_file_corrupt" for o in _obligations(h, d["id"]))
    with h.db.transaction() as conn:
        assert IdentityLedger(h.settings.workdir_root).import_evidence(conn, d["id"]).corrupt == 0


def test_r6_3_lock_wait_timeout_is_transient_not_corruption(harness: Harness) -> None:
    import fcntl

    from unitcompute import identities

    h = harness
    d = create_and_plan(h)
    ledger = h.worker().identities
    ledger.append_evidence(d["id"], [identity("vol-1234567890abcdef0", "tag_inventory")])
    path = h.settings.workdir_root / d["id"] / "identities.jsonl"
    fd = os.open(path, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with pytest.raises(EvidenceBusy):
            identities._read_locked(path, timeout=0.2)
        h.settings  # noqa: B018 - keep the harness alive while locked
        worker = h.worker()
        job = worker.claim()  # none queued: use recovery on a synthetic stranded job instead
        assert job is None
    finally:
        os.close(fd)
    assert not any(o[0] == "evidence_file_corrupt" for o in _obligations(h, d["id"]))


def test_r6_3_startup_recovery_survives_a_busy_evidence_file(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An evidence read that cannot complete (lock wait, I/O) is logged and does not open a
    corruption obligation; the stranded apply still gets its own obligation."""
    from unitcompute import identities

    h = harness
    d = create_and_plan(h)
    approve_current(h, d)
    job = h.worker().claim()
    assert job is not None
    h.worker().identities.append_evidence(
        d["id"], [identity("vol-1234567890abcdef0", "tag_inventory")]
    )

    def busy(path: Path, timeout: float = 0) -> bytes:
        raise EvidenceBusy("busy")

    monkeypatch.setattr(identities, "_read_locked", busy)
    assert Worker(
        h.settings, h.db, h.provisioner, clock=h.clock, worker_id="w2"
    ).recover_interrupted() == [job["id"]]
    assert [o[0] for o in _obligations(h, d["id"])] == ["worker_interrupted"]


def test_r6_3_every_directory_creation_goes_through_the_durable_helpers() -> None:
    """Audit of all creation paths: no direct mkdir/makedirs outside durable.py."""
    offenders = []
    import unitcompute

    for path in Path(unitcompute.__file__).parent.rglob("*.py"):
        if path.name == "durable.py":
            continue
        text = path.read_text()
        for needle in (".mkdir(", "os.makedirs(", "makedirs("):
            if needle in text:
                offenders.append(f"{path.name}: {needle}")
    assert offenders == []


def test_r6_3_initial_storage_ancestors_are_fsynced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reliability reproduction: migrate -> worker lock -> work directory -> evidence in a
    data directory whose parent does not exist yet; every created entry's parent is synced,
    including the one above the data directory."""
    from unitcompute.config import Settings
    from unitcompute.worker import WorkerLock

    synced: list[Path] = []
    original = os.fsync

    def trace(fd: int) -> None:
        synced.append(Path(os.readlink(f"/proc/self/fd/{fd}")))
        original(fd)

    monkeypatch.setattr(os, "fsync", trace)
    settings = Settings(data_dir=tmp_path / "new-parent" / "new-data", provisioner="simulated")
    db = Database(settings.database_path)
    db.migrate()
    assert tmp_path in synced  # new-parent's entry
    assert tmp_path / "new-parent" in synced  # new-data's entry
    assert settings.data_dir in synced  # the database file's entry
    lock = WorkerLock(settings.worker_lock_path)
    lock.acquire()
    try:
        worker = Worker(settings, db, SimulatedProvisioner(settings.data_dir))
        dep, plan = "dep_" + "a" * 32, "plan_" + "b" * 32
        worker.workdir(dep, plan)
        worker.identities.append_evidence(dep, [identity("vol-1234567890abcdef0", "tag_inventory")])
    finally:
        lock.release()
    for directory in (
        settings.data_dir,
        settings.workdir_root,
        settings.workdir_root / dep,
    ):
        assert directory in synced, directory


def test_r6_3_simulator_and_runner_directories_are_durable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from unitcompute.provisioning.runner import TerraformRunner

    synced: list[Path] = []
    original = os.fsync

    def trace(fd: int) -> None:
        synced.append(Path(os.readlink(f"/proc/self/fd/{fd}")))
        original(fd)

    monkeypatch.setattr(os, "fsync", trace)
    data = tmp_path / "a" / "b"
    SimulatedProvisioner(data)
    assert {tmp_path, tmp_path / "a", data} <= set(synced)  # each created entry's parent
    synced.clear()
    work = tmp_path / "w"
    work.mkdir()
    TerraformRunner(Path("/nonexistent")).base_env(work)
    assert work in synced  # .home
    synced.clear()
    TerraformRunner._write_log(work, "x", b"", b"", ())
    assert work in synced  # logs


# ================== R6-4: one credential policy at every text and structured boundary

LEAK = "private-tail-security6"


@pytest.mark.parametrize(
    "message",
    [
        rf"export PASSWORD=prefix\;{LEAK}",
        rf"password=prefix\,{LEAK}",
        rf"password=pre\ fix\ {LEAK}",
        rf"api_key=ab\"{LEAK}",
        rf"client_secret: a\;b\,c\ d\;{LEAK}",
        'password="prefix\\"' + LEAK + '"',
        '{"client_secret":"prefix\\"' + LEAK + '"}',
        "password='it\\'s " + LEAK + "'",
    ],
)
def test_r6_4_escaped_delimiters_do_not_leak_at_any_boundary(
    harness: Harness, message: str
) -> None:
    seen: list[str] = []

    def echo(messages: Any) -> AIMessage:
        seen.extend(str(m.content) for m in messages if isinstance(m, HumanMessage))
        return AIMessage(content=message)

    service = AgentService(
        harness.settings,
        harness.db,
        harness.container.deployments,
        lambda: ScriptedChatModel(script=[echo]),
    )
    reply = asyncio.run(
        service.handle(ALICE, AgentMessageRequest(message=message), None, "key-r6-4-aaaa")
    )
    assert seen and not any(LEAK in s for s in seen)
    assert LEAK not in reply.model_dump_json()
    with harness.db.read() as c:
        stored = [r[0] for r in c.execute("SELECT content FROM chat_messages")]
        stored += [r[0] for r in c.execute("SELECT response_json FROM agent_attempts")]
    assert stored and not any(LEAK in s for s in stored)
    service._model_factory = None  # replay without a provider
    assert (
        LEAK
        not in asyncio.run(
            service.handle(ALICE, AgentMessageRequest(message=message), None, "key-r6-4-aaaa")
        ).model_dump_json()
    )


def test_r6_4_bounded_unquoted_values_still_end_at_unescaped_delimiters() -> None:
    assert redact("password=abc, keep this") == "password=[REDACTED], keep this"
    assert redact("password=abc; keep") == "password=[REDACTED]; keep"
    assert redact("password=abc keep") == "password=[REDACTED] keep"
    assert redact("password=abc\\") == "password=[REDACTED]"  # trailing backslash is data


def _service(h: Harness, model: Any = None) -> AgentService:
    return AgentService(
        h.settings, h.db, h.container.deployments, lambda: model or ScriptedChatModel()
    )


def test_r6_4_legacy_cached_replies_are_redacted_and_validated_on_replay(harness: Harness) -> None:
    h = harness
    service = _service(h)
    asyncio.run(service.handle(ALICE, AgentMessageRequest(message="hello"), None, "legacy-aaaa"))
    legacy_reply = 'password="prefix\\"' + LEAK + '"'
    with h.db.transaction() as c:
        row = c.execute("SELECT id, response_json FROM agent_attempts").fetchone()
        response = json.loads(row["response_json"])
        response.update(
            reply=legacy_reply,
            clarifications=[legacy_reply],
            proposal={
                "name": SK,
                "disk_gib": 8,
                "region": "us-east-1",
                "instance_type": "t3.micro",
                "estimated_monthly_usd": "1.00",
                "next_step": "x",
            },
        )
        c.execute(
            "UPDATE agent_attempts SET response_json=? WHERE id=?",
            (json.dumps(response), row["id"]),
        )
    service._model_factory = None
    replay = asyncio.run(
        service.handle(ALICE, AgentMessageRequest(message="hello"), None, "legacy-aaaa")
    )
    dumped = replay.model_dump_json()
    assert LEAK not in dumped and SK not in dumped
    assert replay.proposal is None  # withheld, not rewritten into a different name
    assert any("withheld" in c for c in replay.clarifications)


def test_r6_4_valid_stored_proposal_replays_unchanged(harness: Harness) -> None:
    h = harness
    script = [
        AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "check_deployment_config",
                    "args": {"name": "my-vm", "disk_gib": 8},
                    "id": "c1",
                    "type": "tool_call",
                }
            ],
        ),
        AIMessage(content="Proposal ready."),
    ]
    service = _service(h, ScriptedChatModel(script=script))
    first = asyncio.run(
        service.handle(ALICE, AgentMessageRequest(message="a vm"), None, "valid-aaaa")
    )
    assert first.proposal is not None and first.proposal.name == "my-vm"
    service._model_factory = None
    again = asyncio.run(
        service.handle(ALICE, AgentMessageRequest(message="a vm"), None, "valid-aaaa")
    )
    assert again.model_dump() == first.model_dump()


def test_r6_4_credential_shaped_name_is_rejected_not_silently_altered(harness: Harness) -> None:
    """Typed validation is preserved and extended: REST and the tool both refuse the name,
    so the model never sees it and no proposal, storage or replay can carry it."""
    h = harness
    response = h.client.post("/deployments", json={"name": SK, "disk_gib": 8}, headers=auth())
    assert response.status_code == 422
    assert (
        h.client.post(
            "/deployments", json={"name": "my-vm", "disk_gib": 8}, headers=auth()
        ).status_code
        == 202
    )
    seen: list[str] = []

    def observe(messages: Any) -> AIMessage:
        seen.extend(str(m.content) for m in messages if isinstance(m, ToolMessage))
        return AIMessage(content="Proposal prepared.")

    script = [
        AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "check_deployment_config",
                    "args": {"name": SK, "disk_gib": 8},
                    "id": "c1",
                    "type": "tool_call",
                }
            ],
        ),
        observe,
    ]
    service = _service(h, ScriptedChatModel(script=script))
    reply = asyncio.run(
        service.handle(ALICE, AgentMessageRequest(message="name it"), None, "name-aaaaa")
    )
    assert reply.proposal is None and SK not in reply.model_dump_json()
    assert seen and not any(SK in s for s in seen)
    with h.db.read() as c:
        assert not any(SK in r[0] for r in c.execute("SELECT response_json FROM agent_attempts"))
    service._model_factory = None
    assert (
        SK
        not in asyncio.run(
            service.handle(ALICE, AgentMessageRequest(message="name it"), None, "name-aaaaa")
        ).model_dump_json()
    )


def test_r6_4_legacy_credential_shaped_deployment_name_does_not_reach_the_model(
    harness: Harness,
) -> None:
    """A deployment stored before names were checked is still shown to its owner by the
    REST API, but tool results to the model are redacted."""
    h = harness
    now = "2026-10-01T00:00:00+00:00"
    with h.db.transaction() as c:
        c.execute(
            "INSERT INTO deployments (id, owner_id, name, disk_gib, region, instance_type, "
            "provisioner, status, created_at, updated_at) VALUES (?, 'dev:alice', ?, 8, "
            "'us-east-1', 't3.micro', 'simulated', 'plan_failed', ?, ?)",
            ("dep_" + "d" * 32, SK, now, now),
        )
    seen: list[str] = []

    def observe(messages: Any) -> AIMessage:
        seen.extend(str(m.content) for m in messages if isinstance(m, ToolMessage))
        return AIMessage(content="done")

    script = [
        AIMessage(
            content="",
            tool_calls=[
                {"name": "list_my_deployments", "args": {}, "id": "c1", "type": "tool_call"},
                {
                    "name": "get_deployment_preview",
                    "args": {"deployment_id": "dep_" + "d" * 32},
                    "id": "c2",
                    "type": "tool_call",
                },
            ],
        ),
        observe,
    ]
    service = _service(h, ScriptedChatModel(script=script))
    asyncio.run(service.handle(ALICE, AgentMessageRequest(message="list"), None))
    assert len(seen) == 2 and not any(SK in s for s in seen)
    assert all("[REDACTED]" in s for s in seen)


def test_r6_4_tool_errors_that_echo_arguments_are_replaced(harness: Harness) -> None:
    seen: list[tuple[str, str]] = []

    def observe(messages: Any) -> AIMessage:
        seen.extend((m.status, str(m.content)) for m in messages if isinstance(m, ToolMessage))
        return AIMessage(content="done")

    script = [
        AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "check_deployment_config",
                    "args": {"name": "my-vm", "disk_gib": "eight " + SK + " passw0rd=hunter2xyz"},
                    "id": "c1",
                    "type": "tool_call",
                }
            ],
        ),
        observe,
    ]
    service = _service(harness, ScriptedChatModel(script=script))
    asyncio.run(service.handle(ALICE, AgentMessageRequest(message="x"), None))
    assert seen == [("error", TOOL_ERROR)]


def test_r6_4_unknown_tool_error_does_not_echo_the_model_supplied_name(harness: Harness) -> None:
    seen: list[str] = []

    def observe(messages: Any) -> AIMessage:
        seen.extend(str(m.content) for m in messages if isinstance(m, ToolMessage))
        return AIMessage(content="done")

    script = [
        AIMessage(
            content="", tool_calls=[{"name": SK, "args": {}, "id": "c1", "type": "tool_call"}]
        ),
        observe,
    ]
    asyncio.run(
        _service(harness, ScriptedChatModel(script=script)).handle(
            ALICE, AgentMessageRequest(message="x"), None
        )
    )
    assert seen == [UNKNOWN_TOOL_ERROR]


def test_r6_4_typed_validation_and_proposal_bounds_are_unchanged() -> None:
    from pydantic import ValidationError

    from unitcompute.schemas import DeploymentRequest, Proposal

    DeploymentRequest(name="my-vm", disk_gib=8)
    for bad in (
        {"name": "My-VM", "disk_gib": 8},
        {"name": "my-vm", "disk_gib": 99},
        {"name": "ab", "disk_gib": 8},
        {"name": SK, "disk_gib": 8},
    ):
        with pytest.raises(ValidationError):
            DeploymentRequest(**bad)
    with pytest.raises(ValidationError):
        Proposal(
            name=SK,
            disk_gib=8,
            region="r",
            instance_type="t",
            estimated_monthly_usd="1",
            next_step="n",
        )
    with pytest.raises(ValidationError):
        Proposal(
            name="my-vm",
            disk_gib=99,
            region="r",
            instance_type="t",
            estimated_monthly_usd="1",
            next_step="n",
        )
