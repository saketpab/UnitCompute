"""Mutation check: remove each critical guard in a scratch copy and confirm a test fails.

    uv run python scripts/check_guards.py [--only NAME ...]

Each mutation edits a copy of ``src/`` and runs the named tests against it. A mutation
that still passes ("SURVIVED") means the guard is not actually tested. Exit status is
non-zero if any mutation survives or no longer applies.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Mutation:
    name: str
    edits: tuple[tuple[str, str, str], ...]  # (path under src/unitcompute, old, new)
    tests: tuple[str, ...]


SVC = "services/deployments.py"
WORKER = "worker.py"
POLICY = "provisioning/policy.py"
MUTATIONS = [
    Mutation(
        "owner-scoping",
        (
            (
                SVC,
                '"SELECT * FROM deployments WHERE id = ? AND owner_id = ?",',
                '"SELECT * FROM deployments WHERE id = ? AND ? IS NOT NULL",',
            ),
        ),
        ("tests/test_authorization.py::test_cross_user_access_is_non_enumerating",),
    ),
    Mutation(
        "approve-hash",
        (
            (
                SVC,
                'if not hmac.compare_digest(plan["plan_hash"] or "", approval.plan_hash):',
                "if False:",
            ),
        ),
        ("tests/test_approval.py::test_tampered_hash_rejected",),
    ),
    Mutation(
        "approve-expiry",
        ((SVC, 'if from_db_time(plan["expires_at"]) <= now_dt:', "if False:"),),
        ("tests/test_approval.py::test_expired_plan_cannot_be_approved",),
    ),
    Mutation(
        "approve-replay",
        ((SVC, 'if plan["status"] != "ready":', "if False:"),),
        ("tests/test_approval.py::test_approval_replay_does_not_create_second_job",),
    ),
    Mutation(
        "approve-plan-type",
        ((SVC, 'if deployment["status"] != APPROVABLE_STATUS[plan["kind"]]:', "if False:"),),
        ("tests/test_approval.py::test_destroy_plan_cannot_be_approved_as_create",),
    ),
    Mutation(
        "approve-versions",
        ((SVC, "or plan_versions(plan) != expected_versions(", "or False and expected_versions("),),
        ("tests/test_approval.py::test_stale_template_version_rejected",),
    ),
    Mutation(
        "quota-check-and-index",
        (
            (SVC, "if live is not None:", "if False:"),
            (
                "db/migrations/0001_initial.sql",
                "CREATE UNIQUE INDEX deployments_one_live_per_owner\n    ON deployments (owner_id) "
                "WHERE status <> 'deleted';",
                "",
            ),
        ),
        (
            "tests/test_lifecycle_api.py::test_quota_one_live_vm_per_user",
            "tests/test_idempotency_and_races.py::test_concurrent_creates_reserve_quota_once",
        ),
    ),
    Mutation(
        "idempotency-payload",
        ((SVC, 'if not hmac.compare_digest(row["payload_hash"], payload_hash):', "if False:"),),
        ("tests/test_idempotency_and_races.py::test_same_key_different_payload_conflicts",),
    ),
    Mutation(
        "worker-hash",
        ((WORKER, 'if sha256_file(plan_path) != plan["plan_hash"]:', "if False:"),),
        ("tests/test_approval.py::test_worker_rejects_plan_file_modified_after_approval",),
    ),
    Mutation(
        "worker-expiry",
        ((WORKER, 'if from_db_time(plan["expires_at"]) <= now:', "if False:"),),
        ("tests/test_approval.py::test_worker_rejects_plan_that_expired_in_queue",),
    ),
    Mutation(
        "worker-approver",
        ((WORKER, '== plan["owner_id"] == plan["approved_by"]', '== plan["owner_id"]'),),
        ("tests/test_approval.py::test_worker_rejects_approval_by_someone_else",),
    ),
    Mutation(
        "worker-delete-verification",
        ((WORKER, "        if remaining:", "        if False:"),),
        (
            "tests/test_worker_recovery.py::"
            "test_deletion_only_completes_when_resources_verified_gone",
        ),
    ),
    Mutation(
        "worker-lock-unlock",
        (
            (
                WORKER,
                "        if self.fd is not None:\n            os.close",
                "        if self.fd is not None:\n"
                "            fcntl.flock(self.fd, fcntl.LOCK_UN)\n"
                "            os.close",
            ),
        ),
        ("tests/test_worker_recovery.py::test_single_worker_lock",),
    ),
    Mutation(
        "recovery-sticky",
        (
            (
                WORKER,
                '            "recovery_required"\n            if unresolved',
                '            "plan_failed"\n            if unresolved',
            ),
        ),
        ("tests/test_worker_recovery.py::test_failed_repair_preview_keeps_recovery_status",),
    ),
    Mutation(
        "agent-daily-cap",
        (
            (
                "agent/service.py",
                "if recent >= self._settings.agent_max_messages_per_day:",
                "if False:",
            ),
        ),
        ("tests/test_agent.py::test_daily_message_cap_per_owner",),
    ),
    Mutation(
        "policy-imdsv2",
        ((POLICY, 'metadata.get("http_tokens") == "required"', "True"),),
        ("tests/test_policy.py::test_policy_rejects_mutation[imdsv1]",),
    ),
    Mutation(
        "policy-ingress",
        ((POLICY, 'after.get("ingress") == []', "True"),),
        ("tests/test_policy.py::test_policy_rejects_mutation[ssh_ingress]",),
    ),
    Mutation(
        "policy-actions",
        ((POLICY, "if actions not in ALLOWED_ACTIONS[kind]:", "if False:"),),
        ("tests/test_policy.py::test_replace_or_update_of_owned_resources_rejected",),
    ),
    Mutation(
        "policy-orphans",
        ((POLICY, "    if orphans:", "    if False:"),),
        ("tests/test_policy.py::test_orphaned_resources_require_operator",),
    ),
    Mutation(
        "policy-provider-args",
        (
            (
                POLICY,
                'if not set(aws.get("expressions") or {}) <= ALLOWED_PROVIDER_ARGUMENTS:',
                "if False:",
            ),
        ),
        ("tests/test_policy.py::test_plan_level_violations",),
    ),
    Mutation(
        "jwt-audience",
        (
            (
                "auth.py",
                'options={"require": ["exp", "iat", "iss", "aud", "sub"]},',
                'options={"require": ["exp", "iat", "iss", "aud", "sub"], "verify_aud": False},',
            ),
        ),
        ("tests/test_config_and_auth.py::test_invalid_jwt_claims",),
    ),
    Mutation(
        "jwt-group",
        (
            (
                "auth.py",
                "if not isinstance(groups, list) or self._group not in groups:",
                "if False:",
            ),
        ),
        ("tests/test_config_and_auth.py::test_jwt_requires_team_group",),
    ),
    Mutation(
        "prod-dev-auth",
        (("config.py", "if production and self.auth_mode is not AuthMode.JWT:", "if False:"),),
        ("tests/test_config_and_auth.py::test_production_fails_closed",),
    ),
    Mutation(
        "runner-shell",
        (("provisioning/runner.py", "shell=False,", "shell=True,"),),
        ("tests/test_runner_and_terraform.py::test_arguments_are_not_shell_interpreted",),
    ),
    Mutation(
        "runner-env",
        (("provisioning/runner.py", "env=dict(env),", "env={**os.environ, **env},"),),
        ("tests/test_runner_and_terraform.py::test_environment_is_controlled",),
    ),
    Mutation(
        "body-limit",
        (("api/app.py", "if received > self.max_bytes:", "if False:"),),
        ("tests/test_api_platform.py::test_body_size_limit_streamed",),
    ),
    Mutation(
        "agent-proposal-validation",
        (
            (
                "agent/service.py",
                "request = DeploymentRequest(name=name, disk_gib=disk_gib)",
                "request = DeploymentRequest.model_construct(name=name, disk_gib=disk_gib)",
            ),
        ),
        ("tests/test_agent.py::test_invalid_values_become_clarifications",),
    ),
]


def run(mutation: Mutation, workspace: Path) -> str:
    src = workspace / "src"
    shutil.rmtree(src, ignore_errors=True)
    shutil.copytree(ROOT / "src", src)
    for relative, old, new in mutation.edits:
        path = src / "unitcompute" / relative
        text = path.read_text()
        if text.count(old) != 1:
            return "NOT-APPLICABLE"
        path.write_text(text.replace(old, new))
    env = {**os.environ, "PYTHONPATH": str(src), "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *mutation.tests],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    return "KILLED" if result.returncode != 0 else "SURVIVED"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", nargs="*")
    args = parser.parse_args()
    selected = [m for m in MUTATIONS if not args.only or m.name in args.only]
    failures = 0
    with tempfile.TemporaryDirectory(prefix="unitcompute-mutants-") as tmp:
        shutil.copytree(ROOT / "src", Path(tmp) / "src")
        probe = subprocess.run(
            [sys.executable, "-c", "import unitcompute; print(unitcompute.__file__)"],
            env={**os.environ, "PYTHONPATH": str(Path(tmp) / "src")},
            capture_output=True,
            text=True,
            check=False,
        )
        if not probe.stdout.startswith(tmp):
            print(f"mutants would not be imported (got {probe.stdout.strip()})")
            return 2
        for mutation in selected:
            outcome = run(mutation, Path(tmp))
            failures += outcome != "KILLED"
            print(f"{outcome:15} {mutation.name}")
    print(f"{len(selected) - failures}/{len(selected)} guards proven by a failing test")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
