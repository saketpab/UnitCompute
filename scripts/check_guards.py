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
                "if attempts >= self._settings.agent_max_messages_per_day:",
                "if False:",
            ),
        ),
        ("tests/test_agent.py::test_daily_message_cap_per_owner",),
    ),
    Mutation(
        "s1-terraform-needs-jwt",
        (
            (
                "config.py",
                "if self.provisioner is ProvisionerKind.TERRAFORM and (",
                "if False and (",
            ),
        ),
        ("tests/test_review_round1.py::test_s1_real_provisioning_requires_verified_team_auth",),
    ),
    Mutation(
        "r3-daily-reservation",
        (
            (
                "agent/service.py",
                "if attempts >= self._settings.agent_max_messages_per_day:",
                "if False:",
            ),
        ),
        ("tests/test_review_round1.py::test_r3_concurrent_requests_cannot_exceed_daily_cap",),
    ),
    Mutation(
        "r3-session-turn-reservation",
        (
            (
                "agent/service.py",
                '"UPDATE chat_sessions SET turns = turns + 1, updated_at = ? WHERE id = ?",',
                '"UPDATE chat_sessions SET updated_at = ? WHERE id = ?",',
            ),
        ),
        ("tests/test_review_round1.py::test_r3_concurrent_requests_cannot_exceed_session_turns",),
    ),
    Mutation(
        "r3-failed-attempts-counted",
        (
            (
                "agent/service.py",
                "                        \"UPDATE agent_attempts SET status = 'failed', "
                'idempotency_key = NULL, "',
                '                        "DELETE FROM agent_attempts WHERE 1 = 1 OR "',
            ),
        ),
        ("tests/test_review_round1.py::test_r3_failed_attempts_stay_counted",),
    ),
    Mutation(
        "r6-chat-idempotency",
        (("agent/service.py", 'if prior["status"] == "succeeded":', "if False:"),),
        (
            "tests/test_review_round1.py::test_r6_chat_idempotency_replays_without_second_model_call",
        ),
    ),
    Mutation(
        "s3-approval-binding",
        (
            (
                SVC,
                "                binding = binding_problem(self._settings, plan)\n"
                "                if binding:",
                "                binding = binding_problem(self._settings, plan)\n"
                "                if False:",
            ),
        ),
        ("tests/test_review_round1.py::test_s3_changed_execution_config_invalidates_approval",),
    ),
    Mutation(
        "s3-worker-binding",
        (
            (
                WORKER,
                "        binding = binding_problem(self.settings, plan)\n        if binding:",
                "        binding = binding_problem(self.settings, plan)\n        if False:",
            ),
        ),
        ("tests/test_review_round1.py::test_s3_worker_rechecks_execution_config",),
    ),
    Mutation(
        "s4-provisioners",
        ((POLICY, 'if resource.get("provisioners"):', "if False:"),),
        ("tests/test_review_round1.py::test_s4_provisioners_rejected",),
    ),
    Mutation(
        "s4-group-attachment",
        ((POLICY, "if group_id is not None and groups == [group_id]:", "if True:"),),
        ("tests/test_review_round1.py::test_s4_existing_instance_must_use_its_own_group",),
    ),
    Mutation(
        "s4-root-attributes",
        (
            (
                POLICY,
                'extra_root = sorted(set(_first(after.get("root_block_device"))) - '
                "ROOT_CREATE_FIELDS)",
                "extra_root: list[str] = []",
            ),
        ),
        ("tests/test_review_round1.py::test_s4_unreviewed_instance_attributes_rejected",),
    ),
    Mutation(
        "r1-delete-by-id",
        (
            (
                WORKER,
                "            found = self.provisioner.find_resources(known.all_ids)",
                "            found = []",
            ),
        ),
        ("tests/test_review_round1.py::test_r1_retained_untagged_root_volume_blocks_deletion",),
    ),
    Mutation(
        "r2-stranded-recovery",
        ((WORKER, "        if self._has_stranded_jobs():", "        if False:"),),
        ("tests/test_review_round1.py::test_r2_persistent_contention_recovers_without_replay",),
    ),
    Mutation(
        "r2-write-retry",
        ((WORKER, "        delays = [*self.write_retry_delays, None]", "        delays = [None]"),),
        ("tests/test_review_round1.py::test_r2_transient_contention_is_retried",),
    ),
    Mutation(
        "r4-ready-needs-worker",
        (("api/app.py", "ready = ready and recent and healthy", "ready = ready"),),
        ("tests/test_review_round1.py::test_r4_not_ready_without_worker",),
    ),
    Mutation(
        "r4-health-gate",
        (
            (
                WORKER,
                "if self._self_check_due() and not self.self_check():\n            return False\n"
                "        if not self._healthy:\n            return False",
                "if self._self_check_due():\n            self.self_check()",
            ),
        ),
        ("tests/test_review_round1.py::test_r4_unhealthy_worker_takes_no_jobs",),
    ),
    Mutation(
        "r4-role-identity",
        (
            (
                "provisioning/aws.py",
                "if account != self._settings.aws_account_id or not "
                "caller.startswith(expected_prefix):",
                "if False:",
            ),
        ),
        ("tests/test_review_round1.py::test_r4_role_identity_verification",),
    ),
    Mutation(
        "r5-connection-ready",
        ((WORKER, "int(readiness.ready),", "1,"),),
        (
            "tests/test_review_round1.py::"
            "test_r5_infrastructure_success_is_distinct_from_connection_readiness",
        ),
    ),
    Mutation(
        "r5-exact-ssm-identity",
        (("provisioning/aws.py", 'if item.get("InstanceId") == instance_id', "if True"),),
        (
            "tests/test_review_round1.py::"
            "test_r5_connection_readiness_reads_ec2_checks_and_exact_ssm_identity",
        ),
    ),
    Mutation(
        "s2-1-no-per-key-cache",
        (("auth.py", "cache_keys=False,", "cache_keys=True,"),),
        ("tests/test_review_round2.py::test_s2_1_removed_signing_key_stops_working",),
    ),
    Mutation(
        "s2-2-session-policy",
        (("provisioning/aws.py", '            "Policy": policy,\n', ""),),
        ("tests/test_review_round2.py::test_s2_2_assume_role_passes_scoped_policy_and_tag",),
    ),
    Mutation(
        "s2-2-session-tag",
        (
            (
                "provisioning/aws.py",
                'kwargs["Tags"] = [{"Key": TAG_DEPLOYMENT, "Value": deployment_id}]',
                "pass",
            ),
        ),
        ("tests/test_review_round2.py::test_s2_2_assume_role_passes_scoped_policy_and_tag",),
    ),
    Mutation(
        "s2-2-session-scope",
        (
            (
                "provisioning/aws.py",
                'owned = {f"ec2:ResourceTag/{TAG_DEPLOYMENT}": deployment_id}',
                'owned = {"ec2:ResourceTag/ManagedBy": "unitcompute"}',
            ),
        ),
        ("tests/test_review_round2.py::test_s2_2_session_policy_alone_enforces_scope",),
    ),
    Mutation(
        "s2-2-provisioner-scope",
        (
            (
                "provisioning/terraform.py",
                '"apply", f"uc-apply-{spec.deployment_id[4:20]}", spec.deployment_id',
                '"apply", f"uc-apply-{spec.deployment_id[4:20]}"',
            ),
        ),
        ("tests/test_review_round2.py::test_s2_2_terraform_provisioner_scopes_plan_and_apply",),
    ),
    Mutation(
        "s2-2-size-guard",
        (("provisioning/aws.py", "if len(policy) > MAX_SESSION_POLICY_CHARS:", "if False:"),),
        ("tests/test_review_round2.py::test_s2_2_oversized_session_policy_is_refused",),
    ),
    Mutation(
        "s2-3-replay-before-provider",
        (
            (
                "agent/service.py",
                "        if idempotency_key is not None:\n            # Completed replays",
                "        if False:\n            # Completed replays",
            ),
        ),
        ("tests/test_review_round2.py::test_s2_3_completed_replay_does_not_need_provider",),
    ),
    Mutation(
        "r2-4-reservation-lease",
        (("agent/service.py", "if expires > utcnow():", "if True:"),),
        ("tests/test_review_round2.py::test_r2_4_stranded_reservation_expires_after_its_lease",),
    ),
    Mutation(
        "r2-4-mark-failed-retry",
        (
            (
                "agent/service.py",
                "for delay in (*MARK_FAILED_RETRY_DELAYS, None):",
                "for delay in (None,):",
            ),
        ),
        ("tests/test_review_round2.py::test_r2_4_failure_marking_retries_through_contention",),
    ),
    Mutation(
        "r2-1-reconcile-known-ids",
        (
            (
                "worker.py",
                "merged = {r.resource_id: r for r in [*tagged, *live]}",
                "merged = {r.resource_id: r for r in tagged}",
            ),
        ),
        ("tests/test_review_round2.py::test_r2_1_known_live_vm_blocks_second_vm",),
    ),
    Mutation(
        "r2-1-append-only",
        (
            (
                "db/migrations/0003_resource_identity_ledger.sql",
                "CREATE TRIGGER deployment_resources_no_delete BEFORE DELETE ON "
                "deployment_resources BEGIN SELECT RAISE(ABORT, "
                "'deployment_resources is append-only'); END;\n",
                "",
            ),
        ),
        ("tests/test_review_round2.py::test_r2_1_identity_rows_are_append_only",),
    ),
    Mutation(
        "r2-2-persist-outputs",
        (("worker.py", 'identity(instance_output, "apply_output"),', "None,"),),
        ("tests/test_review_round2.py::test_r2_2_apply_outputs_persist_when_inventory_fails",),
    ),
    Mutation(
        "r2-2-import-on-recovery",
        (
            (
                "worker.py",
                '                self.identities.import_evidence(conn, job["deployment_id"])\n',
                "",
            ),
        ),
        ("tests/test_review_round2.py::test_r2_2_evidence_file_survives_database_contention",),
    ),
    Mutation(
        "r2-3-root-disk-completeness",
        (("worker.py", "            if missing_disks:", "            if False:"),),
        (
            "tests/test_review_round3.py::"
            "test_r3_3_deletion_verification_independently_requires_root_identity",
        ),
    ),
    Mutation(
        "r2-5-refresh-all-states",
        (
            (
                "worker.py",
                "\"SELECT id, instance_id FROM deployments WHERE status <> 'deleted' \"",
                "\"SELECT id, instance_id FROM deployments WHERE status = 'active' \"",
            ),
        ),
        ("tests/test_review_round2.py::test_r2_5_readiness_keeps_refreshing_during_previews",),
    ),
    Mutation(
        "r2-5-stale-not-ready",
        (
            (
                "services/deployments.py",
                'connection_ready = bool(row["connection_ready"]) and not stale',
                'connection_ready = bool(row["connection_ready"])',
            ),
        ),
        ("tests/test_review_round2.py::test_r2_5_stale_observation_is_not_presented_as_ready",),
    ),
    Mutation(
        "r3-1-policy-volume-tags",
        (("provisioning/policy.py", 'after.get("volume_tags") == root_tags,', "True,"),),
        ("tests/test_review_round3.py::test_r3_1_policy_requires_launch_time_volume_tags",),
    ),
    Mutation(
        "r3-1-policy-root-block-tags",
        (
            (
                "provisioning/policy.py",
                '_first(after.get("root_block_device")).get("tags") in (None, {}),',
                "True,",
            ),
        ),
        ("tests/test_review_round3.py::test_r3_1_policy_requires_launch_time_volume_tags",),
    ),
    Mutation(
        "r3-1-template-tag-on-create",
        (
            (
                "provisioning/templates/ec2_vm_v1/main.tf",
                '  volume_tags = merge(local.tags, { Name = "unitcompute-${var.name}-root" })\n',
                "",
            ),
        ),
        (
            "tests/test_review_round3.py::test_r3_1_template_uses_volume_tags_not_root_block_tags",
            "tests/test_review_round3.py::test_r3_1_pinned_provider_tags_root_volume_in_run_instances",
        ),
    ),
    Mutation(
        "r3-2-root-sources-only",
        (
            (
                "identities.py",
                'and r["parent_id"] and r["source"] in ROOT_SOURCES:',
                'and r["parent_id"]:',
            ),
        ),
        ("tests/test_review_round3.py::test_r3_2_attached_data_disk_is_not_root_evidence",),
    ),
    Mutation(
        "r3-2-root-device-name",
        (("provisioning/aws.py", 'bool(root_name) and m.get("DeviceName") == root_name', "True"),),
        ("tests/test_review_round3.py::test_r3_2_live_root_device_is_positively_identified",),
    ),
    Mutation(
        "r3-2-recorded-volume-exists",
        (("admin.py", "    if not exists:", "    if False:"),),
        (
            "tests/test_review_round2.py::test_r2_3_unknown_root_disk_blocks_until_recorded_and_verified_gone",
        ),
    ),
    Mutation(
        "r3-2-recorded-root-matches",
        (("admin.py", "if roots and args.volume_id not in roots:", "if False:"),),
        ("tests/test_review_round3.py::test_r3_2_recorded_root_must_exist_and_match_the_instance",),
    ),
    Mutation(
        "r3-3-plan-needs-root-identity",
        (
            (
                "worker.py",
                "        if missing:\n            # A known instance",
                "        if False:\n            # A known instance",
            ),
        ),
        (
            "tests/test_review_round3.py::test_r3_3_unresolved_root_blocks_repair_and_deletion_previews",
        ),
    ),
    Mutation(
        "r3-5-torn-tail",
        (("identities.py", 'if size and os.pread(fd, 1, size - 1) != b"\\n":', "if False:"),),
        ("tests/test_review_round3.py::test_r3_5_torn_tail_does_not_swallow_next_record",),
    ),
    Mutation(
        "r3-5-short-write",
        (("identities.py", "view = view[written:]", "view = view[len(view):]"),),
        ("tests/test_review_round3.py::test_r3_5_short_writes_are_completed",),
    ),
    Mutation(
        "r3-6-completion-fence",
        (("agent/service.py", "if owned != 1:", "if False:"),),
        ("tests/test_review_round3.py::test_r3_6_expired_attempt_cannot_publish_after_retry",),
    ),
    Mutation(
        "r3-7-redact-input",
        (
            (
                "agent/service.py",
                "sanitized = redact(request.message)",
                "sanitized = request.message",
            ),
        ),
        ("tests/test_review_round3.py::test_r3_7_credentials_removed_before_provider_and_history",),
    ),
    Mutation(
        "r3-7-redact-history",
        (
            (
                "agent/service.py",
                'HumanMessage(content=redact(r["content"]))',
                'HumanMessage(content=r["content"])',
            ),
        ),
        ("tests/test_review_round3.py::test_r3_7_legacy_history_is_redacted_before_the_provider",),
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
    # pytest exits 1 when tests ran and failed. Any other non-zero code (collection error,
    # unknown test ID, no tests collected) proves nothing about the guard.
    if result.returncode == 1:
        return "KILLED"
    return "SURVIVED" if result.returncode == 0 else f"BROKEN({result.returncode})"


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
