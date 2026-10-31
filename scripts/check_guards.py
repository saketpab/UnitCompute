"""Mutation check: remove each critical guard in a scratch copy and confirm a test fails.

    uv run python scripts/check_guards.py [--only NAME ...]

Each mutation edits a copy of ``src/`` and runs the named tests against it. A mutation
that still passes ("SURVIVED") means the guard is not actually tested. A failing run only
counts as KILLED when it fails for the intended reason: if the output shows an error that a
broken mutant would cause (invalid SQL, a syntax or name error, a type error) the mutant is
reported as "BROKEN-MUTANT" unless the mutation lists that error in ``allow``, and a mutation
may require a pattern in the output with ``expect``. A call-phase assertion in a named
guard test is required by default; other exception outcomes need an explicit error type
and expected diagnostic. Setup failures, skipped tests and unrelated runtime errors never
count. Each run retains the raw pytest output and structured failure reports. Exit status is non-zero if any
mutation survives, is broken or no longer applies.
"""

from __future__ import annotations

import argparse
import json
import os
import re
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
    expect: str = ""  # regex that must appear in the failing output (the intended reason)
    allow: tuple[str, ...] = ()  # error names that this mutation legitimately produces
    logged_timeout_failure: str = ""  # expected failure when the test deliberately logs a timeout


# Errors a mutant produces when the edit itself is invalid rather than the guard missing.
BROKEN_MUTANT_ERRORS = re.compile(
    r"\b(OperationalError(?!: database is locked)|ProgrammingError|UndefinedColumn|UndefinedTable|InvalidTextRepresentation|IndeterminateDatatype|DatatypeMismatch|InvalidDatetimeFormat|InFailedSqlTransaction|SyntaxError|IndentationError|NameError|UnboundLocalError|"
    r"ImportError|ModuleNotFoundError|AttributeError|TypeError)\b"
)


SVC = "services/deployments.py"
WORKER = "worker.py"
POLICY = "provisioning/policy.py"
MUTATIONS = [
    Mutation(
        "owner-scoping",
        (
            (
                "services/deployments.py",
                '"SELECT * FROM deployments WHERE id = %s AND owner_id = %s",',
                '"SELECT * FROM deployments WHERE id = %s AND %s::text IS NOT NULL",',
            ),
        ),
        ("tests/test_authorization.py::test_cross_user_access_is_non_enumerating",),
    ),
    Mutation(
        "approve-hash",
        (
            (
                "services/deployments.py",
                'if not hmac.compare_digest(plan["plan_hash"] or "", approval.plan_hash):',
                "if False:",
            ),
        ),
        ("tests/test_approval.py::test_tampered_hash_rejected",),
    ),
    Mutation(
        "approve-expiry",
        (
            (
                "services/deployments.py",
                'if from_db_time(plan["expires_at"]) <= now_dt:',
                "if False:",
            ),
        ),
        ("tests/test_approval.py::test_expired_plan_cannot_be_approved",),
    ),
    Mutation(
        "approve-replay",
        (("services/deployments.py", 'if plan["status"] != "ready":', "if False:"),),
        ("tests/test_approval.py::test_approval_replay_does_not_create_second_job",),
    ),
    Mutation(
        "approve-plan-type",
        (
            (
                "services/deployments.py",
                'if deployment["status"] != APPROVABLE_STATUS[plan["kind"]]:',
                "if False:",
            ),
        ),
        ("tests/test_approval.py::test_destroy_plan_cannot_be_approved_as_create",),
    ),
    Mutation(
        "approve-versions",
        (
            (
                "services/deployments.py",
                "or plan_versions(plan) != expected_versions(",
                "or False and expected_versions(",
            ),
        ),
        ("tests/test_approval.py::test_stale_template_version_rejected",),
    ),
    Mutation(
        "quota-check-and-index",
        (
            ("services/deployments.py", "if live is not None:", "if False:"),
            (
                "db/migrations/0001_initial.sql",
                "CREATE UNIQUE INDEX deployments_one_live_per_owner\n    ON deployments (owner_id) WHERE status <> 'deleted';",
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
        (
            (
                "services/deployments.py",
                'if not hmac.compare_digest(row["payload_hash"], payload_hash):',
                "if False:",
            ),
        ),
        ("tests/test_idempotency_and_races.py::test_same_key_different_payload_conflicts",),
    ),
    Mutation(
        "worker-hash",
        (("worker.py", 'if sha256_file(plan_path) != plan["plan_hash"]:', "if False:"),),
        ("tests/test_approval.py::test_worker_rejects_plan_file_modified_after_approval",),
    ),
    Mutation(
        "worker-approver",
        (("worker.py", '== plan["owner_id"] == plan["approved_by"]', '== plan["owner_id"]'),),
        ("tests/test_approval.py::test_worker_rejects_approval_by_someone_else",),
    ),
    Mutation(
        "worker-delete-verification",
        (("worker.py", "        if remaining:", "        if False:"),),
        (
            "tests/test_worker_recovery.py::test_deletion_only_completes_when_resources_verified_gone",
        ),
    ),
    Mutation(
        "worker-lock-unlock",
        (
            (
                "worker.py",
                "        if self.fd is not None:\n            os.close",
                "        if self.fd is not None:\n            fcntl.flock(self.fd, fcntl.LOCK_UN)\n            os.close",
            ),
        ),
        ("tests/test_worker_recovery.py::test_single_worker_lock",),
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
                '"UPDATE chat_sessions SET turns = turns + 1, updated_at = %s WHERE id = %s",',
                '"UPDATE chat_sessions SET updated_at = %s WHERE id = %s",',
            ),
        ),
        ("tests/test_review_round1.py::test_r3_concurrent_requests_cannot_exceed_session_turns",),
    ),
    Mutation(
        "r3-failed-attempts-counted",
        (
            (
                "agent/service.py",
                "                        \"UPDATE agent_attempts SET status = 'failed', idempotency_key = NULL, \"\n                        \"finished_at = %s WHERE id = %s AND status = 'reserved'\",\n                        (to_db_time(utcnow()), attempt_id),\n",
                "                        \"DELETE FROM agent_attempts WHERE id = %s AND status = 'reserved'\",\n                        (attempt_id,),\n",
            ),
        ),
        ("tests/test_review_round1.py::test_r3_failed_attempts_stay_counted",),
        expect="rate_limited",
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
                "services/deployments.py",
                "                binding = binding_problem(self._settings, plan)\n                if binding:",
                "                binding = binding_problem(self._settings, plan)\n                if False:",
            ),
        ),
        ("tests/test_review_round1.py::test_s3_changed_execution_config_invalidates_approval",),
    ),
    Mutation(
        "s3-worker-binding",
        (
            (
                "worker.py",
                "        binding = binding_problem(self.settings, plan)\n        if binding:",
                "        binding = binding_problem(self.settings, plan)\n        if False:",
            ),
        ),
        ("tests/test_review_round1.py::test_s3_worker_rechecks_execution_config",),
    ),
    Mutation(
        "s4-provisioners",
        (("provisioning/policy.py", 'if resource.get("provisioners"):', "if False:"),),
        ("tests/test_review_round1.py::test_s4_provisioners_rejected",),
    ),
    Mutation(
        "s4-group-attachment",
        (
            (
                "provisioning/policy.py",
                "if group_id is not None and groups == [group_id]:",
                "if True:",
            ),
        ),
        ("tests/test_review_round1.py::test_s4_existing_instance_must_use_its_own_group",),
    ),
    Mutation(
        "s4-root-attributes",
        (
            (
                "provisioning/policy.py",
                'extra_root = sorted(set(_first(after.get("root_block_device"))) - ROOT_CREATE_FIELDS)',
                "extra_root: list[str] = []",
            ),
        ),
        ("tests/test_review_round1.py::test_s4_unreviewed_instance_attributes_rejected",),
    ),
    Mutation(
        "r1-delete-by-id",
        (
            (
                "worker.py",
                "            found = self.provisioner.find_resources(known.all_ids)",
                "            found = []",
            ),
        ),
        ("tests/test_review_round1.py::test_r1_retained_untagged_root_volume_blocks_deletion",),
    ),
    Mutation(
        "r2-stranded-recovery",
        (("worker.py", "        if self._has_stranded_jobs():", "        if False:"),),
        ("tests/test_review_round1.py::test_r2_persistent_contention_recovers_without_replay",),
        logged_timeout_failure="assert 'running' == 'recovery_required'",
    ),
    Mutation(
        "r2-write-retry",
        (
            (
                "worker.py",
                "        delays = [*self.write_retry_delays, None]",
                "        delays = [None]",
            ),
        ),
        ("tests/test_review_round1.py::test_r2_transient_contention_is_retried",),
        logged_timeout_failure="assert 'recovery_required' == 'succeeded'",
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
                "worker.py",
                "if self._self_check_due() and not self.self_check():\n            return False\n        if not self._healthy:\n            return False",
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
                "if account != self._settings.aws_account_id or not caller.startswith(expected_prefix):",
                "if False:",
            ),
        ),
        ("tests/test_review_round1.py::test_r4_role_identity_verification",),
    ),
    Mutation(
        "r5-connection-ready",
        (("worker.py", "int(readiness.ready),", "1,"),),
        (
            "tests/test_review_round1.py::test_r5_infrastructure_success_is_distinct_from_connection_readiness",
        ),
    ),
    Mutation(
        "r5-exact-ssm-identity",
        (("provisioning/aws.py", 'if item.get("InstanceId") == instance_id', "if True"),),
        (
            "tests/test_review_round1.py::test_r5_connection_readiness_reads_ec2_checks_and_exact_ssm_identity",
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
        expect="ServiceUnavailable: provider unavailable",
        allow=("ServiceUnavailable",),
    ),
    Mutation(
        "r2-4-reservation-lease",
        (("agent/service.py", "if expires > utcnow():", "if True:"),),
        ("tests/test_review_round2.py::test_r2_4_stranded_reservation_expires_after_its_lease",),
        expect="Conflict: A request with this Idempotency-Key is still in progress[.]",
        allow=("Conflict",),
        logged_timeout_failure="Conflict: A request with this Idempotency-Key is still in progress[.]",
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
        logged_timeout_failure="assert \\('reserved', 'key-12345'\\) == \\('failed', None\\)",
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
        "r2-2-import-on-recovery",
        (
            (
                "worker.py",
                '                self.import_identities(job["deployment_id"])\n',
                "                pass\n",
            ),
        ),
        ("tests/test_review_round2.py::test_r2_2_evidence_file_survives_database_contention",),
        logged_timeout_failure="AssertionError: assert .* <= set\\(\\)",
    ),
    Mutation(
        "r2-3-root-disk-completeness",
        (("worker.py", "            if missing_disks:", "            if False:"),),
        (
            "tests/test_review_round3.py::test_r3_3_deletion_verification_independently_requires_root_identity",
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
        "r3-2-root-sources-only",
        (
            (
                "identities.py",
                'launch = r["source"] in LAUNCH_ROOT_SOURCES or (',
                "launch = True or (",
            ),
        ),
        ("tests/test_review_round3.py::test_r3_2_attached_data_disk_is_not_root_evidence",),
    ),
    Mutation(
        "r3-2-root-device-name",
        (("provisioning/aws.py", 'bool(root_name) and m.get("DeviceName") == root_name', "True"),),
        (
            "tests/test_review_round3.py::test_r3_2_root_device_observation_is_distinct_from_launch_root",
        ),
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
        "r4-observation-not-launch-root",
        (
            (
                "identities.py",
                "LAUNCH_ROOT_SOURCES = frozenset({LAUNCH_OUTPUT, LAUNCH_STATE})",
                'LAUNCH_ROOT_SOURCES = frozenset({LAUNCH_OUTPUT, LAUNCH_STATE, "root_device"})',
            ),
        ),
        (
            "tests/test_review_round4.py::test_r4_2_replacement_root_does_not_complete_historical_identity",
        ),
    ),
    Mutation(
        "r4-relookup-after-discovery",
        (
            (
                "worker.py",
                "        live = self.provisioner.find_resources(known.all_ids)\n        merged =",
                "        merged =",
            ),
        ),
        (
            "tests/test_review_round4.py::test_r4_2_launch_evidence_plus_replacement_requires_both_gone",
        ),
    ),
    Mutation(
        "r4-source-distinct-index",
        (
            (
                "db/migrations/0004_source_distinct_identity.sql",
                "COALESCE(parent_id, ''), source);",
                "COALESCE(parent_id, '')) ;",
            ),
        ),
        ("tests/test_review_round4.py::test_r4_4_later_sources_are_kept_for_the_same_volume",),
        expect="RuntimeError: identity evidence not present after import: vol-0123456789abcdef0/root_device",
        allow=("RuntimeError",),
    ),
    Mutation(
        "r4-evidence-presence-check",
        (("worker.py", "        if absent:", "        if False:"),),
        ("tests/test_review_round4.py::test_r4_4_recording_fails_loudly_if_evidence_is_absent",),
    ),
    Mutation(
        "r4-new-ancestor-fsync",
        (
            (
                "durable.py",
                "            continue  # created concurrently; its creator syncs the parent\n        fsync_directory(path.parent)\n",
                "            continue  # created concurrently; its creator syncs the parent\n",
            ),
        ),
        ("tests/test_review_round4.py::test_r4_6_new_evidence_file_and_directories_are_fsynced",),
    ),
    Mutation(
        "r5-refreshed-state-not-launch",
        (
            (
                "identities.py",
                "LAUNCH_ROOT_SOURCES = frozenset({LAUNCH_OUTPUT, LAUNCH_STATE})",
                'LAUNCH_ROOT_SOURCES = frozenset({LAUNCH_OUTPUT, LAUNCH_STATE, "terraform_state"})',
            ),
        ),
        (
            "tests/test_review_round5.py::test_r5_1_refreshed_state_with_replacement_does_not_complete_identity",
        ),
    ),
    Mutation(
        "r5-repair-output-not-launch",
        (("worker.py", 'LAUNCH_OUTPUT if launched else "apply_output_seen",', "LAUNCH_OUTPUT,"),),
        (
            "tests/test_review_round5.py::test_r5_1_repair_outputs_of_existing_instance_are_not_launch_evidence",
        ),
    ),
    Mutation(
        "r5-row-root-kept-on-repair",
        (("worker.py", "int(plan_launches_instance(plan)),", "1,"),),
        (
            "tests/test_review_round5.py::test_r5_1_repair_outputs_of_existing_instance_are_not_launch_evidence",
        ),
    ),
    Mutation(
        "r5-errored-state-capture",
        (("worker.py", "            if errored.is_file():", "            if False:"),),
        (
            "tests/test_review_round5.py::test_r5_2_errored_state_is_captured_and_blocks_false_deletion",
        ),
    ),
    Mutation(
        "r5-obligations-forward-only",
        (
            (
                "db/migrations/0006_obligation_revalidation.sql",
                "THEN RAISE EXCEPTION 'recovery obligations only move forward' USING ERRCODE='23514'; END IF;",
                "THEN NULL; END IF;",
            ),
        ),
        ("tests/test_review_round5.py::test_r5_2_obligation_rows_only_move_forward",),
    ),
    Mutation(
        "r5-retain-open-obligations",
        (
            (
                "worker.py",
                '"  AND NOT EXISTS (SELECT 1 FROM recovery_obligations o "',
                '"  AND EXISTS (SELECT 1 FROM recovery_obligations o "',
            ),
        ),
        (
            "tests/test_review_round5.py::test_r5_2_uncaptured_failed_apply_blocks_everything_and_is_never_discharged",
        ),
    ),
    Mutation(
        "r5-corruption-isolation",
        (
            ("identities.py", '    if not isinstance(raw, dict):\n        return None, ""\n', ""),
            (
                "worker.py",
                '                self.import_identities(job["deployment_id"])\n            except Exception:',
                '                self.import_identities(job["deployment_id"])\n            except ZeroDivisionError:',
            ),
        ),
        (
            "tests/test_review_round5.py::test_r5_3_malformed_evidence_does_not_stop_worker_recovery",
        ),
        expect="NoneType' object has no attribute 'get'",
        allow=("AttributeError",),
    ),
    Mutation(
        "r5-corrupt-obligation",
        (
            (
                "worker.py",
                "            known = self.identities.known(conn, deployment_id)\n        if imported.corrupt:",
                "            known = self.identities.known(conn, deployment_id)\n        if False:",
            ),
        ),
        ("tests/test_review_round5.py::test_r5_3_torn_record_marks_only_that_deployment",),
    ),
    Mutation(
        "r5-worker-dirs-durable",
        (
            (
                "worker.py",
                "        ensure_directory(path.parent)",
                "        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)",
            ),
        ),
        ("tests/test_review_round5.py::test_r5_4_plan_workdirs_are_created_durably",),
    ),
    Mutation(
        "r5-evidence-chain-fsync",
        (
            (
                "identities.py",
                "            fsync_chain(path.parent, self._root.parent)",
                "            pass",
            ),
        ),
        ("tests/test_review_round4.py::test_r4_6_new_evidence_file_and_directories_are_fsynced",),
    ),
    Mutation(
        "r2-1-append-only",
        (
            (
                "db/migrations/0003_resource_identity_ledger.sql",
                "CREATE TRIGGER deployment_resources_no_update BEFORE UPDATE OR DELETE ON deployment_resources FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();\n",
                "",
            ),
        ),
        ("tests/test_review_round2.py::test_r2_1_identity_rows_are_append_only",),
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
        "r4-append-lock",
        (("identities.py", "            fcntl.flock(fd, fcntl.LOCK_EX)\n", ""),),
        ("tests/test_review_round4.py::test_r4_5_concurrent_short_appends_keep_every_record",),
    ),
    Mutation(
        "r2-2-persist-outputs",
        (("worker.py", 'identity(instance_output, "apply_output_seen"),', "None,"),),
        ("tests/test_review_round2.py::test_r2_2_apply_outputs_persist_when_inventory_fails",),
    ),
    Mutation(
        "r4-new-file-dir-fsync",
        (("identities.py", "        if created:\n", "        if False:\n"),),
        ("tests/test_review_round4.py::test_r4_6_new_evidence_file_and_directories_are_fsynced",),
    ),
    Mutation(
        "r5-report-obligations",
        (
            (
                "admin.py",
                "WHERE deployment_id = %s AND (discharged_at IS NULL OR NOT ",
                "WHERE deployment_id = %s AND (FALSE AND ",
            ),
        ),
        (
            "tests/test_review_round5.py::test_r5_2_uncaptured_failed_apply_blocks_everything_and_is_never_discharged",
        ),
    ),
    Mutation(
        "recovery-sticky",
        (
            (
                "worker.py",
                '            "recovery_required"\n            if open_uncaptured',
                '            "plan_failed"\n            if open_uncaptured',
            ),
        ),
        ("tests/test_worker_recovery.py::test_failed_repair_preview_keeps_recovery_status",),
    ),
    Mutation(
        "r4-quoted-assignment",
        (
            (
                "logging_setup.py",
                '    r"(\\"(?:\\\\.|[^\\"\\\\\\n])*(?:\\"|(?=\\n)|$)|\'(?:\\\\.|[^\'\\\\\\n])*(?:\'|(?=\\n)|$)"\n    r"|(?:\\\\.|[^\\s\\"\',;\\\\])+\\\\?|\\\\)"',
                '    r"([^\\s\\"\',;]+)"',
            ),
        ),
        ("tests/test_review_round4.py::test_r4_3_redaction_preserves_quotes_and_bounds",),
    ),
    Mutation(
        "r5-escaped-delimiters",
        (
            (
                "logging_setup.py",
                '    r"(\\"(?:\\\\.|[^\\"\\\\\\n])*(?:\\"|(?=\\n)|$)|\'(?:\\\\.|[^\'\\\\\\n])*(?:\'|(?=\\n)|$)"\n    r"|(?:\\\\.|[^\\s\\"\',;\\\\])+\\\\?|\\\\)"',
                '    r"(\\"[^\\"\\n]*(?:\\"|(?=\\n)|$)|\'[^\'\\n]*(?:\'|(?=\\n)|$)|[^\\s\\"\',;]+)"',
            ),
        ),
        ("tests/test_review_round5.py::test_r5_5_escaped_quotes_do_not_leak_at_any_boundary",),
    ),
    Mutation(
        "r5-legacy-single-create",
        (
            (
                "identities.py",
                "legacy_trusted = _legacy_outputs_have_provenance(conn, deployment_id)",
                "legacy_trusted = True",
            ),
        ),
        (
            "tests/test_review_round5.py::test_r5_1_legacy_root_ids_need_single_create_history",
            "tests/test_review_round6.py::test_r6_2_legacy_trust_rule",
        ),
    ),
    Mutation(
        "r5-capture-on-failure",
        (
            (
                "worker.py",
                "evidence = self._capture_apply_evidence(job, immediate=immediate)",
                'evidence = "captured"',
            ),
        ),
        (
            "tests/test_review_round5.py::test_r5_2_uncaptured_failed_apply_blocks_everything_and_is_never_discharged",
        ),
    ),
    Mutation(
        "r5-stored-state-only-when-final",
        (
            (
                "worker.py",
                "elif immediate and self._is_latest_apply(job) and workdir.is_dir():",
                "elif self._is_latest_apply(job) and workdir.is_dir():",
            ),
        ),
        (
            "tests/test_review_round5.py::test_r5_2_crash_mid_apply_without_errored_state_fails_closed",
            "tests/test_review_round5.py::test_r5_2_later_retry_never_trusts_stored_state",
            "tests/test_review_round6.py::test_r6_1_unaccepted_stored_state_after_crash_is_not_read",
        ),
    ),
    Mutation(
        "r5-plan-gate",
        (
            (
                "worker.py",
                '            self._require_no_uncaptured(deployment["id"], owner)\n            frozen_ami',
                "            frozen_ami",
            ),
        ),
        (
            "tests/test_review_round5.py::test_r5_2_uncaptured_failed_apply_blocks_everything_and_is_never_discharged",
        ),
    ),
    Mutation(
        "r6-gate-helper",
        (
            (
                "worker.py",
                "        blocked = bool(self._uncaptured_obligations(deployment_id))",
                "        blocked = False",
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_3_corruption_found_while_planning_stops_that_plan",
            "tests/test_review_round6.py::test_r6_3_obligation_opened_after_planning_stops_the_apply",
        ),
    ),
    Mutation(
        "r6-recheck-after-reconcile",
        (
            (
                "worker.py",
                '            self._require_no_uncaptured(deployment["id"])\n            policy = evaluate_plan(',
                "            policy = evaluate_plan(",
            ),
        ),
        ("tests/test_review_round6.py::test_r6_3_corruption_found_while_planning_stops_that_plan",),
    ),
    Mutation(
        "r6-recheck-before-apply",
        (
            (
                "worker.py",
                '        self._require_no_uncaptured(deployment["id"], owner)\n        return plan_path',
                "        return plan_path",
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_3_obligation_opened_after_planning_stops_the_apply",
        ),
    ),
    Mutation(
        "r6-reconcile-before-apply",
        (
            (
                "worker.py",
                '        try:\n            self.import_identities(deployment["id"])\n        except Exception as exc:',
                "        try:\n            pass\n        except Exception as exc:",
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_3_obligation_opened_after_planning_stops_the_apply",
        ),
    ),
    Mutation(
        "r6-plan-failure-keeps-recovery",
        (
            (
                "worker.py",
                "            if open_uncaptured is not None\n            or (unresolved",
                "            if (unresolved",
            ),
        ),
        ("tests/test_review_round6.py::test_r6_3_corruption_found_while_planning_stops_that_plan",),
    ),
    Mutation(
        "r6-envelope-complete",
        (
            (
                "provisioning/state_evidence.py",
                'resources, raw_outputs = document.get("resources"), document.get("outputs")',
                'resources, raw_outputs = document.get("resources", []), document.get("outputs", {})',
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_1_unproven_state_never_resolves_an_unknown_mutation",
            "tests/test_review_round6.py::test_r6_1_state_envelope_is_validated",
        ),
    ),
    Mutation(
        "r6-version-pinned",
        (
            (
                "provisioning/state_evidence.py",
                'if document.get("terraform_version") != terraform_version:',
                "if False:",
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_1_unproven_state_never_resolves_an_unknown_mutation",
        ),
    ),
    Mutation(
        "r6-outputs-agree",
        (("provisioning/state_evidence.py", "if expected[key] != value:", "if False:"),),
        (
            "tests/test_review_round6.py::test_r6_1_unproven_state_never_resolves_an_unknown_mutation",
            "tests/test_review_round6.py::test_r6_1_state_envelope_is_validated",
        ),
    ),
    Mutation(
        "r6-bind-lineage",
        (
            (
                "provisioning/state_evidence.py",
                "if prior.lineage and document.lineage != prior.lineage:",
                "if False:",
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_1_unproven_state_never_resolves_an_unknown_mutation",
            "tests/test_review_round6.py::test_r6_1_binding_requires_the_plans_creates_and_rejects_prior_ids",
        ),
    ),
    Mutation(
        "r6-bind-serial",
        (("provisioning/state_evidence.py", "if document.serial < prior.serial:", "if False:"),),
        (
            "tests/test_review_round6.py::test_r6_1_binding_requires_the_plans_creates_and_rejects_prior_ids",
        ),
    ),
    Mutation(
        "r6-bind-prior-ids",
        (("provisioning/state_evidence.py", "if resource_id in prior_ids:", "if False:"),),
        (
            "tests/test_review_round6.py::test_r6_1_binding_requires_the_plans_creates_and_rejects_prior_ids",
        ),
    ),
    Mutation(
        "r6-bind-shows-something",
        (
            (
                "provisioning/state_evidence.py",
                "if creates and all(present.get(address) is None for address in creates):",
                "if False:",
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_1_binding_requires_the_plans_creates_and_rejects_prior_ids",
            "tests/test_review_round6.py::test_r6_1_partial_final_state_is_accepted_and_empty_final_state_is_not",
        ),
    ),
    Mutation(
        "r6-stored-needs-all-creates",
        (("worker.py", "require_all_creates=complete", "require_all_creates=False"),),
        (
            "tests/test_review_round6.py::test_r6_1_stored_snapshot_must_show_every_planned_resource",
        ),
    ),
    Mutation(
        "r6-evidence-bound-to-plan-file",
        (
            (
                "worker.py",
                'if not plan_path.is_file() or sha256_file(plan_path) != plan["plan_hash"]:',
                "if not plan_path.is_file():",
            ),
        ),
        ("tests/test_review_round6.py::test_r6_1_tampered_saved_plan_voids_the_binding",),
    ),
    Mutation(
        "r6-unaccepted-ids-observed",
        (
            (
                "worker.py",
                '                    identity(rid, f"{source}_seen", parent)\n                    for rid, parent in observed_identities(document)\n',
                '                    identity(rid, f"{source}_seen", parent)\n                    for rid, parent in []\n',
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_1_ids_in_unaccepted_state_are_recorded_as_observations",
        ),
    ),
    Mutation(
        "r6-signal-classified",
        (("provisioning/terraform.py", "if result.returncode < 0:", "if False:"),),
        (
            "tests/test_review_round6.py::test_r6_1_signal_exit_is_classified_not_reported_as_a_plain_failure",
        ),
    ),
    Mutation(
        "r6-state-command-read-only",
        (
            (
                "provisioning/runner.py",
                'if args[0] == "state" and tuple(args) != ALLOWED_STATE_ARGS:',
                "if False:",
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_1_state_command_is_read_only",
            "tests/test_runner_and_terraform.py::test_disallowed_subcommands",
        ),
    ),
    Mutation(
        "r6-legacy-single-ran",
        (("identities.py", 'if len(ran) != 1 or ran[0]["status"] != "succeeded":', "if False:"),),
        (
            "tests/test_review_round6.py::test_r6_2_legacy_trust_rule",
            "tests/test_review_round6.py::test_r6_2_failed_repair_after_a_successful_launch_is_not_launch_provenance",
        ),
    ),
    Mutation(
        "r6-legacy-counts-failed-runs",
        (
            (
                "identities.py",
                "AND jobs.status IN ('succeeded', 'recovery_required', 'running')",
                "AND jobs.status IN ('succeeded')",
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_2_failed_repair_after_a_successful_launch_is_not_launch_provenance",
            "tests/test_review_round6.py::test_r6_2_legacy_trust_rule",
        ),
    ),
    Mutation(
        "r6-migration-revalidates-resolved",
        (
            (
                "db/migrations/0006_obligation_revalidation.sql",
                "'evidence_revalidation', 'uncaptured'",
                "'evidence_revalidation', 'not_needed'",
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_2_failed_launch_then_noop_success_is_not_launch_provenance",
        ),
    ),
    Mutation(
        "r6-migration-classifies-destroy",
        (
            (
                "db/migrations/0006_obligation_revalidation.sql",
                "UPDATE recovery_obligations SET evidence = 'not_needed' WHERE",
                "UPDATE recovery_obligations SET evidence = 'not_needed' WHERE FALSE AND",
            ),
        ),
        ("tests/test_review_round6.py::test_r6_2_failed_destroy_needs_no_capture_after_upgrade",),
    ),
    Mutation(
        "r6-trigger-not-needed-only-for-deletes",
        (
            (
                "db/migrations/0006_obligation_revalidation.sql",
                "(NEW.evidence = 'not_needed' AND plan_proves_no_create(NEW.plan_id))",
                "(NEW.evidence = 'not_needed')",
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_2_not_needed_is_only_reachable_for_plans_that_create_nothing",
        ),
    ),
    Mutation(
        "r6-runtime-classifies-destroy",
        (
            (
                "worker.py",
                '            evidence = self._capture_apply_evidence(job, immediate=False)\n            if evidence == "uncaptured":\n                continue',
                '            evidence = self._capture_apply_evidence(job, immediate=False)\n            if evidence != "captured":\n                continue',
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_2_failed_destroy_is_classified_at_runtime_when_still_uncaptured",
        ),
    ),
    Mutation(
        "r6-evidence-read-locked",
        (("identities.py", "fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)", "pass"),),
        ("tests/test_review_round6.py::test_r6_3_import_waits_for_an_append_in_progress",),
    ),
    Mutation(
        "r6-busy-is-not-corruption",
        (
            (
                "worker.py",
                '                log.exception(\n                    "evidence import failed during recovery",',
                '                self._open_obligation(job["deployment_id"], None, None, "evidence_file_corrupt", "uncaptured")\n                log.exception(\n                    "evidence import failed during recovery",',
            ),
        ),
        ("tests/test_review_round6.py::test_r6_3_startup_recovery_survives_a_busy_evidence_file",),
    ),
    Mutation(
        "pg-transaction-durable",
        (
            (
                "db/database.py",
                "            with self.connect() as conn, conn.transaction():\n                # Scoped requests",
                "            with self.connect() as conn, conn.transaction(force_rollback=True):\n                # Scoped requests",
            ),
        ),
        ("tests/test_postgresql.py::test_transaction_survives_connection_restart",),
    ),
    Mutation(
        "r6-runner-dirs-durable",
        (
            (
                "provisioning/runner.py",
                "        ensure_directory(home)\n",
                "        home.mkdir(mode=0o700, exist_ok=True)\n",
            ),
        ),
        ("tests/test_review_round6.py::test_r6_3_simulator_and_runner_directories_are_durable",),
    ),
    Mutation(
        "r6-simulator-dir-durable",
        (
            (
                "provisioning/simulated.py",
                "        ensure_directory(self._state_dir)\n",
                "        self._state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)\n",
            ),
        ),
        ("tests/test_review_round6.py::test_r6_3_simulator_and_runner_directories_are_durable",),
    ),
    Mutation(
        "r6-lock-dir-durable",
        (
            (
                "worker.py",
                "        ensure_directory(self.path.parent)\n",
                "        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)\n",
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_3_every_directory_creation_goes_through_the_durable_helpers",
        ),
    ),
    Mutation(
        "r6-escaped-unquoted",
        (
            (
                "logging_setup.py",
                '    r"(\\"(?:\\\\.|[^\\"\\\\\\n])*(?:\\"|(?=\\n)|$)|\'(?:\\\\.|[^\'\\\\\\n])*(?:\'|(?=\\n)|$)"\n    r"|(?:\\\\.|[^\\s\\"\',;\\\\])+\\\\?|\\\\)"',
                '    r"(\\"(?:\\\\.|[^\\"\\\\\\n])*(?:\\"|(?=\\n)|$)|\'(?:\\\\.|[^\'\\\\\\n])*(?:\'|(?=\\n)|$)"\n    r"|[^\\s\\"\',;]+)"',
            ),
        ),
        ("tests/test_review_round6.py::test_r6_4_escaped_delimiters_do_not_leak_at_any_boundary",),
    ),
    Mutation(
        "r6-replay-sanitized",
        (
            (
                "agent/service.py",
                "    return sanitize_reply(reply)\n\n\ndef build_tools",
                "    return reply\n\n\ndef build_tools",
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_4_legacy_cached_replies_are_redacted_and_validated_on_replay",
        ),
    ),
    Mutation(
        "r6-replay-proposal-revalidated",
        (
            (
                "agent/service.py",
                'reply = reply.model_copy(update={"proposal": Proposal.model_validate(proposal)})',
                'reply = reply.model_copy(update={"proposal": Proposal.model_construct(**proposal)})',
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_4_legacy_cached_replies_are_redacted_and_validated_on_replay",
        ),
    ),
    Mutation(
        "r6-reply-text-sanitized",
        (
            (
                "agent/service.py",
                '"reply": redact(reply.reply)[:MAX_REPLY_CHARS],',
                '"reply": reply.reply,',
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_4_legacy_cached_replies_are_redacted_and_validated_on_replay",
        ),
    ),
    Mutation(
        "r6-tool-results-middleware",
        (("agent/service.py", "            _RedactToolResults(),\n", ""),),
        (
            "tests/test_review_round6.py::test_r6_4_tool_errors_that_echo_arguments_are_replaced",
            "tests/test_review_round6.py::test_r6_4_unknown_tool_error_does_not_echo_the_model_supplied_name",
            "tests/test_review_round6.py::test_r6_4_legacy_credential_shaped_deployment_name_does_not_reach_the_model",
        ),
    ),
    Mutation(
        "r6-name-rejects-credentials",
        (("schemas.py", "if redact(value) != value:", "if False:"),),
        (
            "tests/test_review_round6.py::test_r6_4_credential_shaped_name_is_rejected_not_silently_altered",
            "tests/test_review_round6.py::test_r6_4_typed_validation_and_proposal_bounds_are_unchanged",
        ),
    ),
    Mutation(
        "r6-proposal-typed",
        (
            (
                "schemas.py",
                "class Proposal(BaseModel):\n    name: DeploymentName\n    disk_gib: DiskGiB",
                "class Proposal(BaseModel):\n    name: str\n    disk_gib: int",
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_4_typed_validation_and_proposal_bounds_are_unchanged",
        ),
    ),
    Mutation(
        "worker-expiry",
        (("worker.py", 'if from_db_time(plan["expires_at"]) <= self.clock():', "if False:"),),
        (
            "tests/test_approval.py::test_worker_rejects_plan_that_expired_in_queue",
            "tests/test_review_round7.py::test_r7_2_worker_rejects_a_plan_that_expired_during_the_evidence_import",
        ),
    ),
    Mutation(
        "r7-expiry-in-transaction",
        (
            (
                "worker.py",
                "                self._require_unexpired(plan)\n                conn.execute(",
                "                conn.execute(",
            ),
        ),
        (
            "tests/test_review_round7.py::test_r7_2_worker_rejects_a_plan_that_expired_while_waiting_for_the_write_lock",
        ),
    ),
    Mutation(
        "r7-expiry-before-dispatch",
        (
            (
                "worker.py",
                "            self._require_unexpired(plan)  # and once more immediately before dispatch\n",
                "",
            ),
        ),
        ("tests/test_review_round7.py::test_r7_2_worker_rechecks_immediately_before_dispatch",),
    ),
    Mutation(
        "r7-approve-time-after-lock",
        (
            (
                "services/deployments.py",
                "        with self._db.transaction(principal.owner_id) as conn:\n            self._db.ensure_user(conn, principal)\n            # Sampled only after the write lock is held",
                "        stale_dt = self._clock()\n        with self._db.transaction(principal.owner_id) as conn:\n            self._db.ensure_user(conn, principal)\n            # Sampled only after the write lock is held",
            ),
            (
                "services/deployments.py",
                "            now_dt = self._clock()\n            now = to_db_time(now_dt)\n            replay = self._idempotent_replay(conn, principal, scope, idempotency_key, payload_hash)\n            if replay:\n                return replay\n            deployment = self._owned_deployment(conn, principal, deployment_id)",
                "            now_dt = stale_dt\n            now = to_db_time(now_dt)\n            replay = self._idempotent_replay(conn, principal, scope, idempotency_key, payload_hash)\n            if replay:\n                return replay\n            deployment = self._owned_deployment(conn, principal, deployment_id)",
            ),
        ),
        (
            "tests/test_review_round7.py::test_r7_2_approval_time_is_sampled_after_the_transaction_wait",
            "tests/test_review_round7.py::test_r7_2_approval_with_a_real_postgresql_lock_wait",
        ),
    ),
    Mutation(
        "r7-quota-unproven-obligation",
        (
            (
                "services/deployments.py",
                "            if unproven is not None:\n                # An earlier apply's effects",
                "            if False:\n                # An earlier apply's effects",
            ),
        ),
        (
            "tests/test_review_round7.py::test_r7_1_runtime_open_uncaptured_obligation_blocks_reservation",
            "tests/test_review_round7.py::test_r7_1_owner_with_a_newer_deployment_keeps_both_rows_and_the_obligation_visible",
        ),
    ),
    Mutation(
        "r7-migration-surfaces-deleted",
        (
            (
                "db/migrations/0007_deleted_with_open_obligation.sql",
                "UPDATE deployments SET status = 'recovery_required'",
                "UPDATE deployments SET status = 'deleted'",
            ),
        ),
        (
            "tests/test_review_round7.py::test_r7_1_deleted_deployment_with_unproven_obligation_becomes_recovery_required",
        ),
    ),
    Mutation(
        "r7-migration-respects-live-slot",
        (
            (
                "db/migrations/0007_deleted_with_open_obligation.sql",
                "AND live.status <> 'deleted'",
                "AND live.status = 'nonexistent'",
            ),
        ),
        (
            "tests/test_review_round7.py::test_r7_1_owner_with_a_newer_deployment_keeps_both_rows_and_the_obligation_visible",
        ),
        expect="UniqueViolation:.*deployments_one_live_per_owner",
        allow=("UniqueViolation",),
    ),
    Mutation(
        "r7-admin-lists-deleted",
        (
            (
                "admin.py",
                "WHERE d.status = 'recovery_required' OR EXISTS",
                "WHERE d.status = 'recovery_required' AND EXISTS",
            ),
        ),
        (
            "tests/test_review_round7.py::test_r7_1_owner_with_a_newer_deployment_keeps_both_rows_and_the_obligation_visible",
        ),
    ),
    Mutation(
        "r7-runner-stdout-bounded",
        (("provisioning/runner.py", "head_limit=MAX_STDOUT_BYTES + 1", "head_limit=1 << 40"),),
        ("tests/test_review_round7.py::test_r7_3_oversized_stdout_is_bounded_and_still_rejected",),
        expect="peak",
    ),
    Mutation(
        "r7-runner-tail-bounded",
        (
            (
                "provisioning/runner.py",
                "            del self._tail[:-MAX_LOG_BYTES]\n",
                "            pass\n",
            ),
        ),
        ("tests/test_review_round7.py::test_r7_3_noisy_stderr_is_bounded",),
        expect="peak",
    ),
    Mutation(
        "r7-runner-pipes-held-open",
        (
            (
                "provisioning/runner.py",
                "                if reader.is_alive():\n                    raise subprocess.TimeoutExpired(command, timeout)\n",
                "                if False:\n                    raise subprocess.TimeoutExpired(command, timeout)\n",
            ),
        ),
        (
            "tests/test_review_round7.py::test_r7_3_a_lingering_grandchild_holding_the_pipes_is_a_timeout",
        ),
        expect="DID NOT RAISE",
    ),
    Mutation(
        "r8-owner-wide-plan-gate",
        (
            (
                "worker.py",
                'owner = deployment["owner_id"] if kind == "create" else None',
                "owner = None",
            ),
        ),
        (
            "tests/test_review_round8.py::test_r8_1_queued_reservation_cannot_plan_while_an_older_create_is_unproven",
            "tests/test_review_round8.py::test_r8_1_repair_of_a_running_vm_is_blocked_but_its_deletion_is_not",
            "tests/test_review_round8.py::test_r8_1_schema4_upgrade_with_a_preexisting_reservation",
        ),
    ),
    Mutation(
        "r8-owner-wide-apply-gate",
        (
            (
                "worker.py",
                'owner = deployment["owner_id"] if plan["kind"] == "create" else None',
                "owner = None",
            ),
        ),
        (
            "tests/test_review_round8.py::test_r8_1_an_approved_and_queued_apply_is_refused_by_the_worker",
        ),
    ),
    Mutation(
        "r8-owner-wide-helper",
        (
            (
                "worker.py",
                "if not blocked and owner_id is not None:",
                "if False:",
            ),
        ),
        (
            "tests/test_review_round8.py::test_r8_1_queued_reservation_cannot_plan_while_an_older_create_is_unproven",
            "tests/test_review_round8.py::test_r8_1_an_approved_and_queued_apply_is_refused_by_the_worker",
        ),
    ),
    Mutation(
        "r8-cleanup-plan-not-blocked",
        (
            (
                "worker.py",
                'owner = deployment["owner_id"] if kind == "create" else None',
                'owner = deployment["owner_id"]',
            ),
        ),
        (
            "tests/test_review_round8.py::test_r8_1_a_ready_plan_cannot_be_approved_but_cleanup_can",
            "tests/test_review_round8.py::test_r8_1_repair_of_a_running_vm_is_blocked_but_its_deletion_is_not",
            "tests/test_review_round8.py::test_r8_1_schema4_upgrade_with_a_preexisting_reservation",
        ),
    ),
    Mutation(
        "r8-cleanup-apply-not-blocked",
        (
            (
                "worker.py",
                'owner = deployment["owner_id"] if plan["kind"] == "create" else None',
                'owner = deployment["owner_id"]',
            ),
        ),
        (
            "tests/test_review_round8.py::test_r8_1_a_ready_plan_cannot_be_approved_but_cleanup_can",
            "tests/test_review_round8.py::test_r8_1_repair_of_a_running_vm_is_blocked_but_its_deletion_is_not",
        ),
    ),
    Mutation(
        "r8-approval-gate",
        (
            (
                "services/deployments.py",
                'if plan["kind"] == "create":\n                # Cleanup stays approvable',
                "if False:\n                # Cleanup stays approvable",
            ),
        ),
        ("tests/test_review_round8.py::test_r8_1_a_ready_plan_cannot_be_approved_but_cleanup_can",),
    ),
    Mutation(
        "r8-approval-gate-blocks-cleanup",
        (
            (
                "services/deployments.py",
                'if plan["kind"] == "create":\n                # Cleanup stays approvable',
                "if True:\n                # Cleanup stays approvable",
            ),
        ),
        (
            "tests/test_review_round8.py::test_r8_1_a_ready_plan_cannot_be_approved_but_cleanup_can",
            "tests/test_review_round8.py::test_r8_1_repair_of_a_running_vm_is_blocked_but_its_deletion_is_not",
        ),
    ),
    Mutation(
        "r8-dispatch-check-at-boundary",
        (
            (
                "provisioning/terraform.py",
                "            check_dispatch()\n        result = self._runner.run(",
                "            pass\n        result = self._runner.run(",
            ),
        ),
        (
            "tests/test_review_round8.py::test_r8_2_the_provisioner_checks_after_the_credential_exchange",
            "tests/test_review_round8.py::test_r8_2_worker_to_provisioner_to_runner_never_dispatches_an_expired_plan",
        ),
    ),
    Mutation(
        "r8-dispatch-check-before-credentials",
        (
            (
                "provisioning/terraform.py",
                "            check_dispatch()\n        result = self._runner.run(",
                "            pass\n        result = self._runner.run(",
            ),
            (
                "provisioning/terraform.py",
                '        creds = self._aws.credentials(\n            "apply", f"uc-apply-{spec.deployment_id[4:20]}", spec.deployment_id\n        )',
                '        check_dispatch()\n        creds = self._aws.credentials(\n            "apply", f"uc-apply-{spec.deployment_id[4:20]}", spec.deployment_id\n        )',
            ),
        ),
        (
            "tests/test_review_round8.py::test_r8_2_the_provisioner_checks_after_the_credential_exchange",
            "tests/test_review_round8.py::test_r8_2_the_check_comes_after_preparation_and_before_the_spawn",
        ),
    ),
    Mutation(
        "r8-not-started-is-a-plain-failure",
        (
            (
                "worker.py",
                "        except NotStarted as exc:",
                "        except KeyError as exc:",
            ),
        ),
        (
            "tests/test_review_round8.py::test_r8_2_worker_to_provisioner_to_runner_never_dispatches_an_expired_plan",
        ),
    ),
    Mutation(
        "r8-simulator-honours-guard",
        (
            (
                "provisioning/simulated.py",
                "        check_dispatch()\n        intent = json.loads",
                "        intent = json.loads",
            ),
        ),
        ("tests/test_review_round8.py::test_r8_2_the_simulator_honours_the_guard",),
    ),
    Mutation(
        "r8-guard-installed-by-worker",
        (
            (
                "worker.py",
                "with dispatch_guard(lambda: self._refuse_expired_dispatch(plan)):",
                "if True:",
            ),
        ),
        (
            "tests/test_review_round8.py::test_r8_2_worker_to_provisioner_to_runner_never_dispatches_an_expired_plan",
            "tests/test_review_round8.py::test_r8_2_a_real_binary_is_never_spawned_for_an_expired_plan",
        ),
    ),
    Mutation(
        "policy-imdsv2",
        (("provisioning/policy.py", 'metadata.get("http_tokens") == "required"', "True"),),
        ("tests/test_policy.py::test_policy_rejects_mutation[imdsv1]",),
    ),
    Mutation(
        "policy-ingress",
        (("provisioning/policy.py", 'after.get("ingress") == []', "True"),),
        ("tests/test_policy.py::test_policy_rejects_mutation[ssh_ingress]",),
    ),
    Mutation(
        "policy-actions",
        (("provisioning/policy.py", "if actions not in ALLOWED_ACTIONS[kind]:", "if False:"),),
        ("tests/test_policy.py::test_replace_or_update_of_owned_resources_rejected",),
    ),
    Mutation(
        "policy-orphans",
        (("provisioning/policy.py", "    if orphans:", "    if False:"),),
        ("tests/test_policy.py::test_orphaned_resources_require_operator",),
    ),
    Mutation(
        "policy-provider-args",
        (
            (
                "provisioning/policy.py",
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
    Mutation(
        "pg-uncaptured-completion",
        (
            (
                "db/migrations/0011_completion_integrity.sql",
                "AND (evidence <> 'uncaptured' OR (discharged_at IS NULL AND discharge_job IS NULL))",
                "AND TRUE",
            ),
            (
                "db/migrations/0011_completion_integrity.sql",
                "CHECK (evidence <> 'uncaptured' OR (discharged_at IS NULL AND discharged_by_job_id IS NULL));",
                "CHECK (TRUE);",
            ),
        ),
        ("tests/test_postgresql_review11.py::test_direct_completion_contradictions_are_atomic",),
    ),
    Mutation(
        "pg-discharge-order",
        (("db/migrations/0011_completion_integrity.sql", "dst.sequence>src.sequence", "TRUE"),),
        ("tests/test_postgresql_review11.py::test_direct_completion_contradictions_are_atomic",),
    ),
    Mutation(
        "pg-completed-reply",
        (
            (
                "db/migrations/0011_completion_integrity.sql",
                "CHECK (status <> 'succeeded' OR assistant_reply_readable(response_json));",
                "CHECK (TRUE);",
            ),
        ),
        ("tests/test_postgresql_review11.py::test_completed_reply_requires_readable_payload",),
    ),
]


def exception_diagnostics(output: str) -> str:
    diagnostics = []
    for line in output.splitlines():
        try:
            record = json.loads(line)
        except (ValueError, TypeError):
            record = None
        if (
            isinstance(record, dict)
            and {"ts", "level", "logger", "message", "exception"} <= record.keys()
            and isinstance(record["exception"], str)
        ):
            lines = record["exception"].splitlines()
        else:
            lines = [line]
        diagnostics.extend(
            item for item in lines if item.startswith("E ") or re.match(r"^[\w.]+:", item)
        )
    return "\n".join(diagnostics)


def broken_errors(output: str) -> set[str]:
    # Source snippets are not diagnostics. Decode only JsonFormatter's exception field.
    diagnostics = exception_diagnostics(output)
    return {m.group(1) for m in BROKEN_MUTANT_ERRORS.finditer(diagnostics)} | set(
        re.findall(r"psycopg(?:\.errors)?\.([A-Za-z]+):", diagnostics)
    )


def run(
    mutation: Mutation, workspace: Path, verbose: bool = False, evidence_root: Path | None = None
) -> str:
    src = workspace / "src"
    shutil.rmtree(src, ignore_errors=True)
    shutil.copytree(ROOT / "src", src)
    for relative, old, new in mutation.edits:
        path = src / "unitcompute" / relative
        text = path.read_text()
        if text.count(old) != 1:
            return "NOT-APPLICABLE"
        path.write_text(text.replace(old, new))
    evidence = (evidence_root or workspace) / mutation.name
    evidence.mkdir(exist_ok=True)
    reports = evidence / "reports.jsonl"
    reports.unlink(missing_ok=True)
    plugin = workspace / "guard_reports.py"
    plugin.write_text(
        "import json, os\n"
        "def pytest_runtest_logreport(report):\n"
        "    crash = getattr(report.longrepr, 'reprcrash', None)\n"
        "    with open(os.environ['GUARD_REPORTS'], 'a') as f:\n"
        "        f.write(json.dumps({'nodeid': report.nodeid, 'when': report.when, "
        "'outcome': report.outcome, 'message': getattr(crash, 'message', ''), "
        "'path': str(getattr(crash, 'path', ''))}) + '\\n')\n"
    )
    env = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join((str(src), str(workspace))),
        "PYTHONDONTWRITEBYTECODE": "1",
        "GUARD_REPORTS": str(reports),
    }
    result = subprocess.run(  # noqa: S603 - fixed argv
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-x",
            "-p",
            "no:cacheprovider",
            "-p",
            "guard_reports",
            *mutation.tests,
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    output = result.stdout + result.stderr
    (evidence / "pytest.log").write_text(output)
    if result.returncode == 0:
        return "SURVIVED"
    if result.returncode != 1:
        return f"BROKEN({result.returncode})"
    outcomes = (
        [json.loads(line) for line in reports.read_text().splitlines()] if reports.exists() else []
    )
    if any(r["outcome"] == "skipped" for r in outcomes):
        return "SKIPPED-TEST"
    failed = [r for r in outcomes if r["outcome"] == "failed"]
    if not failed or any(r["when"] != "call" for r in failed):
        return "BROKEN-TEST-SETUP"
    diagnostics = exception_diagnostics(output)
    if mutation.logged_timeout_failure:
        if any(not re.search(mutation.logged_timeout_failure, r["message"]) for r in failed):
            return "WRONG-REASON"
        # These tests deliberately exhaust the advisory-lock timeout. A direct timeout
        # still cannot qualify: the structured failure must be the behavioral assertion.
        diagnostics = "\n".join(
            line
            for line in diagnostics.splitlines()
            if not re.fullmatch(
                r"(?:E\s+)?psycopg\.errors\.LockNotAvailable: canceling statement due to lock timeout",
                line,
            )
        )
    errors = broken_errors(diagnostics) - set(mutation.allow)
    if errors:
        if verbose:
            print("      " + ", ".join(sorted(errors)))
        return "BROKEN-MUTANT(" + ",".join(sorted(errors)) + ")"
    for report in failed:
        if not any(
            report["nodeid"] == node or report["nodeid"].startswith(node + "[")
            for node in mutation.tests
        ):
            return "WRONG-TEST"
        message = report["message"]
        assertion = message.startswith(
            ("assert ", "AssertionError", "Failed: DID NOT RAISE")
        ) and Path(report["path"]).resolve().is_relative_to(ROOT / "tests")
        explicit = bool(
            mutation.expect
            and mutation.allow
            and any(name in message for name in mutation.allow)
            and re.search(mutation.expect, message)
        )
        if not assertion and not explicit:
            return "BROKEN-RUNTIME"
    if mutation.expect and not re.search(mutation.expect, output):
        return "WRONG-REASON"
    return "KILLED"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", nargs="*")
    parser.add_argument(
        "--verbose", action="store_true", help="print the error lines of broken mutants"
    )
    parser.add_argument(
        "--output-dir", type=Path, help="retain per-mutant pytest and report evidence"
    )
    args = parser.parse_args()
    names = {m.name for m in MUTATIONS}
    if args.only is not None and (not args.only or set(args.only) - names):
        parser.error("--only requires one or more known mutation names")
    selected = [m for m in MUTATIONS if args.only is None or m.name in args.only]
    failures = 0
    output_dir = args.output_dir or Path(tempfile.mkdtemp(prefix="unitcompute-mutants-"))
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"Mutation evidence: {output_dir.resolve()}")
    with tempfile.TemporaryDirectory(prefix="unitcompute-mutant-source-") as tmp:
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
            # The source copy is disposable; test diagnostics remain in the evidence directory.
            outcome = run(mutation, Path(tmp), args.verbose, output_dir)
            failures += outcome != "KILLED"
            print(f"{outcome:15} {mutation.name}")
    print(f"{len(selected) - failures}/{len(selected)} guards proven by a failing test")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
