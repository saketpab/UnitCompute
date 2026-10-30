"""Mutation check: remove each critical guard in a scratch copy and confirm a test fails.

    uv run python scripts/check_guards.py [--only NAME ...]

Each mutation edits a copy of ``src/`` and runs the named tests against it. A mutation
that still passes ("SURVIVED") means the guard is not actually tested. A failing run only
counts as KILLED when it fails for the intended reason: if the output shows an error that a
broken mutant would cause (invalid SQL, a syntax or name error, a type error) the mutant is
reported as "BROKEN-MUTANT" unless the mutation lists that error in ``allow``, and a mutation
may require a pattern in the output with ``expect``. Exit status is non-zero if any
mutation survives, is broken or no longer applies.
"""

from __future__ import annotations

import argparse
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


# Errors a mutant produces when the edit itself is invalid rather than the guard missing.
BROKEN_MUTANT_ERRORS = re.compile(
    r"\b(OperationalError(?!: database is locked)|SyntaxError|IndentationError|NameError|UnboundLocalError|"
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
                "                        \"UPDATE agent_attempts SET status = 'failed', idempotency_key = NULL, \"\n                        \"finished_at = ? WHERE id = ? AND status = 'reserved'\",\n                        (to_db_time(utcnow()), attempt_id),\n",
                "                        \"DELETE FROM agent_attempts WHERE id = ? AND status = 'reserved'\",\n                        (attempt_id,),\n",
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
        "r2-2-import-on-recovery",
        (
            (
                "worker.py",
                '                self.import_identities(job["deployment_id"])\n',
                "                pass\n",
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
            "tests/test_review_round3.py::"
            "test_r3_2_root_device_observation_is_distinct_from_launch_root",
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
                "IFNULL(parent_id, ''), source);",
                "IFNULL(parent_id, ''));",
            ),
        ),
        ("tests/test_review_round4.py::test_r4_4_later_sources_are_kept_for_the_same_volume",),
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
        (
            (
                "worker.py",
                'LAUNCH_OUTPUT if launched else "apply_output_seen",',
                "LAUNCH_OUTPUT,",
            ),
        ),
        (
            "tests/test_review_round5.py::test_r5_1_repair_outputs_of_existing_instance_are_not_launch_evidence",
        ),
    ),
    Mutation(
        "r5-row-root-kept-on-repair",
        (
            (
                "worker.py",
                "int(plan_launches_instance(plan)),",
                "1,",
            ),
        ),
        (
            "tests/test_review_round5.py::test_r5_1_repair_outputs_of_existing_instance_are_not_launch_evidence",
        ),
    ),
    Mutation(
        "r5-errored-state-capture",
        (
            (
                "worker.py",
                "            if errored.is_file():",
                "            if False:",
            ),
        ),
        (
            "tests/test_review_round5.py::test_r5_2_errored_state_is_captured_and_blocks_false_deletion",
        ),
    ),
    Mutation(
        "r5-obligations-forward-only",
        (
            (
                "db/migrations/0006_obligation_revalidation.sql",
                "BEFORE UPDATE ON recovery_obligations WHEN NOT (",
                "BEFORE UPDATE ON recovery_obligations WHEN 0 AND NOT (",
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
            (
                "identities.py",
                '    if not isinstance(raw, dict):\n        return None, ""\n',
                "",
            ),
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
                "CREATE TRIGGER deployment_resources_no_delete BEFORE DELETE ON "
                "deployment_resources BEGIN SELECT RAISE(ABORT, "
                "'deployment_resources is append-only'); END;\n",
                "",
            ),
        ),
        ("tests/test_review_round2.py::test_r2_1_identity_rows_are_append_only",),
    ),
    Mutation(
        "r3-1-template-tag-on-create",
        (
            (
                "provisioning/templates/ec2_vm_v2/main.tf",
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
        (
            (
                "worker.py",
                'identity(instance_output, "apply_output_seen"),',
                "None,",
            ),
        ),
        ("tests/test_review_round2.py::test_r2_2_apply_outputs_persist_when_inventory_fails",),
    ),
    Mutation(
        "r4-new-file-dir-fsync",
        (
            (
                "identities.py",
                "        if created:\n",
                "        if False:\n",
            ),
        ),
        ("tests/test_review_round4.py::test_r4_6_new_evidence_file_and_directories_are_fsynced",),
    ),
    Mutation(
        "r5-report-obligations",
        (
            (
                "admin.py",
                "WHERE deployment_id = ? AND discharged_at IS NULL ORDER BY id",
                "WHERE deployment_id = ? AND 0 ORDER BY id",
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
                '            status = "recovery_required"\n        elif edited_vm is not None:',
                '            status = "plan_failed"\n        elif edited_vm is not None:',
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
                '        if open_uncaptured is not None or (\n            unresolved is not None and unresolved["status"] == "recovery_required"\n        ):',
                '        if (\n            unresolved is not None and unresolved["status"] == "recovery_required"\n        ):',
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
        (
            (
                "provisioning/state_evidence.py",
                "if expected[key] != value:",
                "if False:",
            ),
        ),
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
        (
            (
                "provisioning/state_evidence.py",
                "if document.serial < prior.serial:",
                "if False:",
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_1_binding_requires_the_plans_creates_and_rejects_prior_ids",
        ),
    ),
    Mutation(
        "r6-bind-prior-ids",
        (
            (
                "provisioning/state_evidence.py",
                "if resource_id in prior_ids and address != INSTANCE_STATE:",
                "if False:",
            ),
        ),
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
        (
            (
                "worker.py",
                "require_all_creates=complete",
                "require_all_creates=False",
            ),
        ),
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
        (
            (
                "provisioning/terraform.py",
                "if result.returncode < 0:",
                "if False:",
            ),
        ),
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
        (
            (
                "identities.py",
                'if len(ran) != 1 or ran[0]["status"] != "succeeded":',
                "if False:",
            ),
        ),
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
                "UPDATE recovery_obligations SET evidence = 'uncaptured' WHERE",
            ),
        ),
        ("tests/test_review_round6.py::test_r6_2_failed_destroy_needs_no_capture_after_upgrade",),
    ),
    Mutation(
        "r6-trigger-not-needed-only-for-deletes",
        (
            (
                "db/migrations/0006_obligation_revalidation.sql",
                "AND EXISTS (SELECT 1 FROM plans p WHERE p.id = NEW.plan_id",
                "AND NOT EXISTS (SELECT 1 FROM plans p WHERE p.id = NEW.plan_id",
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
        (
            (
                "identities.py",
                "fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)",
                "pass",
            ),
        ),
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
        "r6-storage-root-durable",
        (
            (
                "db/database.py",
                "        ensure_directory(self.path.parent)\n",
                "        self.path.parent.mkdir(parents=True, exist_ok=True)\n",
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_3_initial_storage_ancestors_are_fsynced",
            "tests/test_review_round6.py::test_r6_3_every_directory_creation_goes_through_the_durable_helpers",
        ),
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
                'return _stored_reply(prior["response_json"])',
                'return AgentReply.model_validate_json(prior["response_json"])',
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
        (
            (
                "agent/service.py",
                "            _RedactToolResults(),\n",
                "",
            ),
        ),
        (
            "tests/test_review_round6.py::test_r6_4_tool_errors_that_echo_arguments_are_replaced",
            "tests/test_review_round6.py::test_r6_4_unknown_tool_error_does_not_echo_the_model_supplied_name",
            "tests/test_review_round6.py::test_r6_4_legacy_credential_shaped_deployment_name_does_not_reach_the_model",
        ),
    ),
    Mutation(
        "r6-name-rejects-credentials",
        (
            (
                "schemas.py",
                "if redact(value) != value:",
                "if False:",
            ),
        ),
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
        (
            (
                "worker.py",
                'if from_db_time(plan["expires_at"]) <= self.clock():',
                "if False:",
            ),
        ),
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
                "        with self._db.transaction() as conn:\n            # Sampled only after the write lock is held",
                "        stale_dt = self._clock()\n        with self._db.transaction() as conn:\n            # Sampled only after the write lock is held",
            ),
            (
                "services/deployments.py",
                "            now_dt = self._clock()\n            now = to_db_time(now_dt)\n            replay = self._idempotent_replay(conn, principal, scope, idempotency_key, payload_hash)\n            if replay:\n                return replay\n            deployment = self._owned_deployment(conn, principal, deployment_id)",
                "            now_dt = stale_dt\n            now = to_db_time(now_dt)\n            replay = self._idempotent_replay(conn, principal, scope, idempotency_key, payload_hash)\n            if replay:\n                return replay\n            deployment = self._owned_deployment(conn, principal, deployment_id)",
            ),
        ),
        (
            "tests/test_review_round7.py::test_r7_2_approval_time_is_sampled_after_the_transaction_wait",
            "tests/test_review_round7.py::test_r7_2_approval_with_a_real_sqlite_lock_wait",
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
        expect="UNIQUE constraint failed",
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
        (
            (
                "provisioning/runner.py",
                "head_limit=MAX_STDOUT_BYTES + 1",
                "head_limit=1 << 40",
            ),
        ),
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
        "r9-no-replacement",
        (
            (
                "provisioning/policy.py",
                '    "create": {("create",), ("no-op",), ("update",)},',
                '    "create": {("create",), ("no-op",), ("update",), ("delete", "create")},',
            ),
        ),
        ("tests/test_policy_updates.py::test_update_policy_rejects_mutation",),
    ),
    Mutation(
        "r9-update-instance-keys",
        (
            (
                "provisioning/policy.py",
                "        extra = sorted(changed - INSTANCE_UPDATE_CHANGES)\n",
                "        extra: list[str] = []\n",
            ),
        ),
        ("tests/test_policy_updates.py::test_update_policy_rejects_mutation",),
    ),
    Mutation(
        "r9-update-unknown-keys",
        (
            (
                "provisioning/policy.py",
                "        unexpected = sorted(unknown_keys - INSTANCE_UPDATE_UNKNOWN)\n",
                "        unexpected: list[str] = []\n",
            ),
        ),
        ("tests/test_policy_updates.py::test_update_policy_rejects_mutation",),
    ),
    Mutation(
        "r9-update-instance-shape",
        (
            (
                "provisioning/policy.py",
                "        v.extend(_check_instance(after, spec, targets, ami_id, unknown))\n",
                "        pass\n",
            ),
        ),
        (
            "tests/test_policy_updates.py::test_update_policy_rejects_mutation",
            "tests/test_policy_updates.py::test_the_plan_must_match_the_request_it_was_made_for",
        ),
    ),
    Mutation(
        "r9-disk-grow-only",
        (
            (
                "provisioning/policy.py",
                "isinstance(size, int) and isinstance(old_size, int) and size >= old_size,",
                "True,",
            ),
        ),
        (
            "tests/test_policy_updates.py::test_update_policy_rejects_mutation",
            "tests/test_policy_updates.py::test_real_terraform_plans_a_disk_shrink_as_an_update_and_only_the_policy_stops_it",
        ),
    ),
    Mutation(
        "r9-update-sg-keys",
        (
            (
                "provisioning/policy.py",
                "        extra = sorted(changed - SECURITY_GROUP_UPDATE_CHANGES)\n",
                "        extra: list[str] = []\n",
            ),
        ),
        ("tests/test_policy_updates.py::test_update_policy_rejects_mutation",),
    ),
    Mutation(
        "r9-power-targets-own-instance",
        (
            (
                "provisioning/policy.py",
                'return instance_id is not None and values.get("instance_id") == instance_id',
                "return True",
            ),
        ),
        ("tests/test_policy_updates.py::test_update_policy_rejects_mutation",),
    ),
    Mutation(
        "r9-power-never-forced",
        (
            (
                "provisioning/policy.py",
                'values.get("force") in (None, False)',
                "True",
            ),
        ),
        (
            "tests/test_policy_updates.py::test_a_forced_power_change_is_refused_when_the_resource_is_created_or_kept",
        ),
    ),
    Mutation(
        "r9-power-matches-request",
        (
            (
                "provisioning/policy.py",
                '        values.get("state") == spec.power_state,\n',
                '        values.get("state") in POWER_STATES,\n',
            ),
        ),
        (
            "tests/test_policy_updates.py::test_the_plan_must_match_the_request_it_was_made_for",
            "tests/test_policy_updates.py::test_a_create_plan_may_not_set_a_power_state_other_than_requested",
        ),
    ),
    Mutation(
        "r9-power-variable-checked",
        (
            (
                "provisioning/policy.py",
                '        "power_state": spec.power_state,\n        "vpc_id": targets.vpc_id,',
                '        "vpc_id": targets.vpc_id,',
            ),
        ),
        ("tests/test_policy_updates.py::test_power_state_variable_is_checked",),
    ),
    Mutation(
        "r9-invisible-updates-hidden",
        (
            (
                "provisioning/policy.py",
                'invisible = actions == ("update",) and not _diff(address, before, after)',
                "invisible = False",
            ),
        ),
        ("tests/test_policy_updates.py::test_real_terraform_plans_start_after_stop",),
    ),
    Mutation(
        "r9-empty-edit-rejected",
        (
            (
                "worker.py",
                "        if edit_request(plan) and policy.allowed and not policy.changes:",
                "        if False:",
            ),
        ),
        (
            "tests/test_lifecycle_ops.py::test_an_edit_that_changes_nothing_is_rejected_by_the_worker",
        ),
    ),
    Mutation(
        "r9-disk-shrink-refused",
        (
            (
                "services/deployments.py",
                'if request.disk_gib is not None and request.disk_gib < deployment["disk_gib"]:',
                "if False:",
            ),
        ),
        ("tests/test_lifecycle_ops.py::test_the_disk_can_only_grow_and_a_noop_is_refused",),
    ),
    Mutation(
        "r9-noop-edit-refused",
        (
            (
                "services/deployments.py",
                "            if unchanged:",
                "            if False:",
            ),
        ),
        ("tests/test_lifecycle_ops.py::test_the_disk_can_only_grow_and_a_noop_is_refused",),
    ),
    Mutation(
        "r9-edit-needs-a-vm",
        (
            (
                "services/deployments.py",
                '            if not deployment["instance_id"]:',
                "            if False:",
            ),
        ),
        ("tests/test_lifecycle_ops.py::test_an_edit_needs_an_existing_vm_and_an_owner",),
    ),
    Mutation(
        "r9-edit-state-gate",
        (
            (
                "services/deployments.py",
                'if deployment["status"] not in PLANNABLE["create"] - {"awaiting_deletion_approval"}:',
                "if False:",
            ),
        ),
        (
            "tests/test_lifecycle_ops.py::test_an_edit_cannot_be_requested_while_a_deletion_is_in_progress",
        ),
    ),
    Mutation(
        "r9-edit-request-nonempty",
        (
            (
                "schemas.py",
                "if self.name is None and self.disk_gib is None and self.power_state is None:",
                "if False:",
            ),
        ),
        ("tests/test_lifecycle_ops.py::test_invalid_update_requests_are_rejected_without_a_plan",),
    ),
    Mutation(
        "r9-plan-spec-from-edit",
        (
            (
                "worker.py",
                'name=edit.get("name", deployment["name"]),',
                'name=deployment["name"],',
            ),
        ),
        (
            "tests/test_lifecycle_ops.py::test_edit_name_and_grow_disk",
            "tests/test_lifecycle_ops.py::test_combined_edit",
        ),
    ),
    Mutation(
        "r9-power-persisted-in-spec",
        (
            (
                "worker.py",
                'power_state=edit.get("power_state") or deployment["power_state"] or "running",',
                'power_state=edit.get("power_state") or "running",',
            ),
        ),
        (
            "tests/test_lifecycle_ops.py::test_a_stopped_vm_stays_stopped_through_repair_and_other_edits",
        ),
    ),
    Mutation(
        "r9-edit-verified-against-ec2",
        (
            (
                "worker.py",
                'if plan["request_json"] or spec.power_state != "running":',
                "if False:",
            ),
        ),
        ("tests/test_lifecycle_ops.py::test_an_edit_is_verified_against_ec2_not_just_terraform",),
    ),
    Mutation(
        "r9-edit-power-verified",
        (
            (
                "worker.py",
                "if details.state not in wanted[spec.power_state]:",
                "if False:",
            ),
        ),
        (
            "tests/test_lifecycle_ops.py::TestMotoLifecycle::test_a_stop_that_did_not_happen_in_ec2_is_recovery",
            "tests/test_lifecycle_ops.py::test_an_edit_is_verified_against_ec2_not_just_terraform",
        ),
    ),
    Mutation(
        "r9-edit-disk-verified",
        (
            (
                "worker.py",
                "if details.root_volume_gib != spec.disk_gib:",
                "if False:",
            ),
        ),
        ("tests/test_lifecycle_ops.py::test_the_root_disk_size_is_verified_against_ec2",),
    ),
    Mutation(
        "r9-failed-edit-keeps-vm-active",
        (
            (
                "worker.py",
                "        elif edited_vm is not None:",
                "        elif False:",
            ),
        ),
        (
            "tests/test_lifecycle_ops.py::test_a_rejected_edit_leaves_the_vm_active",
            "tests/test_lifecycle_ops.py::test_edits_are_blocked_by_the_owner_wide_recovery_rule_but_deletion_is_not",
        ),
    ),
    Mutation(
        "r9-updates-are-not-creates",
        (
            (
                "worker.py",
                '    return {str(c.get("address")) for c in changes if c["action"] == "create"}',
                '    return {str(c.get("address")) for c in changes if c["action"] != "delete"}',
            ),
        ),
        (
            "tests/test_lifecycle_ops.py::test_a_failed_edit_needs_recovery_without_blocking_the_owner_forever",
        ),
    ),
    Mutation(
        "r9-cost-follows-power",
        (
            (
                "worker.py",
                'spec.disk_gib, region=spec.region, running=spec.power_state == "running"',
                "spec.disk_gib, region=spec.region, running=True",
            ),
        ),
        ("tests/test_lifecycle_ops.py::test_stop_then_start_is_previewed_approved_and_verified",),
    ),
    Mutation(
        "r9-stopped-cost",
        (
            (
                "pricing.py",
                "hours = Decimal(snapshot.hours_per_month if running else 0)",
                "hours = Decimal(snapshot.hours_per_month)",
            ),
        ),
        ("tests/test_lifecycle_ops.py::test_stop_then_start_is_previewed_approved_and_verified",),
    ),
    Mutation(
        "r9-power-resource-matches-instance",
        (
            (
                "provisioning/state_evidence.py",
                "    if power_entry and (not instance_entry or power_entry[0] != instance_entry[0]):",
                "    if False:",
            ),
        ),
        (
            "tests/test_lifecycle_ops.py::test_a_power_resource_must_belong_to_the_states_own_instance",
        ),
    ),
    Mutation(
        "r9-power-resource-prior-id",
        (
            (
                "provisioning/state_evidence.py",
                "if resource_id in prior_ids and address != INSTANCE_STATE:",
                "if resource_id in prior_ids:",
            ),
        ),
        (
            "tests/test_lifecycle_ops.py::test_state_evidence_accepts_the_power_resource_added_to_an_existing_vm",
        ),
    ),
    Mutation(
        "r9-region-format",
        (
            (
                "config.py",
                "if not _REGION.fullmatch(self.aws_region):",
                "if False:",
            ),
        ),
        ("tests/test_region_and_iam.py::test_malformed_regions_are_rejected",),
    ),
    Mutation(
        "r9-region-reviewed",
        (
            (
                "config.py",
                "elif self.aws_region not in SUPPORTED_REGIONS:",
                "elif False:",
            ),
        ),
        (
            "tests/test_region_and_iam.py::test_a_well_formed_region_without_a_reviewed_snapshot_is_rejected",
        ),
    ),
    Mutation(
        "r9-price-per-region",
        (
            (
                "pricing.py",
                "snapshot = PRICE_SNAPSHOTS[region] if region is not None else PRICE_SNAPSHOT",
                "snapshot = PRICE_SNAPSHOT",
            ),
        ),
        (
            "tests/test_region_and_iam.py::test_a_registered_region_flows_through_configuration_prices_and_plans",
        ),
    ),
    Mutation(
        "r9-session-region",
        (
            (
                "provisioning/aws.py",
                "region, account = settings.aws_region, settings.aws_account_id",
                'region, account = "us-east-1", settings.aws_account_id',
            ),
        ),
        ("tests/test_region_and_iam.py::test_the_session_policy_follows_the_configured_region",),
    ),
    Mutation(
        "r9-agent-region",
        (
            (
                "agent/service.py",
                "            region=region,",
                '            region="us-east-1",',
            ),
        ),
        ("tests/test_region_and_iam.py::test_the_agent_uses_the_configured_region",),
    ),
    Mutation(
        "r9-rename-name-tag-only",
        (
            (
                "provisioning/aws.py",
                '                "ForAllValues:StringEquals": {"aws:TagKeys": ["Name"]},\n',
                "",
            ),
        ),
        (
            "tests/test_region_and_iam.py::test_each_policy_alone_enforces_the_name_only_rule",
            "tests/test_lifecycle_ops.py::test_each_execution_policy_alone_keeps_a_deployment_to_its_own_resources",
        ),
    ),
    Mutation(
        "r9-session-grants-stop",
        (
            (
                "provisioning/aws.py",
                '                "ec2:StopInstances",\n',
                "",
            ),
        ),
        (
            "tests/test_region_and_iam.py::test_lifecycle_actions_work_only_on_the_deployments_own_tagged_resources",
        ),
    ),
    Mutation(
        "r9-session-lifecycle-owned-only",
        (
            (
                "provisioning/aws.py",
                '                "StringEquals": owned,\n                "ForAllValues',
                '                "StringEquals": {},\n                "ForAllValues',
            ),
        ),
        (
            "tests/test_lifecycle_ops.py::test_each_execution_policy_alone_keeps_a_deployment_to_its_own_resources",
        ),
    ),
    Mutation(
        "r9-orphan-deleted-deployment",
        (
            (
                "admin.py",
                '        elif statuses[deployment_id] == "deleted":',
                "        elif False:",
            ),
        ),
        (
            "tests/test_lifecycle_ops.py::test_orphan_report_flags_resources_of_a_deleted_deployment",
        ),
    ),
    Mutation(
        "r9-orphan-unknown-deployment",
        (
            (
                "admin.py",
                "        elif deployment_id not in statuses:",
                "        elif False:",
            ),
        ),
        (
            "tests/test_lifecycle_ops.py::test_orphan_report_lists_resources_without_a_live_deployment",
        ),
    ),
    Mutation(
        "r9-orphan-unrecorded",
        (
            (
                "admin.py",
                "        elif resource.resource_id not in recorded.get(deployment_id, set()):",
                "        elif False:",
            ),
        ),
        (
            "tests/test_lifecycle_ops.py::test_orphan_report_flags_unrecorded_resources_of_a_live_deployment",
        ),
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
        ("tests/test_policy.py::test_replacement_of_owned_resources_rejected",),
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


def run(mutation: Mutation, workspace: Path, verbose: bool = False) -> str:
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
    if result.returncode == 0:
        return "SURVIVED"
    if result.returncode != 1:
        return f"BROKEN({result.returncode})"
    output = result.stdout + result.stderr
    errors = {m.group(1) for m in BROKEN_MUTANT_ERRORS.finditer(output)} - set(mutation.allow)
    if errors:
        if verbose:
            for line in output.splitlines():
                if BROKEN_MUTANT_ERRORS.search(line) and not line.lstrip().startswith("def "):
                    print(f"      | {line.strip()[:200]}")
        return "BROKEN-MUTANT(" + ",".join(sorted(errors)) + ")"
    if mutation.expect and not re.search(mutation.expect, output):
        return "WRONG-REASON"
    return "KILLED"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", nargs="*")
    parser.add_argument(
        "--verbose", action="store_true", help="print the error lines of broken mutants"
    )
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
            outcome = run(mutation, Path(tmp), args.verbose)
            failures += outcome != "KILLED"
            print(f"{outcome:15} {mutation.name}")
    print(f"{len(selected) - failures}/{len(selected)} guards proven by a failing test")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
