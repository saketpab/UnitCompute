# Verification ledger

Evidence for each review round: what was checked, on which commit, and the result.
"Passed" means the check was run and succeeded; "blocked" and "not run" are stated
explicitly. Offline evidence (simulator, mocked provider, moto, fakes) does not prove
real AWS or real-model behaviour.

Implementation: Claude Opus 5.5 (`claude-opus-5-5`), medium effort. Independent reviews:
GPT-6.1-Sol, medium effort, in fresh contexts run by the orchestrator.

## Gates

| Gate | Status |
|---|---|
| Live AWS sandbox lifecycle (plan → approve → launch → EC2/SSM ready → destroy → verify) | **Blocked**: no sandbox credentials or spending authorization |
| Paid runtime LLM test | **Not run**: no authorization |
| Two clean independent Sol Medium review rounds on the final commit | Round 1 on `715e5e3`: **not clean**. Round 2 on `910e9c0`: **not clean**. Round 3 on `018c180`: **not clean**. Round 4: pending |
| Safe CI on the exact pushed commit | `715e5e3`: passed ([run 40959338191](https://github.com/saketpab/UnitCompute/actions/runs/40959338191)). `910e9c0`: passed ([run 40988581402](https://github.com/saketpab/UnitCompute/actions/runs/40988581402)). `018c180`: passed ([run 40992170490](https://github.com/saketpab/UnitCompute/actions/runs/40992170490)). Round-3 fix commit: see below |
| Draft PR | Not opened (gates outstanding) |

## Candidate 1: `715e5e380b543c38971a802e83a780fec691f173`

| Check | Result |
|---|---|
| `uv lock --check`, ruff format and lint, `mypy --strict` | passed |
| `pytest` with offline Terraform tests required | 210 passed, locally and in CI |
| Terraform `fmt`/`validate`/`test` (mocked provider) and real offline plans checked against the policy | passed |
| `scripts/check_guards.py` | 27/27 mutants killed |
| pip-audit (hash-pinned), gitleaks (full history in CI) | passed, nothing found |
| Process-level offline client walkthrough (real API and worker, simulated provisioner) | passed |
| Sol Medium security review | **not clean**: 5 required findings (S1–S5) |
| Sol Medium reliability review | **not clean**: 6 required findings (R1–R6) |

## Round 1 findings → fixes → tests

Reviewer reproductions: security `test_review_adversarial.py` (8 tests); reliability
`test_independent_review.py` (9 tests). Both files were kept outside the repository and run
unchanged against both trees:

- On `715e5e3`, all 17 pass. They assert the defective behaviour, so this reproduces it.
- On the fix tree, 15 fail, meaning the defect is gone.
- The other 2 are the R1 deletion reproductions. Their stub provisioner overrides only the
  tag inventory, so the new by-ID verification (`find_resources`) falls back to the
  simulator's local state and never reaches moto. With one adaptation that routes
  `find_resources` to the same moto EC2, they fail on the fix tree (`recovery_required`)
  and still pass on `715e5e3` (`deleted`). In production, `TerraformProvisioner.find_resources`
  queries AWS by ID. The regression tests below cover this with moto.

S2 and R3 were the same assistant-reservation defect and were fixed together.

| ID | Finding | Fix | Regression tests (`tests/test_review_round1.py`) | Mutants |
|---|---|---|---|---|
| S1 (P1) | Dev identities could drive the Terraform provisioner | `config.py`: `provisioner=terraform` requires `auth_mode=jwt` and `auth_required_group` in any environment, so the ASGI factory path is covered too | `test_s1_*` | `s1-terraform-needs-jwt` |
| S2/R3 (P1/P2) | Assistant limits counted only completed calls, so concurrent, failed, timed-out or cancelled calls exceeded caps | `agent/service.py`: one `BEGIN IMMEDIATE` transaction reserves the daily attempt (`agent_attempts`, migration 0002) and the session turn before the provider is called; failures and cancellations stay counted | `test_r3_*` (concurrency for daily and session caps, timeout, provider error, cancellation) | `r3-daily-reservation`, `r3-session-turn-reservation`, `r3-failed-attempts-counted` |
| R6 (P2) | Chat ignored `Idempotency-Key` | `POST /agent/messages` accepts the key: owner-scoped replay, `409 idempotency_key_reused`, `409 idempotency_in_progress`; a failed attempt releases the key but stays counted | `test_r6_*` | `r6-chat-idempotency` |
| S3 (P2) | Approval was not bound to account, network, profile, state backend or roles | `services/deployments.py`: `execution_binding` hash stored on each plan (migration 0002) and checked by `binding_problem` at approval and in the worker precheck, with the state key and Terraform account also checked | `test_s3_*` (simulator path, plus the real Terraform provisioner with a recording runner for all 7 settings) | `s3-approval-binding`, `s3-worker-binding` |
| S4 (P2) | Policy ignored provisioners and security-group attachment | `provisioning/policy.py`: rejects provisioners and unreviewed meta-arguments; configured arguments must match the reviewed set exactly; the instance must reference only `aws_security_group.vm` (and match its ID for existing resources); attributes of created resources are allow-listed (rejects `key_name`, `tenancy`, IOPS/throughput, ENIs and similar); existing (no-op) resources are re-checked | `test_s4_*`, including a real pinned offline plan with `local-exec` and a foreign security group | `s4-provisioners`, `s4-group-attachment`, `s4-root-attributes` |
| S5 (P2) | Plan role could overwrite or delete any state | `docs/iam/*.json`: state read is separate from `.tflock` Get/Put/Delete; the plan role is explicitly denied Put/Delete on state; the apply role is denied state deletion | `test_s5_*` (IAM statement evaluator) | — (data file) |
| R1 (P1) | Deletion trusted tag inventory only | `worker.py`: records the instance, security group and root volume IDs and the plan's prior-state IDs; deletion requires every one to be confirmed gone by direct lookup (`find_resources`) plus an empty tag inventory; if this cannot be verified, the deployment stays `recovery_required` and keeps its quota | `test_r1_*` (moto: untagged VM with lost state, retained untagged root volume, lookup failure, ID recording, by-ID semantics) | `r1-delete-by-id` |
| R2 (P1) | DB contention could strand an applied job as `running` | `worker.py`: terminal writes retry lock acquisition with backoff; an idle lock-holding worker recovers any stranded `running` job (`failed` / `recovery_required`) before claiming; nothing is re-applied | `test_r2_*` (transient contention succeeds; persistent contention recovers with exactly one apply) | `r2-stranded-recovery`, `r2-write-retry` |
| R4 (P2) | `/readyz` was ready without a worker | `api/app.py`: with provisioning enabled, readiness requires a heartbeat younger than `worker_stale_seconds` and a passing worker self-check. The self-check covers the Terraform version, both roles assumed, STS `assumed-role/<configured name>` in the configured account, distinct roles, and AMI resolution. Unhealthy workers take no jobs | `test_r4_*` (stub sessions for STS identity) | `r4-ready-needs-worker`, `r4-health-gate`, `r4-role-identity` |
| R5 (P2) | SSM readiness was not established or refreshed | `worker.py`/`aws.py`: after a verified apply, a bounded observation of EC2 status checks plus SSM `PingStatus` for this exact EC2 instance, refreshed by housekeeping; `access.ready` and `resources.connection` are separate from `active` | `test_r5_*` (stubbed EC2/SSM clients, bounded wait, refresh) | `r5-connection-ready`, `r5-exact-ssm-identity` |
| Price provenance | The snapshot claimed a recording date for unverified illustrative prices | `pricing.py`: `basis` = illustrative spec baseline, `verified_against_aws_on = null`, and the disclaimer says it is not a quote | `test_price_snapshot_is_labelled_unverified` | — |

Moto does not implement `ssm:DescribeInstanceInformation`, and the real
`describe_instance_status` and STS role ARNs are only stubbed. R4 and R5 are therefore
proven against stubbed clients only. Real EC2/SSM/IAM acceptance remains part of the
blocked live gate.

## Round 1 fix commit: `910e9c00634edc591878b88f43b2901c1332a591` (parent `715e5e3`)

| Check | Result |
|---|---|
| ruff format and lint, `mypy --strict`, `uv lock --check` | passed |
| `pytest` with offline Terraform tests required | 267 passed |
| `scripts/check_guards.py` | all mutants killed (27 existing + 18 new = 45) |
| Reviewer reproductions against `715e5e3` and the fix tree | see "Round 1 findings" above |
| pip-audit (hash-pinned) | no known vulnerabilities |
| gitleaks (working tree) | no leaks |
| Process-level offline run (real API and worker processes) | `/readyz` 503 without a worker and 200 with a healthy worker; client walkthrough exit 0; repeated chat `Idempotency-Key` returned the same session over HTTP; second worker refused by the lock; Terraform with dev auth refused at configuration |
| CI on the exact pushed commit | passed: [run 40988581402](https://github.com/saketpab/UnitCompute/actions/runs/40988581402), 267 tests |

## Candidate 2: `910e9c00634edc591878b88f43b2901c1332a591`

| Check | Result |
|---|---|
| Sol Medium security review | **not clean**: 3 required findings (S2-1 to S2-3) |
| Sol Medium reliability review | **not clean**: 6 required findings (R2-1 to R2-6) |

S2-3 and R2-6 are the same defect (a completed chat replay needed the provider), so there
are 8 unique findings.

## Round 2 findings → fixes → tests

Reviewer reproductions: security2 `test_security2_independent.py` (3 defect tests and 1
control); reliability2 `test_reliability_review2.py` (6 defect tests). Both files were kept
outside the repository and run unchanged:

- On `910e9c0`, all 10 pass (the defects reproduce and the control holds).
- On the fix tree, all 9 defect tests fail and the control still passes.
- Three of those fail at an earlier or incidental assertion: the migration test now
  applies `[2, 3]`, the inventory-error test stops at approve, and the readiness test stops
  at the first `ready` check. For those three, minimally adapted copies print the actual
  end state on the fix tree:
  - the migrated deployment ends `recovery_required` rather than `deleted`;
  - the ID returned by apply is persisted, and the deletion preview is rejected because the
    live VM is not in Terraform state;
  - readiness is refreshed (`stopped`/`ConnectionLost`) and reports not ready.

| ID | Finding | Fix | Regression tests (`tests/test_review_round2.py`) | Mutants |
|---|---|---|---|---|
| S2-1 (P2) | Removed JWKS keys stayed trusted (PyJWT per-key cache never expires) | `auth.py`: `cache_keys=False`; the JWKS document cache is bounded by `auth_jwks_cache_seconds` (default 300) | `test_s2_1_*` (key removal rejects new tokens; lifespan is configurable) | `s2-1-no-per-key-cache` |
| S2-2 (P2) | Execution sessions could act on other deployments | `aws.py`: every `AssumeRole` passes an inline session policy plus a `UnitComputeDeployment` session tag. State is limited to that deployment's key, mutations to resources tagged with its ID, and creation to that tag. Unscoped plan sessions are read-only without state; unscoped apply sessions are deny-all. Policies over 2,048 characters are refused (also checked by the worker self-check). The IAM examples bind the same scope through `${aws:PrincipalTag/UnitComputeDeployment}`; a trust-policy example is added | `test_s2_2_*`: recorded STS arguments, plus an offline evaluator (`tests/iam_eval.py`) over the role policy alone, the session policy alone, and both combined | `s2-2-session-policy`, `s2-2-session-tag`, `s2-2-session-scope`, `s2-2-provisioner-scope`, `s2-2-size-guard` |
| S2-3 / R2-6 (P2) | Completed chat replays required the provider | `agent/service.py`: completed replays and key conflicts are resolved from the database before the model factory is called | `test_s2_3_*` (service and HTTP; factory unavailable or unconfigured; factory never called) | `s2-3-replay-before-provider` |
| R2-1 (P1) | Repair could launch a second VM despite a recorded live instance | Append-only `deployment_resources` table (migration 0003, triggers forbid UPDATE/DELETE). Planning imports all evidence (including the deployment row), looks up every known ID, and treats live known resources missing from Terraform state as orphans, so the plan is rejected | `test_r2_1_*` (moto: no second VM, history kept, append-only enforced) | `r2-1-reconcile-known-ids`, `r2-1-append-only` |
| R2-2 (P1) | IDs returned by apply were lost when the follow-up lookup failed | Apply outputs are appended to the fsynced per-deployment evidence file, then the table, before any inventory or verification. Stranded-job recovery, planning and verification import the file first | `test_r2_2_*` (inventory failure then no false deletion; DB contention then evidence imported on recovery) | `r2-2-persist-outputs`, `r2-2-import-on-recovery` |
| R2-3 (P1) | Migrated deployments could be marked deleted while an untagged root disk remained | Migration 0003 backfills identities from schema-2 columns and plan prior-state IDs. Disks of live known instances are discovered and recorded. Deletion requires every known instance to have an identified root disk, otherwise `identity_incomplete`: recovery is kept, and the quota stays reserved until an operator records `unitcompute-admin acknowledge-root-disk` (append-only, audited) | `test_r2_3_*` (a real schema 1→2→3 upgrade with moto; acknowledgement path; discovery while live) | `r2-3-root-disk-completeness` |
| R2-4 (P2) | Cancellation plus contention stranded a chat key as in progress forever | Reservations carry a lease (`agent_timeout + 60s`, also derived from `created_at`). An expired reservation is closed as failed (still counted) and the key is reused. Failure marking retries through contention | `test_r2_4_*` | `r2-4-reservation-lease`, `r2-4-mark-failed-retry` |
| R2-5 (P2) | A pending preview froze readiness | Readiness is observed and refreshed in every non-deleted status. An observation older than twice the refresh interval is `stale` and not ready | `test_r2_5_*` | `r2-5-refresh-all-states`, `r2-5-stale-not-ready` |

Behaviour changed deliberately in existing tests:

- `test_r1_untagged_vm_with_lost_state_blocks_deletion` now expects the deletion preview
  itself to be rejected (stricter than the earlier `recovery_required` after apply).
- `test_r1_unverifiable_deletion_keeps_recovery_and_quota` fails lookups only after apply.
  A new test, `test_r1_lookup_failure_blocks_preview`, covers lookups failing during planning.
- The IAM tests use the evaluator because the resources now contain principal-tag variables.

The session-policy and IAM evidence is offline policy evaluation and recorded STS
arguments only. Real IAM, STS session-tag and EC2/SSM acceptance remains part of the
blocked live gate.

## Round 2 fix commit: `018c180bcd7d4978c13a2f5e62749ca22976ee75` (parent `910e9c0`)

| Check | Result |
|---|---|
| ruff format and lint, `mypy --strict`, `uv lock --check` | passed |
| `pytest` with offline Terraform tests required | 299 passed |
| `scripts/check_guards.py` | 61/61 mutants killed (45 earlier + 16 new). Three earlier mutants were retargeted because their code moved: `r3-failed-attempts-counted`, `r6-chat-idempotency` and `r1-delete-by-id` |
| Reviewer reproductions against `910e9c0` and the fix tree | see "Round 2 findings" above |
| pip-audit (hash-pinned), gitleaks (working tree) | passed, nothing found |
| Process-level offline run (real API and worker processes, schema 3) | `/readyz` 503 without a worker and 200 with one; client walkthrough exit 0; repeated chat `Idempotency-Key` returned the same session; identities recorded in the table and the `identities.jsonl` evidence file; second worker refused; worker stopped cleanly on SIGTERM |
| CI on the exact pushed commit | passed: [run 40992170490](https://github.com/saketpab/UnitCompute/actions/runs/40992170490), 299 tests |

## Candidate 3: `018c180bcd7d4978c13a2f5e62749ca22976ee75`

| Check | Result |
|---|---|
| Sol Medium security review | **not clean**: 4 required findings |
| Sol Medium reliability review | **not clean**: 4 required findings |

The volume-tag / IAM mismatch appears in both reviews, so there are 7 unique findings (R3-1
to R3-7 below).

## Round 3 findings → fixes → tests

Reviewer reproductions: security3 `test_security3_independent.py` (4 tests) and
reliability3 `test_reliability_review3.py` (4 tests, including a run of the pinned AWS
provider against a loopback EC2 stub). Both files were kept outside the repository:

- On `018c180`, all 8 pass, so every defect reproduces.
- On the fix tree, 7 of 8 fail for the intended reason. The security file imports the
  removed `_acknowledge_root_disk`, so it was run with that one import made optional; its
  other tests are unchanged.
- `test_actual_provider_volume_tagging_does_not_satisfy_policies` still passes on the fix.
  It asserts that both IAM policies deny an untagged volume launch, which is the
  tag-on-create least privilege we deliberately keep. Its premise, that the plan leaves
  volumes untagged, no longer holds: the pinned-provider reproduction now captures an
  `{instance, volume}` TagSpecification, and `test_r3_1_pinned_provider_tags_root_volume_in_run_instances`
  shows those request tags satisfy both policies.

| ID | Finding | Fix | Regression tests (`tests/test_review_round3.py`) | Mutants |
|---|---|---|---|---|
| R3-1 (P1, both reviews) | `root_block_device.tags` are applied by a post-launch CreateTags, so the tag-on-create IAM conditions deny the launch | The template uses `volume_tags` (provider 6.71.0 sends them as RunInstances `TagSpecifications`, per the pinned provider docs, line 314). The policy now requires `volume_tags` equal to the deployment's root tags and rejects `root_block_device.tags`, in both the plan values and the configuration. The IAM policies are **unchanged**: untagged volume launches stay denied. The simulator and the real-Terraform fixture were regenerated, and `terraform test` asserts the new shape | `test_r3_1_*`: the pinned provider against a loopback EC2 stub captures `{instance, volume}` TagSpecifications with the deployment tags and no CreateTags; role and session policies allow that request and deny untagged or foreign-tagged launches; policy and template checks | `r3-1-policy-volume-tags`, `r3-1-policy-root-block-tags`, `r3-1-template-tag-on-create` |
| R3-2 (P1 security, P1 reliability) | An operator free-text acknowledgement became verified deletion, and any attached disk counted as the root | Acknowledgement removed; the schema-3 `identity_acknowledgements` rows are ignored. Root evidence comes only from root-specific sources (root output, Terraform `root_block_device`, the deployment's root ID, `RootDeviceName` mapping, operator-recorded volume). Attached disks are recorded as `attached_device` but are never root evidence. `unitcompute-admin record-root-volume` only accepts a volume AWS reports as existing (and not contradicting a live instance's root); deletion must then verify it is gone | `test_r3_2_*`, plus the rewritten `test_r2_3_unknown_root_disk_blocks_until_recorded_and_verified_gone` | `r3-2-root-sources-only`, `r3-2-root-device-name`, `r3-2-recorded-volume-exists`, `r3-2-recorded-root-matches` |
| R3-3 (P2) | Create/repair ignored an unresolved root identity | Planning (create, repair and deletion) fails with `identity_incomplete` while any known instance lacks root evidence; deletion verification keeps the same rule | `test_r3_3_*` (both routes: no approvable plan, quota held) | `r3-3-plan-needs-root-identity` |
| R3-5 (P2) | A torn evidence-file tail swallowed the next durable record | Before appending, an unterminated last record is closed with a newline; short `os.write` results are retried until complete (no progress raises); then fsync | `test_r3_5_*` (torn tail, one-byte writes, zero-progress) | `r3-5-torn-tail`, `r3-5-short-write` |
| R3-6 (P2) | An expired chat attempt could publish success after its retry completed | Completion is fenced: `UPDATE … WHERE id = ? AND status = 'reserved'` must succeed before any history is written, in the same transaction; otherwise `409 attempt_superseded` and nothing is published | `test_r3_6_*` (reviewer scenario: late attempt `failed` and superseded, retry `succeeded`, 2 messages, replay = retry) | `r3-6-completion-fence` |
| R3-7 (P2) | Recognisable credentials reached the model and stored history | The message is redacted before the idempotency hash, the provider and storage; history is redacted again on load (covering pre-existing rows); redaction now also covers PEM private keys and more `name=value` secret names; the reply adds a notice. Pattern-based, not complete detection | `test_r3_7_*` (4 credential shapes, replay, legacy history, HTTP) | `r3-7-redact-input`, `r3-7-redact-history` |

Changed test expectations (each is stricter):

- `test_r2_3_unknown_root_disk_blocks_deletion_until_acknowledged` is now
  `test_r2_3_unknown_root_disk_blocks_until_recorded_and_verified_gone`. The deletion
  preview is refused up front (previously it was approved, then failed at verification).
  An operator can only add an existing volume, which must then be removed and verified
  gone before `deleted`; there is no acknowledgement.
- The S3 binding test's stub plan now uses `volume_tags`, matching real Terraform output
  for the new template.
- The `moto_env` fixture moved to `conftest.py`.

The mutation runner was also tightened. Previously any non-zero pytest exit counted as
KILLED, so an unknown test ID would have looked like a kill. Now only exit code 1 counts;
other codes are reported as BROKEN. All 73 referenced test IDs collect (only the renamed
R2-3 ID needed updating).

## Round 3 fix commit (parent `018c180`)

| Check | Result |
|---|---|
| ruff format and lint, `mypy --strict`, `uv lock --check` | passed |
| `pytest` with offline Terraform tests required | 320 passed |
| `scripts/check_guards.py` | 74/74 mutants killed (61 earlier + 13 new). In the first full run, `r2-3-root-disk-completeness` survived: its test now stops at the new plan-time block before reaching the deletion-verification check. That check was kept as a second guard, and a direct test, `test_r3_3_deletion_verification_independently_requires_root_identity`, now kills the mutant |
| Reviewer reproductions against `018c180` and the fix tree | see "Round 3 findings" above |
| pip-audit (hash-pinned), gitleaks (working tree) | passed, nothing found |
| Process-level offline runs (real API and worker processes) | Fresh data dir, and a restart on the round-2 schema-3 data dir with existing identities (no migration needed). Both: `/readyz` 503 without a worker and 200 with one; client walkthrough exit 0; a synthetic `aws_secret_access_key=` chat message was not stored and the reply carried the redaction notice; second worker refused; worker stopped on SIGTERM |
| CI on the exact pushed commit | reported in the handoff (the ledger cannot contain its own commit's SHA) |

The live AWS lifecycle, IAM, EC2 and SSM gate remains blocked and is not proven by these
offline results.
