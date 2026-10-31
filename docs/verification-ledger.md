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
| Two clean independent Sol Medium review rounds on the final commit | Round 1 on `715e5e3`: **not clean**. Round 2 on `910e9c0`: **not clean**. Round 3 on `018c180`: **not clean**. Round 4 on `8cf2e5d`: **not clean**. Round 5 on `33602aa`: **not clean**. Round 6 on `b5341db`: **not clean**. Round 7 on `5756293`: **not clean**. Round 8 on `256356c`: **not clean**. Round 9: pending |
| Safe CI on the exact pushed commit | `715e5e3`: passed ([run 40959338191](https://github.com/saketpab/UnitCompute/actions/runs/40959338191)). `910e9c0`: passed ([run 40988581402](https://github.com/saketpab/UnitCompute/actions/runs/40988581402)). `018c180`: passed ([run 40992170490](https://github.com/saketpab/UnitCompute/actions/runs/40992170490)). `8cf2e5d`: passed ([run 41016426496](https://github.com/saketpab/UnitCompute/actions/runs/41016426496)). `33602aa`: passed ([run 41022275602](https://github.com/saketpab/UnitCompute/actions/runs/41022275602)). `b5341db`: passed ([run 41052612031](https://github.com/saketpab/UnitCompute/actions/runs/41052612031)). `5756293`: passed ([run 41097901151](https://github.com/saketpab/UnitCompute/actions/runs/41097901151)). `256356c`: passed ([run 41106001355](https://github.com/saketpab/UnitCompute/actions/runs/41106001355)). Round-8 fix commit: see below |
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

## Round 3 fix commit: `8cf2e5d2176264bcfe8105aa5f4ed4b67936b3fd` (parent `018c180`)

| Check | Result |
|---|---|
| ruff format and lint, `mypy --strict`, `uv lock --check` | passed |
| `pytest` with offline Terraform tests required | 320 passed |
| `scripts/check_guards.py` | 74/74 mutants killed (61 earlier + 13 new). In the first full run, `r2-3-root-disk-completeness` survived: its test now stops at the new plan-time block before reaching the deletion-verification check. That check was kept as a second guard, and a direct test, `test_r3_3_deletion_verification_independently_requires_root_identity`, now kills the mutant |
| Reviewer reproductions against `018c180` and the fix tree | see "Round 3 findings" above |
| pip-audit (hash-pinned), gitleaks (working tree) | passed, nothing found |
| Process-level offline runs (real API and worker processes) | Fresh data dir, and a restart on the round-2 schema-3 data dir with existing identities (no migration needed). Both: `/readyz` 503 without a worker and 200 with one; client walkthrough exit 0; a synthetic `aws_secret_access_key=` chat message was not stored and the reply carried the redaction notice; second worker refused; worker stopped on SIGTERM |
| CI on the exact pushed commit | passed: [run 41016426496](https://github.com/saketpab/UnitCompute/actions/runs/41016426496), 320 tests |

The live AWS lifecycle, IAM, EC2 and SSM gate remains blocked and is not proven by these
offline results.

## Candidate 4: `8cf2e5d2176264bcfe8105aa5f4ed4b67936b3fd`

| Check | Result |
|---|---|
| Sol Medium security review | **not clean**: 4 required findings |
| Sol Medium reliability review | **not clean**: 6 required findings |

Both reviews reported the operator non-root/unrelated-volume false deletion, the
quoted-secret leak and the source-uniqueness suppression, so there are 7 unique findings
(R4-1 to R4-7 below).

## Round 4 findings → fixes → tests

Reviewer reproductions: security4 `test_security4_independent.py` (7 cases, one of them a
JSON redaction control) and reliability4 `test_reliability_review4.py` (6 tests). Both files
were kept outside the repository:

- On `8cf2e5d`, all 13 pass: every defect reproduces, and the JSON control holds.
- On the fix tree (with only the import of the removed `_record_root_volume` made optional),
  all 12 defect cases fail and the control still passes.
- Several of those fail incidentally, because the operator command no longer exists or
  `root_volumes` was renamed. So `tests/test_review_round4.py` replays every scenario end to
  end through the API, worker and moto-backed AWS lookups and asserts the safe outcome:
  no `deleted`, and quota held.

Design change (one coherent rule, not special cases): an instance's identity is complete
only with **launch-root evidence**, meaning what UnitCompute recorded from Terraform:

- apply outputs;
- Terraform `root_block_device` state;
- the deployment row's root ID;
- migrated copies of those.

Current root-device mappings (including replacement roots), attached disks and tag inventory
are **observations**. They are recorded and must be verified gone, but they never complete
identity. The operator `record-root-volume` path was **removed**, because no operator input
can verify a historical root association. The recovery route is restoring launch evidence:
Terraform state from the versioned bucket, or the retained `errored.tfstate`.

| ID | Finding | Fix | Regression tests (`tests/test_review_round4.py`) | Mutants |
|---|---|---|---|---|
| R4-1 (P1, both reviews) | An operator-recorded unrelated or non-root volume completed identity, causing false deletion and quota release | `record-root-volume` removed; completeness needs launch-root evidence only | `test_r4_1_unrelated_volume_cannot_complete_identity` (even a deployment-tagged volume), `test_r4_1_known_non_root_disk_cannot_complete_identity`, `test_r3_2_operator_root_claims_no_longer_exist` | `r4-observation-not-launch-root` |
| R4-2 (P1, security) | A replacement at the root device name completed historical identity | Root-device mappings are recorded as `root_device` observations (`KnownIdentities.observed_roots`), separate from `launch_roots`. Planning also looks resources up again after discovery, so a newly observed replacement outside state rejects the same plan (a gap found while writing these tests) | `test_r4_2_replacement_root_does_not_complete_historical_identity`, `test_r4_2_launch_evidence_plus_replacement_requires_both_gone` | `r4-observation-not-launch-root`, `r4-relookup-after-discovery` |
| R4-3 (P2, both reviews) | Quoted credential assignments leaked to the model, history, output and replay | One assignment pattern for listed credential names with unquoted, `'single'`, `"double"` (whole value), `export NAME="…"` and JSON forms, keeping the quotes. Applied at input, history load and reply (so stored replay responses too). Bounded: prose isn't recognised | `test_r4_3_*` (7 forms, model echo, history, stored response, provider-free replay, legacy history, bounds) | `r4-quoted-assignment` |
| R4-4 (P2, both reviews) | The unique index ignored a new source for the same resource/parent, so later valid evidence was dropped silently | Migration 0004 rebuilds the unique index to include `source` (append-only triggers unchanged). Evidence files re-import rows the old index suppressed. `record_identities` raises unless the exact rows are present | `test_r4_4_later_sources_are_kept_for_the_same_volume`, `test_r4_4_upgrade_reimports_evidence_suppressed_by_old_index` (real schema 3→4 upgrade), `test_r4_4_recording_fails_loudly_if_evidence_is_absent` | `r4-source-distinct-index`, `r4-evidence-presence-check` |
| R4-5 (P2) | Concurrent short appends lost acknowledged evidence | An exclusive `flock` on the evidence file covers the torn-tail check, the short-write loop and the fsync, across threads and processes | `test_r4_5_concurrent_short_appends_keep_every_record` (reviewer interleaving), `test_r4_5_appends_from_separate_processes_are_serialized` (4 processes × 200 appends) | `r4-append-lock` |
| R4-6 (P2) | New evidence file and directory entries weren't made durable | The parent of every newly created directory is fsynced, and the file's directory after the file is created (per fsync(2)) | `test_r4_6_new_evidence_file_and_directories_are_fsynced` (traced fsync targets) | `r4-new-file-dir-fsync`, `r4-new-ancestor-fsync` |
| R4-7 (P2) | An unapproved repair preview allowed pruning a failed apply's work directory (which may hold `errored.tfstate`) | Retention is keyed on apply history: an `apply_failed` plan's directory is kept until a later apply for that deployment succeeds, whatever previews come in between | `test_r4_7_failed_apply_workdir_kept_until_a_later_apply_succeeds` (repair preview and deletion preview, then resolved and pruned) | `r4-retain-unresolved-apply` |

Changed test expectations (each is stricter):

- `test_r2_3_unknown_root_disk_blocks_until_recorded_and_verified_gone` is now
  `test_r2_3_unknown_root_disk_blocks_until_launch_evidence_recovered`. Recovery needs
  restored Terraform state, not an operator record. The disk must still be verified gone,
  and the first deletion ends `recovery_required` because the disk exists.
- `test_r2_3_live_instance_disk_is_discovered_and_verified` is now
  `test_r2_3_live_root_observation_is_recorded_but_not_launch_evidence`. A live root
  observation no longer completes identity.
- `test_r3_2_live_root_device_is_positively_identified` is now
  `test_r3_2_root_device_observation_is_distinct_from_launch_root`, for the same reason.
- `test_r3_2_recorded_root_must_exist_and_match_the_instance` is replaced by
  `test_r3_2_operator_root_claims_no_longer_exist`.
- Migration lists now include schema 4.
- Mutants `r3-2-recorded-volume-exists` and `r3-2-recorded-root-matches` were removed with
  the command they guarded. `r3-2-root-sources-only` was retargeted to the
  launch-root-source check.

## Round 4 fix commit: `33602aa45f2e3a62b5d0a4bf2ab596b58c9803ef` (parent `8cf2e5d`)

| Check | Result |
|---|---|
| ruff format and lint, `mypy --strict`, `uv lock --check` | passed |
| `pytest` with offline Terraform tests required | 340 passed |
| `scripts/check_guards.py` | 81/81 mutants killed in one full run (74 earlier, minus 2 removed with the operator command, plus 9 new). All referenced test IDs collect and every mutation applies exactly once |
| Reviewer reproductions against `8cf2e5d` and the fix tree | see "Round 4 findings" above |
| pip-audit (hash-pinned), gitleaks (working tree) | passed, nothing found |
| Process-level offline runs (real API and worker processes) | Fresh data dir (migrations 1–4), and an **upgrade** of the round-3 data dir from schema 3 to 4 (`applied: [4]`). Both: `/readyz` 503 without a worker and 200 with one; client walkthrough exit 0; a quoted `export AWS_SECRET_ACCESS_KEY="…"` chat message was not stored and the reply carried the removal notice; source-distinct evidence rows present; second worker refused; worker stopped on SIGTERM |
| CI on the exact pushed commit | reported in the handoff (the ledger cannot contain its own commit's SHA) |

Residual limits: redaction is pattern-based. Whether real AWS reports root mappings,
retains replaced roots and accepts the IAM policies is part of the blocked live gate.

## Candidate 5: `33602aa45f2e3a62b5d0a4bf2ab596b58c9803ef`

| Check | Result |
|---|---|
| Safe CI on the exact commit | passed ([run 41022275602](https://github.com/saketpab/UnitCompute/actions/runs/41022275602)) |
| Sol Medium security review | **not clean** |
| Sol Medium reliability review | **not clean** |

## Round 5 findings → fixes → tests

Five unique required findings: two P1s reported by both reviews, escaped-quote secret
leakage (P2, security), and from the reliability review a missed ancestor fsync and
malformed evidence blocking worker restart for every job. The correction instruction also
asked to remove obsolete operator guidance (R5-6).

Reviewer reproductions: security `test_security5_independent.py` (4 tests), reliability
`test_reliability5_independent.py` (4 tests) and `reproduce_backend_failure.py`. They were
kept outside the repository and run unchanged in isolated copies of both trees:

- On `33602aa`, all 8 pass: the defects reproduce. The JWT cross-owner test is the
  reviewer's control.
- On the fix tree, the 7 defect tests fail for the intended reason and the control still
  passes.
- `reproduce_backend_failure.py` (real Terraform 1.17.1 with a local HTTP backend that
  returns 500 on state write, no AWS requests) confirmed that a failed apply leaves the
  instance ID in `errored.tfstate` and that `33602aa` ignored it. It is adapted as
  `test_r5_2_real_terraform_backend_failure_leaves_errored_state`.

Design changes:

- **Provenance, not labels.** Refreshed plan state is an observation (`terraform_state`).
  Launch-root evidence is only what the apply that launched the instance recorded: its
  outputs (`launch_output`) or its errored or stored state read without a refresh
  (`launch_state`). Outputs of a repair apply that did not create the instance are
  `apply_output_seen`, and the deployment row's root ID changes only when the apply
  launched the instance. Sources written by earlier versions count as launch evidence only
  while the deployment has had at most one successful create apply.
- **Recovery obligations** (migration 0005). Every failed, timed-out, crashed or
  interrupted apply records an obligation with evidence `captured`, `not_needed` or
  `uncaptured`. Rows cannot be deleted, and triggers allow only forward moves. An
  `uncaptured` obligation fails every plan with `recovery_evidence_missing` and is never
  discharged, so empty state, empty tags, no known IDs and a later empty successful apply
  cannot clear it, and its work directory is never pruned. The migration backfills
  obligations for earlier failed applies.
- **Evidence capture** reads a validated `errored.tfstate`, or stored state via
  `terraform show -json` only when Terraform itself reported the failure of the latest
  apply. Crashes, kills, timeouts and later retries trust `errored.tfstate` only. State is
  never pushed, imported or force-unlocked automatically.

| ID | Finding | Fix | Regression tests (`tests/test_review_round5.py`) | Mutants |
|---|---|---|---|---|
| R5-1 (P1, both reviews) | Refreshed state naming a replacement root completed launch identity, so the original disk was never verified and the deployment was falsely deleted | Refreshed state is an observation; launch provenance per apply; legacy sources need a single create apply | `test_r5_1_refreshed_state_with_replacement_does_not_complete_identity`, `test_r5_1_repair_outputs_of_existing_instance_are_not_launch_evidence`, `test_r5_1_legacy_root_ids_need_single_create_history` | `r5-refreshed-state-not-launch`, `r5-repair-output-not-launch`, `r5-row-root-kept-on-repair`, `r5-legacy-single-create` |
| R5-2 (P1, both reviews) | After a failed apply with empty backend state, `errored.tfstate` was ignored, a later empty apply released quota while the instance ran, and the evidence was pruned | Recovery obligations; `errored.tfstate`/stored-state capture with validation (`provisioning/state_evidence.py`); plan gate; obligation-based retention; deletion guard; open obligations in `recovery-report` | `test_r5_2_*` (13: real Terraform backend failure, moto false-deletion, stored-state capture, crash with and without `errored.tfstate`, retries, failed delete, forward-only triggers, schema 4→5 backfill, reader acceptance and fail-closed cases) | `r5-capture-on-failure`, `r5-errored-state-capture`, `r5-stored-state-only-when-final`, `r5-plan-gate`, `r5-obligations-forward-only`, `r5-retain-open-obligations`, `r5-report-obligations` |
| R5-3 (reliability) | A JSON scalar in `identities.jsonl` crashed startup recovery for every job | Records are shape-validated; corrupt ones are counted and open an `evidence_file_corrupt` obligation for that deployment only; recovery runs per job | `test_r5_3_malformed_evidence_does_not_stop_worker_recovery`, `test_r5_3_torn_record_marks_only_that_deployment` | `r5-corruption-isolation`, `r5-corrupt-obligation` |
| R5-4 (reliability) | Directories created by the worker before the ledger were never fsynced | `durable.py` used by every creator (worker, Terraform runner, simulator, ledger); a new evidence file syncs its whole directory chain | `test_r5_4_worker_created_evidence_ancestors_are_synced`, `test_r5_4_plan_workdirs_are_created_durably` | `r5-worker-dirs-durable`, `r5-evidence-chain-fsync` |
| R5-5 (P2, security) | A JSON-escaped quote ended the redacted value early and exposed the credential suffix | Quoted values allow backslash escapes and unterminated quotes; applied at input, history, output and replay | `test_r5_5_escaped_quotes_do_not_leak_at_any_boundary` | `r5-escaped-delimiters` |
| R5-6 (correction instruction) | Operator guidance pointed to the removed `record-root-volume` command and to restoring state | Messages and `docs/operations.md` describe obligations and the support decision instead | `test_r5_6_operator_guidance_does_not_mention_removed_command` | — |

Changed test expectations (each is stricter):

- `test_r2_3_unknown_root_disk_blocks_until_launch_evidence_recovered` is now
  `test_r2_3_unknown_root_disk_stays_blocked_when_only_refreshed_state_is_restored`.
  Restored, refreshed state is recorded as an observation and identity stays incomplete.
- Round-4 tests seed launch evidence as `launch_output`/`apply_output` instead of
  `terraform_state`.
- `test_partial_apply_requires_recovery_then_reconciles[timeout]` now expects
  `recovery_evidence_missing`. The killed apply left no `errored.tfstate` and stored state
  is not final, so what it created is unknown. The `terraform_apply_failed` case still
  reconciles.
- Migration lists include schema 5. Mutant `r4-retain-unresolved-apply` was replaced by
  `r5-retain-open-obligations`. `r2-2-persist-outputs` and `r4-new-file-dir-fsync` were
  retargeted to the new code.

## Round 5 fix commit: `b5341db9ceb6122eae65c00fc8bc0ec3f70c865a` (parent `33602aa`)

| Check | Result |
|---|---|
| ruff format and lint, `mypy --strict`, `uv lock --check` | passed |
| `pytest` with offline Terraform tests required | 374 passed |
| `scripts/check_guards.py` | 96/96 mutants killed in one full run (81 earlier, minus 1 replaced, plus 16 new). All referenced test IDs collect and every mutation applies exactly once |
| Reviewer reproductions against `33602aa` and the fix tree | see "Round 5 findings" above |
| pip-audit (hash-pinned), gitleaks (working tree) | passed, nothing found |
| Process-level offline runs (real API and worker processes) | Fresh data dir (migrations 1–5), and an **upgrade** of the round-4 data dir from schema 4 to 5 (`applied: [5]`). Both: `/readyz` 503 without a worker and 200 with one; client walkthrough exit 0; a chat message with `aws_secret_access_key="ab\"…"` (escaped quote) was not stored; launch and observation sources recorded separately; no open obligations; `recovery-report` ran; second worker refused; worker stopped on SIGTERM |
| CI on the exact pushed commit | reported in the handoff (the ledger cannot contain its own commit's SHA) |

Residual limits: redaction is pattern-based. Whether real AWS reports root mappings,
retains replaced roots and accepts the IAM policies, and how real Terraform behaves when
killed mid-apply against S3, are part of the blocked live gate. An `uncaptured` obligation
can only be resolved by a support decision outside the application.

## Candidate 6: `b5341db9ceb6122eae65c00fc8bc0ec3f70c865a`

| Check | Result |
|---|---|
| Safe CI on the exact commit | passed ([run 41052612031](https://github.com/saketpab/UnitCompute/actions/runs/41052612031)) |
| Sol Medium security review | **not clean**: six findings |
| Sol Medium reliability review | **not clean**: six findings |

Round 6 was implemented by native Claude Opus 5.5 (medium) until the run was interrupted,
and finished by native Claude Sonnet 5.5 (high) after the user changed the implementation
model to stretch usage. Reviews remain GPT-6.1-Sol, medium.

## Round 6 findings → fixes → tests

Reviewer reproductions (`test_security6_independent.py`, `test_reliability6_independent.py`,
`reproduce_backend_failure6.py`) were kept outside the repository and run unchanged in
isolated copies:

- On `b5341db` all 18 tests pass (12 security including the JWT control, 6 reliability), so the
  defects reproduce. The real-Terraform script prints `ACCEPTED AS EMPTY`.
- On the fix tree 17 fail and the JWT control passes. Failures that were only incidental
  (the reviewers' scripts call the renamed `_capture_apply_evidence(state_final=...)`, replay
  only migration 5, or release a paused writer after the importer returns) are *not* counted
  as fixes: each defect is re-proven by a test in `tests/test_review_round6.py` written for
  the intended invariant, and by a mutant that reverts it.

Design changes (invariants, not counterexamples):

- **A process exit proves nothing about what was persisted.** An apply's outcome is
  established only by a *raw state document bound to that apply*
  (`provisioning/state_evidence.py`): complete envelope (format 4, the pinned Terraform
  version, lineage, serial, explicit `resources` and `outputs`), confined to the template,
  outputs agreeing with resources, the saved plan file unchanged since approval, lineage equal
  to the plan's prior state, serial not older, at least one planned resource shown, and no
  created ID that was already in the prior state. Stored state (read-only `terraform state
  pull`, never `show -json`) is used only right after the apply and must show every planned
  resource; after a crash or on retry only `errored.tfstate` counts. IDs in any state that is
  read but not accepted are still recorded as observations. A signal exit is its own error
  (`terraform_signalled`). `terraform state` accepts `pull` only; no push, import or
  force-unlock exists anywhere.
- **Legacy launch provenance** (`identities.py`): legacy root IDs are launch evidence only when
  the deployment has exactly one create-kind apply that reached Terraform, it succeeded and
  its recorded plan created the VM. Failed launches, failed repairs and later no-op successes
  can no longer justify or erase uncertainty.
- **Migration 0006** revalidates history: every earlier failed apply of a plan that could
  create resources gets a new `uncaptured` obligation (0005 had discharged some merely because
  a later apply succeeded); obligations of deletion-only plans become `not_needed`, and the
  forward-only trigger allows that move only for such plans. The worker applies the same
  classification at runtime.
- **Gates**: the open-obligation check runs when a plan starts, after reconciliation, and in
  the apply precheck after a fresh evidence import. Evidence reads take a bounded shared lock
  so a write in progress is never read as corruption; a lock timeout or I/O error is
  transient and never opens a corruption obligation.
- **Durability**: all directory creation (data directory and ancestors, worker lock, work
  directories, runner home and logs, simulator, Terraform version scratch) goes through
  `durable.py`; an audit test fails on any direct `mkdir`.
- **Credential policy** at one boundary per data flow: escaped delimiters in unquoted values;
  tool results (and tool errors, replaced by fixed messages because LangChain echoes raw
  arguments) redacted in one middleware; replies redacted and the stored proposal
  revalidated on replay; `DeploymentName` rejects credential-shaped names (REST 422, tool
  invalid) and `Proposal` is typed, so unsafe structured values are rejected or withheld,
  never silently rewritten.

| ID | Finding | Regression tests (`tests/test_review_round6.py`) | Mutants |
|---|---|---|---|
| R6-1 (P1 ×3, both reviews) | Empty, incomplete or stale state, a signalled or backend-failed Terraform, and unread raw outputs resolved an unknown mutation, allowing verified deletion | `test_r6_1_*` (8 unproven-state variants through the worker with moto, observed-ID recording, stored-snapshot rules, tampered plan, crash path, envelope/binder unit cases, **real Terraform**: SIGKILL after an external effect, and backend plus fallback write failure, read-only `state`) | `r6-envelope-complete`, `r6-version-pinned`, `r6-outputs-agree`, `r6-bind-lineage`, `r6-bind-serial`, `r6-bind-prior-ids`, `r6-bind-shows-something`, `r6-stored-needs-all-creates`, `r6-evidence-bound-to-plan-file`, `r6-unaccepted-ids-observed`, `r6-signal-classified`, `r6-state-command-read-only`, `r5-capture-on-failure`, `r5-stored-state-only-when-final` |
| R6-2 (P1 ×2) | Legacy success counts and failed repairs supplied false launch-root provenance; migration discharged failed launches | `test_r6_2_*` (failed launch + no-op success and failed repair after launch, both ending in blocked deletion with the original disk alive; trust-rule table) | `r5-legacy-single-create`, `r6-legacy-single-ran`, `r6-legacy-counts-failed-runs`, `r6-migration-revalidates-resolved` |
| R6-2b (P2) | Migration blocked failed destroys that need no capture | `test_r6_2_failed_destroy_*`, `test_r6_2_not_needed_is_only_reachable_for_plans_that_create_nothing` | `r6-migration-classifies-destroy`, `r6-trigger-not-needed-only-for-deletes`, `r6-runtime-classifies-destroy` |
| R6-3 (P2 ×3) | Obligation found during planning did not stop that plan's apply; imports raced locked writers; fresh storage ancestors were not synced | `test_r6_3_*` | `r6-gate-helper`, `r6-recheck-after-reconcile`, `r6-recheck-before-apply`, `r6-reconcile-before-apply`, `r6-plan-failure-keeps-recovery`, `r6-evidence-read-locked`, `r6-busy-is-not-corruption`, `r6-storage-root-durable`, `r6-runner-dirs-durable`, `r6-simulator-dir-durable`, `r6-lock-dir-durable` |
| R6-4 (P2 ×3) | Escaped unquoted delimiters, cached legacy replies and structured proposals/tool results bypassed redaction | `test_r6_4_*` (8 escaped forms through ingress/provider/storage/reply/replay, legacy replay, name rejection, legacy stored name via tools, tool errors) | `r6-escaped-unquoted`, `r6-replay-sanitized`, `r6-replay-proposal-revalidated`, `r6-reply-text-sanitized`, `r6-tool-results-middleware`, `r6-name-rejects-credentials`, `r6-proposal-typed` |

Changed test expectations (each stricter or equivalent):

- `FailingApply` (worker recovery tests) now writes Terraform's final state as
  `errored.tfstate` for the partial-apply scenario; a variant without it (only a stored
  snapshot lacking the planned VM) must fail closed for an error, a signal and a timeout.
- `test_r2_2_apply_outputs_persist_when_inventory_fails` now expects the deletion preview to
  stop with `recovery_evidence_missing` (the apply's outcome is unproven).
- Round-4 legacy fixtures seed a real single successful launch history
  (`seed_launch_history`), as the new provenance rule requires.
- The round-5 raw-state tests use complete envelopes; the `show -json` reader is gone.
- Migration lists include schema 6; `test_disallowed_subcommands` also rejects `state push`,
  `state pull <arg>` and bare `state`.
- Tool error messages are fixed strings (`TOOL_ERROR`, `UNKNOWN_TOOL_ERROR`) that keep the
  words the existing agent tests assert.
- Mutant inventory: all 96 earlier mutants are retained (seven retargeted to the new code);
  37 added; one (`r6-tool-output-redacted`) was dropped when a first full run showed it
  redundant with the single redaction middleware, which is now the only boundary. The first
  full run also found five survivors (an obsolete migration target, a tamper test that was
  rejected for a different reason, an audit test that scanned the checkout instead of the
  imported package, and two redundant validation layers); each was fixed, not excused.

## Round 6 fix commit: `57562930a04b6a718db5c05f9266ddf204e019d2` (parent `b5341db`)

| Check | Result |
|---|---|
| ruff format and lint, `mypy --strict`, `uv lock --check`, `uv sync --locked` | passed |
| `pytest` with offline Terraform tests required | 449 passed |
| `scripts/check_guards.py` | 132/132 mutants killed in one full run. All referenced test IDs collect and every mutation applies exactly once |
| Reviewer reproductions against `b5341db` and the fix tree | see above |
| pip-audit (hash-pinned), gitleaks (working tree) | passed, nothing found |
| Process-level offline runs (real API and worker processes) | Fresh data dir (migrations 1–6) and an **upgrade** of a copy of the round-5 data dir from schema 5 to 6 (`applied: [6]`). Both: `/readyz` 503 without a worker and 200 with one; client walkthrough exit 0; a chat message `export PASSWORD=prefix\;…` was not stored and its tail never reached the reply; a credential-shaped REST name returned 422; no open obligations; second worker refused; worker stopped on SIGTERM |
| CI on the exact pushed commit | reported in the handoff (the ledger cannot contain its own commit's SHA) |

Residual limits: a failed apply whose Terraform both failed to persist state and left no
`errored.tfstate` (or was killed before persisting) stays `uncaptured`. Quota is held and
verified deletion is refused, by design, until a support decision outside the application. A
legacy deployment whose history includes a failed repair also stays `identity_incomplete`
even if its recorded root was in fact the launch root. Redaction is pattern-based. Real AWS
behaviour of root mappings, replaced roots, `terraform state pull` against S3 and Terraform
being killed mid-apply remains part of the blocked live gate. Offline Terraform, simulator
and moto evidence do not prove AWS behaviour.

## Candidate 7: `57562930a04b6a718db5c05f9266ddf204e019d2`

| Check | Result |
|---|---|
| Safe CI on the exact commit | passed ([run 41097901151](https://github.com/saketpab/UnitCompute/actions/runs/41097901151)) |
| Sol Medium security review | **not clean** |
| Sol Medium reliability review | **not clean** |

Four unique findings; both reviewers independently confirmed the frozen HEAD, the CI run
and 449 passing tests. Implementation: native Claude Sonnet 5.5 (high), at the user's request.

## Round 7 findings → fixes → tests

Reviewer reproductions (`test_independent_reliability.py`, `test_independent.py`,
`runner-memory-repro.py`) were run unchanged in isolated copies. On `5756293` all six tests
fail (each asserts the safe outcome) and the memory script reports a 201 MB traced peak. On
the fix tree the five expiry tests pass and the script's peak is 0.4 MB. The migration
reproduction asserts `db.migrate() == [5, 6]` and then expects a second reservation to be
accepted; on the fix tree the migration list is `[5, 6, 7]` and the reservation is refused,
which is the intended behaviour (the deployment is `recovery_required`).

| ID | Finding | Fix | Regression tests (`tests/test_review_round7.py`) | Mutants |
|---|---|---|---|---|
| R7-1 (P1) | Migration 0006 reopened an `uncaptured` obligation on a `deleted` deployment but left it `deleted`; `create_deployment` ignored obligations, so a second VM could be reserved | Migration 0007 turns such a deployment into `recovery_required` (one row per owner, the newest, because the one-live-VM unique index forbids more). An owner who already has a newer live deployment keeps the old row `deleted`: the migration does not fail, the obligation stays open and `recovery-report` lists it. `POST /deployments` refuses with `409 recovery_required` whenever any of the owner's deployments has an open `uncaptured` obligation | `test_r7_1_*` (reviewer's schema-4 history; owner with a newer deployment, including after it is deleted; two deleted rows; unaffected owners; runtime guard independent of the migration) | `r7-migration-surfaces-deleted`, `r7-migration-respects-live-slot`, `r7-quota-unproven-obligation`, `r7-admin-lists-deleted` |
| R7-2 (P2) | Approval sampled the clock before acquiring SQLite; the worker checked expiry before its blocking evidence import and never again | Approval samples after the write lock is held. The worker has one expiry helper called inside the `apply.started` transaction (after the precheck's waits, before anything is recorded) and once more immediately before dispatch; the early duplicate check was removed | `test_r7_2_*` (injected-clock waits at the import, before the write lock and during the commit; **real** 1.5 s `flock` and real 1.5 s SQLite lock with a monotonic clock starting 0.5 s before expiry; the in-window boundary still applies) | `worker-expiry`, `r7-expiry-in-transaction`, `r7-expiry-before-dispatch`, `r7-approve-time-after-lock` |
| R7-3 (P2) | `communicate()` buffered both streams completely: 64 MiB of stderr cost about 201 MB | Two reader threads drain both pipes as they are written into bounded buffers (stdout head up to the 8 MiB limit, a 64 KiB tail per stream for the log). A noisy child is never killed. Timeout, group kill, signal exit codes, and the oversize-stdout rejection are unchanged; a descendant holding the pipes open after the child exits is a timeout | `test_r7_3_*` (traced peak < 4 MiB for 64 MiB stderr; oversized stdout bounded and rejected; intact JSON; both streams full; timeout with a grandchild; lingering grandchild; `-9` exit code) | `r7-runner-stdout-bounded`, `r7-runner-tail-bounded`, `r7-runner-pipes-held-open` |
| R7-4 (P2) | The mutant `r3-failed-attempts-counted` rewrote the statement into invalid SQL; the runner counted the resulting failure as a kill | Corrected to a valid deletion of the attempt row (statement and parameters), which fails the rate-limit assertion. The runner now checks the *reason* (below) | `test_r7_4_*` (the old broken mutant is reported `BROKEN-MUTANT(OperationalError)`; the valid one is `KILLED`; a wrong `expect` is `WRONG-REASON`; every edit in the inventory still compiles) | `r3-failed-attempts-counted` (now with `expect="rate_limited"`) |

**Mutant-runner audit.** `scripts/check_guards.py` now treats a failing run as a kill only if
the output contains no error that an invalid mutant would cause (invalid SQL, syntax, name,
type and attribute errors; `database is locked` is exempt because several guards exist to
handle it), and a mutation may require a pattern (`expect`) and list errors it legitimately
produces (`allow`). Running the whole inventory under the new rule found nine more
mutants whose failure was not the intended one: `worker-approver` and `worker-expiry` (the test
indexed `None` after the guard was removed; both tests now assert cleanly),
`r6-state-command-read-only` (it failed inside `Popen`; the test now uses a recording binary),
`r5-corruption-isolation` (it fails with the original defect, an `AttributeError` on a JSON
`null` record, so it now declares that), and five lock-contention guards (`database is locked` is
their subject). `worker-expiry` also survived once the early duplicate check was removed and was
retargeted to the single helper. A first pass at the new mutants found `r7-expiry-before-dispatch`
survived because the test's clock advanced one transaction too early; the test now advances time
precisely after the in-transaction check. All 132 earlier mutants are retained and 10 are new (142).

Changed test expectations: migration lists include schema 7; `_precheck_apply` no longer takes a
clock argument (one caller in the round-1 tests); `test_worker_rejects_approval_by_someone_else`
and `test_worker_rejects_plan_that_expired_in_queue` assert `(error or {}).get("code")` so a
removed guard fails cleanly.

## Round 7 fix commit: `256356c75f0b56bfe81b36ec15c205694d414143` (parent `5756293`)

| Check | Result |
|---|---|
| ruff format and lint, `mypy --strict`, `uv lock --check`, `uv sync --locked` | passed |
| `pytest` with offline Terraform tests required | 472 passed |
| `scripts/check_guards.py --verbose` | 142/142 mutants killed for the intended reason in one full run. All referenced test IDs collect and every mutation applies exactly once |
| pip-audit (hash-pinned), gitleaks (working tree) | passed, nothing found |
| Process-level offline runs (real API and worker processes) | Fresh data dir (migrations 1–7), and an **upgrade** of a schema-6 data dir seeded with a deleted deployment holding an open `uncaptured` obligation (`applied: [7]`): it became `recovery_required`, its owner's new reservation was refused, `recovery-report` listed it, another owner's lifecycle exited 0. In all runs `/readyz` was 503 without a worker and 200 with one, a second worker was refused and the worker stopped on SIGTERM |
| CI on the exact pushed commit | reported in the handoff (the ledger cannot contain its own commit's SHA) |

Residual limits: unchanged from round 6. *Correction (round 8):* this row originally said the
dispatch check could not cover time before `terraform apply` starts and that the 15-minute
window tolerated a late dispatch. That was wrong: the check sat before the credential
exchange (STS) in `TerraformProvisioner.apply`, so a slow exchange dispatched an expired plan
(R8-2). There is no expiry tolerance. For an owner with a newer live deployment, the old unproven deletion is visible to operators and blocks new
reservations but is not shown as a status of the old row.

## Candidate 8: `256356c75f0b56bfe81b36ec15c205694d414143`

| Check | Result |
|---|---|
| Safe CI on the exact commit | passed ([run 41106001355](https://github.com/saketpab/UnitCompute/actions/runs/41106001355)) |
| Sol Medium security review | **not clean** |
| Sol Medium reliability review | **not clean** |

Two required defects; both reviewers independently confirmed the frozen HEAD, the CI run,
472 tests and 142 valid mutant kills. Implementation: native Claude Sonnet 5.5 (high).

## Round 8 findings → fixes → tests

Reviewer reproductions (`test_independent_r8.py`, `test_round8_independent.py`) were run
unchanged in isolated copies. On `256356c` the upgrade case ends `active` with a running VM
while the older create is `uncaptured`, and the real `TerraformProvisioner.apply` spawns
`terraform apply` 1 s (injected) and 119 s after the plan expired. On the fix tree the
upgrade case ends `plan_failed` with no resources, the expired plan's binary is never spawned
(the reviewer's `delay=120` case now fails because its marker file is never written, which is
the intended outcome), and `delay=0` still dispatches.

| ID | Finding | Fix | Regression tests (`tests/test_review_round8.py`) | Mutants |
|---|---|---|---|---|
| R8-1 (P1) | Obligations were checked per deployment, so a newer reservation made before an older create became `uncaptured` could plan, be approved and apply | One owner-wide invariant: while any of the owner's deployments (any status) has an open `uncaptured` obligation, no create or repair work proceeds. Enforced at reservation, at approval (`409 recovery_required`), when the worker plans a create/repair, and in the apply precheck, so already queued reservations, ready plans and approved jobs are all stopped. Deletion plans and applies check only the deployment's own obligations, so cleanup is never blocked by someone else's | `test_r8_1_*` (queued reservation; ready plan; approved-and-queued apply; repair of a running VM; deletion still approvable and completing in each; other owners unaffected; a real schema-4 upgrade with a legacy-style queued reservation) | `r8-owner-wide-plan-gate`, `r8-owner-wide-apply-gate`, `r8-owner-wide-helper`, `r8-cleanup-plan-not-blocked`, `r8-cleanup-apply-not-blocked`, `r8-approval-gate`, `r8-approval-gate-blocks-cleanup` |
| R8-2 (P2) | `TerraformProvisioner.apply` exchanged credentials (STS) after the worker's last expiry check, so an expired approved plan was dispatched | The worker installs a dispatch guard (a context variable); `TerraformProvisioner._run` calls it for mutating commands after the environment and credentials are ready, immediately before `runner.run`; the simulator calls it at the start of `apply`. The guard raises `NotStarted`, which the worker records as a plain `plan_expired` failure (nothing ran, so no recovery obligation). The worker keeps its own in-transaction and post-transaction checks for provisioners that ignore the guard | `test_r8_2_*` (the boundary on its own with a 119 s exchange; ordering `credentials, check, run`; time left still applies; guard scope; simulator; worker to provisioner to runner; a real synthetic binary never spawned) | `r8-dispatch-check-at-boundary`, `r8-dispatch-check-before-credentials`, `r8-not-started-is-a-plain-failure`, `r8-simulator-honours-guard`, `r8-guard-installed-by-worker` |

The second plan-time recheck (after reconciliation) stays own-deployment only: it exists for
obligations that reconciliation itself opens, which are the deployment's own.

## Round 8 fix commit (parent `256356c`)

| Check | Result |
|---|---|
| ruff format and lint, `mypy --strict`, `uv lock --check`, `uv sync --locked` | passed |
| `pytest` with offline Terraform tests required | 486 passed |
| `scripts/check_guards.py --verbose` | 154/154 mutants killed for the intended reason in one full run (142 earlier, all retained, plus 12 new). All referenced test IDs collect and every mutation applies exactly once. Retargeted because the code moved: `r5-plan-gate`, `r6-gate-helper`, `r6-recheck-before-apply`, `r7-quota-unproven-obligation` (found by the static inventory audit) |
| pip-audit (hash-pinned), gitleaks (working tree) | passed, nothing found |
| Process-level offline runs (real API and worker processes) | Fresh data dir (migrations 1–7), client walkthrough exit 0. Upgrade of a schema-6 data dir seeded with an older unproven create and a legacy-style queued reservation for the same owner (`applied: [7]`): the reservation's plan failed `recovery_evidence_missing`, its deletion was planned, approved and completed, the next reservation was refused with `recovery_required`, `recovery-report` listed the older deployment. In all runs `/readyz` was 503 without a worker and 200 with one, a second worker was refused and the worker stopped on SIGTERM |
| CI on the exact pushed commit | reported in the handoff (the ledger cannot contain its own commit's SHA) |

Residual limits: unchanged from round 7 (the corrected statement above replaces the earlier
one about expiry). The dispatch check runs in the provisioner immediately before
`runner.run`; the interval from that call to the operating system starting the process is
not controllable from Python. A different `Provisioner` implementation must call
`check_dispatch()` at its own spawn boundary; the worker's checks before it remain as the
backstop. Live AWS behaviour, including real STS latency, remains part of the blocked live gate.

## PostgreSQL candidate review corrections (parent `9e8cd819`)

Independent Sol Medium review `79535099-05c1-4de1-bdfc-3165ec249666` of
`9e8cd8196a02a887129e1b7969154617085eea47` is **NOT CLEAN**. It independently
reproduced 541 passing tests, zero skips, one exact-SHA successful CI check and
154 reported mutant kills. Those totals did not prove recovery-reference integrity,
historical JSON usability or complete mutation failure classification.

Three required defects were reproduced before editing: a crossed recovery obligation
was cleared using another deployment's deletion evidence and then permitted a simulated
apply; an actual PostgreSQL DivisionByZero formatted by the application's JSON logger
was counted as a guard kill; and imported job/preview arrays committed a success receipt
but caused authenticated API 500 responses. The earlier blanket claim of 154 valid kills
on this PostgreSQL candidate is withdrawn. The original logs remain evidence of reported
outcomes, with the structured-logging counterexample limiting their assurance.

The earlier reserved-subject authentication claim is also corrected. Both reviewed
revisions reject signed JWT subjects beginning `dev:` in `JwtAuthenticator`. The earlier
reproducer constructed `Principal` directly; it proved source-owner assignment, not
successful JWT authentication or an authentication bypass. Explicit importer provenance
remains useful and unchanged. A signed-JWT API control now checks ordinary `carol`
acceptance and reserved `dev:carol` rejection.

The successor adds migration 0010 without rewriting migrations 0001–0009. Owned recovery
plan/job/discharge constraints and deferred apply-operation checks reject inconsistent
history, including later job updates that would invalidate it. Unknown null references
remain supported. Upgrade failure leaves corrupt obligations and schema version intact;
the worker independently scopes recovery evidence to the obligation's deployment, owner,
plan and apply job, retaining uncertainty on mismatch. Import validates the same source
relationships before writing history.

Historical JSON is checked against its actual consumers before the atomic success
receipt: job results, plan previews/cost/provider versions/prior IDs, completed assistant
replies, idempotent accepted responses, heartbeat checks and audit details. Validation
preserves source values and hashes; it does not normalize invalid data. The retained
synthetic history fixture was corrected to contain a complete resource-change preview,
a complete accepted response and a successful apply discharge job, rather than treating
those malformed examples as supported history.

Mutation calibration decodes only the known JSON logger's string `exception` field,
including escaped newlines, then applies the existing exception-diagnostic rules. Source
snippets and message-only examples are not exception evidence. Deliberate exact lock
timeouts still require their specified behavioral failure; other SQL errors veto a kill.
The review's actual formatter/worker/PostgreSQL reproduction is a regression control,
not one of the configured guard mutants.

Successor local verification: 583 tests passed, zero skipped, with one existing
fork-related DeprecationWarning on real PostgreSQL 15.19 and required offline Terraform
checks. The full calibrated guard run qualified 154/154 kills: 150 assertion failures
and four explicitly expected exception outcomes. All 154 retained reports failed in
call phase, with zero skipped outcomes; SQL diagnostics were limited to the five
specified lock-timeout cases and the expected owner-quota unique-index violation.
Nine separate classifier controls passed, including the actual application JSON-logged
DivisionByZero rejection. The diagnostic run's recovery-upgrade fixture failure was
corrected by removing/reapplying the full recovery subsystem; it is not counted as a
kill. Format, lint, strict types, lock consistency, dependency audit and staged secret
scan passed. Real API/worker subprocess create/inspect/approval/apply, durable restart,
worker exclusion and deletion passed against PostgreSQL with simulated cloud.

Exact committed-SHA process and CI evidence are recorded in the successor handoff. No clean independent successor review, live AWS lifecycle,
SDK parity or lifecycle/orphan-cleanup video is established here. The frozen `4f601eee`
owner-wide obligation and post-STS dispatch-expiry invariants remain required.


## PostgreSQL-only scope and completion integrity (parent `e5c43959`)

Independent review `582ed0f3-d39d-4992-bf73-c93e582874ae` found the parent NOT CLEAN,
despite 583 passing tests (including nine classifier controls), zero skips, 154 qualified
mutants and exact-SHA CI success. Its JSON-logged SQL false-kill finding was closed; its
new discharge contradiction and SQL-NULL completed-reply findings remained open.

At 00:55 UTC the user approved a clean PostgreSQL-only deliverable. The optional offline
SQLite importer/CLI and active synthetic SQLite fixture set are retired. Import-specific
reproductions are retired scope, not claimed repaired. Source remains in Git history and
existing review/artifact directories; no actual database, receipt, work/evidence file or
published migration is deleted or reset. The original SPEC chose SQLite for an undeployed
foundation, but the later explicit PostgreSQL requirement supersedes that runtime choice.
No concrete real SQLite cutover requirement was established by the available evidence.

Mixed-purpose native API, ownership, approval projection, worker, evidence, JSON result
and PostgreSQL upgrade tests remain, using direct PostgreSQL history. Import-only cases
are explicitly removed; the successor handoff records the node inventory difference.
The historical verification entries above describe their original candidates and are not
rewritten as current acceptance. The stale README runtime wording is corrected.

Forward migration 0011 validates evidence/discharge consistency and known job ordering,
including direct writes and later job updates, without rewriting migrations 0001–0010.
An invalid upgrade rolls back its pending schema changes and retains original history.
Unknown references and valid historical discharges remain supported. API/worker owner
safety gates, operator reporting and housekeeping independently treat contradictory
completion as unresolved; a timestamp alone is not evidence of safe completion.

Completed assistant attempts require a readable reply in PostgreSQL; reserved/failed
attempts may retain SQL NULL. Corrupt completed replay returns a controlled
`503 stored_reply_invalid` before model creation, without inventing a response or changing
history. Valid capture, approved repair, deferred discharge/job-success and restart paths
are covered by real PostgreSQL/API/worker regressions. The guard inventory retains the
154 prior mutants (one admin SQL target mechanically follows its changed query) and adds
three focused completion/reply mutants. Frozen successor results belong in its handoff.

Lifecycle integration, fresh independent exact-SHA review, actual AWS access and the
create/inspect-edit/stop-start/delete/final orphan-cleanup video remain pending. No PR,
live cloud, credentials, image build, deployment or merge is authorized by these results.


Successor local verification: 578 tests passed, zero skipped, one existing fork-related
DeprecationWarning on real PostgreSQL 15.19 with offline Terraform cases required.
The test inventory changes from 583 are explicit: 536 unchanged node IDs, 36 retired
import-only cases, 11 old cases replaced by 13 PostgreSQL cases, and 29 new completion
cases. The nine classifier controls are included in the 578 aggregate, and also retained
in a focused diagnostic run. No skip substitution was used.

All 157 configured guard mutants qualified: the original 154 plus three new completion
mutants. Retained reports have call-phase failures and zero skips; SQL diagnostics are
limited to the five deliberate lock-timeout cases and the explicitly expected quota-index
UniqueViolation. Format, lint, strict types (36 source files), lock consistency, dependency
audit and staged secret scanning pass. Actual API/worker subprocess create, inspect,
approval, simulated apply/delete, worker exclusion and durable restart pass on PostgreSQL.
Exact committed-SHA process/CI results, preservation evidence and the precise port contract
are recorded in the successor handoff; these results do not establish a clean independent
review or live lifecycle/video completion.
