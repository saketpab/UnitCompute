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
| Two clean independent Sol Medium review rounds on the final commit | Round 1 on `715e5e3`: **not clean** (both reviews). Round 2: pending |
| Safe CI on the exact pushed commit | `715e5e3`: passed ([run 40959338191](https://github.com/saketpab/UnitCompute/actions/runs/40959338191)). Round-1 fix commit: see below |
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

## Round 1 fix commit (parent `715e5e3`)

| Check | Result |
|---|---|
| ruff format and lint, `mypy --strict`, `uv lock --check` | passed |
| `pytest` with offline Terraform tests required | 267 passed |
| `scripts/check_guards.py` | all mutants killed (27 existing + 18 new = 45) |
| Reviewer reproductions against `715e5e3` and the fix tree | see "Round 1 findings" above |
| pip-audit (hash-pinned) | no known vulnerabilities |
| gitleaks (working tree) | no leaks |
| Process-level offline run (real API and worker processes) | `/readyz` 503 without a worker and 200 with a healthy worker; client walkthrough exit 0; repeated chat `Idempotency-Key` returned the same session over HTTP; second worker refused by the lock; Terraform with dev auth refused at configuration |
| CI on the exact pushed commit | recorded in the handoff for this commit |
