# Operating UnitCompute

This covers production configuration, the AWS prerequisites that must exist before
UnitCompute can provision anything, and how to handle failures. UnitCompute never creates
these prerequisites itself.

## Process model

Run three things on one persistent host:

| Process | Command | Notes |
|---|---|---|
| Migrations | `unitcompute-admin migrate` | Run on every deploy, before the API and worker start. Both refuse to start on an outdated schema. |
| API | `unitcompute-api --host <addr>` (or `uvicorn --factory unitcompute.api.main:app_factory`) | Stateless apart from the database. Put TLS termination in front of it. |
| Worker | `unitcompute-worker` | Exactly one per data directory, enforced by an exclusive `flock` on `data/worker.lock` that every Terraform child inherits. Stop it with SIGTERM and allow it to finish the current job; an apply can take up to `UNITCOMPUTE_APPLY_TIMEOUT_SECONDS`. |

Both the API and the worker read and write `UNITCOMPUTE_DATA_DIR`, which must be on durable
local storage (not tmpfs, not a network filesystem). It holds the SQLite database (WAL
mode), per-plan Terraform work directories and logs. Everything is created with owner-only
permissions. Back it up with `sqlite3 data/unitcompute.sqlite3 ".backup <file>"`.
Terraform state is not stored here; it lives in S3.

### Worker self-check and readiness

At start-up, and every `UNITCOMPUTE_WORKER_SELF_CHECK_SECONDS` (default 300), the worker
verifies:

- the pinned Terraform version;
- that each execution role can be assumed;
- that STS reports each role as `assumed-role/<configured role name>` in the configured
  account;
- that the two roles are distinct;
- that the official AL2023 AMI resolves.

A worker that fails its self-check takes no jobs. `/readyz` returns `503` unless the
schema is current and, whenever provisioning is enabled, the newest worker heartbeat is
younger than `UNITCOMPUTE_WORKER_STALE_SECONDS` (default 120) and its self-check passed. The
failing check's code is included in the response. Only the last four digits of the account
are reported.

### Database contention

The worker retries acquiring the write lock for terminal job updates with bounded backoff.
If an update still cannot be written, the worker recovers that job the next time it is idle,
while it still holds the worker lock: a plan becomes `failed`, and an apply becomes
`recovery_required`. An apply is never replayed.

## Production configuration

Production refuses to start unless all of the following are set. Unknown `UNITCOMPUTE_*`
variables are also rejected.

| Variable | Purpose |
|---|---|
| `UNITCOMPUTE_ENVIRONMENT=production` | Enables fail-closed validation |
| `UNITCOMPUTE_AUTH_MODE=jwt`, `_AUTH_ISSUER`, `_AUTH_AUDIENCE`, `_AUTH_JWKS_URL` (https), optional `_AUTH_JWKS_CACHE_SECONDS` (default 300) | Token verification. Signing keys are not cached individually: a key removed from the issuer's JWKS stops being accepted within the JWKS cache lifetime. |
| `UNITCOMPUTE_AUTH_REQUIRED_GROUP`, optional `_AUTH_GROUPS_CLAIM` (default `groups`) | Team membership |
| `UNITCOMPUTE_PROVISIONER=terraform` | The simulator and the disabled mode are refused in production. In any environment, Terraform provisioning requires `auth_mode=jwt` with a team group, so development identities can never drive real infrastructure. |
| `UNITCOMPUTE_AWS_ACCOUNT_ID`, `_VPC_ID`, `_SUBNET_ID`, `_INSTANCE_PROFILE_NAME` | Approved bootstrap network and SSM profile |
| `UNITCOMPUTE_STATE_BUCKET` | Bucket for per-deployment state |
| `UNITCOMPUTE_PLAN_ROLE_ARN`, `UNITCOMPUTE_APPLY_ROLE_ARN` | Two distinct execution roles |
| `UNITCOMPUTE_TERRAFORM_BINARY` | Path to Terraform **1.17.1**; any other version is refused |
| Optional: `UNITCOMPUTE_TERRAFORM_PLUGIN_CACHE_DIR`, `_CORS_ORIGINS`, `_MAX_REQUEST_BYTES`, timeouts, `_WORKDIR_RETENTION_DAYS` | |
| Optional: `UNITCOMPUTE_AGENT_MODEL=<provider>:<model>` plus the provider key (`ANTHROPIC_API_KEY` or `OPENAI_API_KEY`) | Without these the assistant returns `503 agent_unavailable` and the REST workflow keeps working. Install the matching extra (`uv sync --extra anthropic`). The runtime model is independent of any model used to write this code. |

Run `unitcompute-admin check-config` to validate the configuration without starting
anything.

## AWS bootstrap prerequisites (operator-owned)

These resources are long-lived and shared. They must be created and reviewed separately,
for example in a dedicated bootstrap Terraform configuration whose state lives under
`bootstrap/` (or in another bucket). UnitCompute's runtime roles are explicitly denied
access to that prefix, and nothing in this repository applies them.

1. **Network.** A VPC in `us-east-1` with one public subnet. The subnet needs a route to an
   internet gateway and must auto-assign public IPv4 addresses. No NAT gateway and no
   Elastic IPs: each VM gets an ephemeral public IPv4 address (about $3.65/month) for
   outbound HTTPS to SSM and package repositories. Inbound traffic is impossible because
   each VM's security group has no inbound rules.
2. **SSM instance role and profile.** An IAM role trusted by `ec2.amazonaws.com` with the AWS
   managed policy `AmazonSSMManagedInstanceCore`, and an instance profile for it. Its ARN is
   the only role the apply role may pass.
3. **State bucket.** Turn on versioning, default encryption (SSE-S3, or SSE-KMS with
   `kms:Decrypt`/`kms:GenerateDataKey` granted to both runtime roles), Block Public Access
   (all four settings), and a bucket policy that denies non-TLS requests. Each deployment
   uses the key `deployments/<deployment_id>/terraform.tfstate` and locks with S3
   `use_lockfile` (`.tflock` objects). The deprecated DynamoDB locking is not used.
4. **Runtime roles.** Use [docs/iam/plan-role-policy.json](iam/plan-role-policy.json) and
   [docs/iam/apply-role-policy.json](iam/apply-role-policy.json) as starting points. Replace
   the `${…}` placeholders, then review the policies and test them with IAM Access Analyzer
   policy validation before use. The plan role is read-only for infrastructure. It may
   only read `terraform.tfstate` (writes and deletes are explicitly denied), but planning
   still needs `GetObject`/`PutObject`/`DeleteObject` on the separate `.tflock` objects.
   The apply role may read and write state but never delete it.
   The apply role can only launch tagged `t3.micro` instances with IMDSv2 and encrypted gp3
   disks of 30 GiB or less in the approved subnet, manage resources tagged
   `ManagedBy=unitcompute`, and pass only the SSM instance role. Both roles must trust only
   the host's identity, with a short maximum session duration
   ([docs/iam/role-trust-policy.json](iam/role-trust-policy.json)). The trust policy also
   allows `sts:TagSession` only for a single `UnitComputeDeployment` tag.

   **Per-deployment sessions.** Every `AssumeRole` call for planning or applying a
   deployment passes that deployment's ID as the `UnitComputeDeployment` session tag and an
   inline session policy, generated by `session_policy()` in
   `src/unitcompute/provisioning/aws.py`. The session can then only:
   - read (plan) or read and write (apply) that deployment's `terraform.tfstate`;
   - use that deployment's `.tflock`;
   - create resources tagged with that deployment ID;
   - change or terminate resources already carrying that tag.

   The role policies apply the same restriction again through
   `${aws:PrincipalTag/UnitComputeDeployment}`, so the scope still holds if a session
   policy were missing. Sessions not tied to a deployment are restricted further:
   - the plan role is read-only, with no state access (inventory, readiness, ID lookups);
   - the apply role is denied everything, and is only used to prove its identity in the
     self-check.

   The worker refuses to run if a session policy would exceed the 2,048-character STS
   limit; it never falls back to an unscoped session.
5. **Host identity.** The host gets temporary credentials, for example from an EC2 instance
   profile, that can only call `sts:AssumeRole` on the two runtime roles. Do not use
   long-lived access keys or root credentials. The API process never receives runner
   credentials, and nothing returns them to clients.
6. **User SSM access.** For a user to open a session, their own AWS identity needs
   `ssm:StartSession` on their instance, for example scoped by the `UnitComputeDeployment`
   tag. A UnitCompute login does not grant this.
7. **Billing guardrails.** AWS Budgets alerts are useful, but they only notify; they do not
   cap spending.

## How a change runs

1. Planning resolves the current official AL2023 AMI (SSM public parameter, then
   `DescribeImages` confirms it is Amazon-owned, `x86_64` and `available`) and freezes it in
   the plan. It then copies the reviewed template into a fresh private work directory and
   writes validated tfvars JSON. It runs `terraform init -lockfile=readonly` with the
   per-deployment backend key, then `terraform plan -input=false -out=tfplan` (with
   `-destroy` for deletion), then `terraform show -json`.
2. The plan policy allows only `aws_instance.vm` and `aws_security_group.vm` with the
   expected actions, attribute values and ownership tags. It rejects extra resources, data
   sources, modules, provider arguments, replacements and untracked tagged resources
   (orphans).
   Volumes must be tagged at launch through `volume_tags`, which the provider sends as
   RunInstances `TagSpecifications`. `root_block_device.tags` are rejected: the provider
   applies them with a later `CreateTags` call, which the tag-on-create IAM policies deny.
   It also rejects provisioners, unreviewed arguments or meta-arguments, and any
   instance-to-security-group attachment other than the deployment's own group. For newly
   created resources, attributes outside the reviewed set (for example `key_name`,
   `tenancy`, extra network interfaces, or custom IOPS or throughput) are rejected.
3. The binary plan is stored read-only, together with:
   - its SHA-256;
   - the template, Terraform and provider versions;
   - account, region, AMI and state key;
   - an execution-binding hash over the account, VPC, subnet, instance profile, state bucket
     and key, and both role ARNs;
   - the resource IDs in prior state;
   - the cost snapshot and a 15-minute expiry.
4. Approval, and the worker again just before applying, re-check owner, plan type, expiry,
   hash, versions, execution binding and job state. Apply runs exactly
   `terraform apply -input=false tfplan` with apply-role credentials.
5. A create is marked `active` only after the instance is found by its tags and by direct
   ID lookup. Its instance, security group and root volume IDs are recorded. Connection
   readiness (both EC2 status checks plus SSM `Online` for that exact instance) is then
   observed for up to `UNITCOMPUTE_READINESS_TIMEOUT_SECONDS` and refreshed every
   `UNITCOMPUTE_READINESS_REFRESH_SECONDS`.
6. A deletion is marked `deleted` only after no tagged resource remains and every recorded
   or state-known instance, volume and security group ID is confirmed gone by direct
   lookup. If existence cannot be established, the deployment stays `recovery_required`
   and keeps its quota slot.

Terraform runs with a fixed argument list (`shell=False`), a minimal environment (no
inherited variables, no shared AWS config files, no IMDS), a separate process group, and a
timeout that kills the whole group. Logs are capped, redacted and stored with mode `0600`
under the plan's work directory.

## Recovery

`recovery_required` means AWS may hold partially changed, possibly billable resources. It
happens when the worker died mid-apply, an apply failed or timed out, or the
post-apply verification failed.

1. `unitcompute-admin recovery-report --inventory` lists affected deployments, their last
   job, every identity ever recorded for them, any instance whose launch root was never
   identified, open recovery obligations, and the AWS resources currently tagged for each
   one (read-only).
2. Do not force-unlock, push, import or delete state, and do not re-run old plans.
   UnitCompute never does any of these automatically either. The worker lock guarantees
   no earlier Terraform process is still running once a new worker starts.
3. The owner, or an operator acting through the API as the owner, requests a new preview.
   Use `POST /plan` to finish or repair the VM, or `POST /deletion-plan` to clean up. The
   preview refreshes state against AWS, and any change still needs explicit approval.
4. If the preview is rejected because AWS has resources that are recorded or tagged for the
   deployment but are not in state (orphans), an operator must decide whether to
   `terraform import` them into that deployment's state or delete them by hand. Afterwards,
   request a new preview. Never let the application guess. A recorded VM that is still
   running therefore always blocks a repair preview from launching a second VM.
5. `recovery_evidence_missing` means an apply may have changed AWS but what it created
   could not be read (see Recovery obligations), or an evidence file is corrupt. Every
   repair and deletion preview is refused, and deletion cannot be verified.
6. `identity_incomplete` means an instance is known, but its **launch root** was never
   recorded by UnitCompute. Typical causes are a deployment created before identities
   were tracked, or an instance seen only by tag or in refreshed state. The original root
   disk may still exist and be billable (AWS root replacement, for example, can keep the
   original volume). So every repair and deletion preview is refused. There is no waiver,
   and no operator command can assert which volume was the root. Restoring or importing
   Terraform state does not help: a preview refreshes it from AWS, so it only shows what
   exists now, which is an observation, not launch evidence.

In both cases the deployment stays in recovery and keeps its quota. Resolving it is a
deliberate support decision outside the application, made with the retained work
directory, the identity evidence and the AWS inventory.

### Recovery obligations

Whenever an apply fails, times out, crashes or is found interrupted at startup, the worker
records a recovery obligation for it. Obligations can never be deleted, and each one has
an evidence state that only moves forward:

- `captured`: what the apply did was established from state **bound to that apply** and
  recorded. Terraform exiting, normally or by signal, proves nothing about what it
  persisted, so the worker accepts only a raw state document that is:
  - a complete envelope: format 4, the pinned Terraform version, a lineage, a serial,
    and explicit `resources` and `outputs`; a document with a missing field, or with
    outputs that disagree with its resources, is refused;
  - confined to the template (one `aws_instance.vm`, at most one `aws_security_group.vm`,
    well-formed IDs, no modules, `count`/`for_each` or deposed objects);
  - tied to the saved plan that ran: the plan file is unchanged since approval, the lineage
    matches the plan's prior state, the serial is not older, the state shows at least one
    resource the plan creates, and every created ID is new (not in the plan's prior state).
  Sources: `errored.tfstate` in the plan's work directory (Terraform's final state, which
  may show a partial outcome), or, only right after the apply and only for the latest
  apply, the stored state from the read-only `terraform state pull`, which must show
  every resource the plan creates because a stored snapshot can be stale. After a crash
  or on a later retry only `errored.tfstate` is read. If both the backend write and the
  `errored.tfstate` write fail, the stored state is empty and nothing is accepted. Any
  well-formed ID in a state that is read but not accepted is still recorded as an
  observation that must be verified gone.
- `not_needed`: the plan's recorded changes show it creates nothing (deletions only), so
  the apply could not have created anything. Unreadable changes count as creating.
- `uncaptured`: nothing acceptable was found. Empty state, empty tags and no known IDs do
  not prove that nothing was created. The worker retries the `errored.tfstate` read before
  every plan.

An obligation is discharged only by the next successful apply for the deployment, and
only if it is `captured` or `not_needed`. An `uncaptured` obligation is never discharged:
every later plan fails with `recovery_evidence_missing`, including an empty one. A corrupt
or malformed record in a deployment's `identities.jsonl` opens an `uncaptured` obligation
for that deployment only (reason `evidence_file_corrupt`). Other deployments and jobs
keep running. Open obligations are checked when a plan starts, again after its
reconciliation (which can open one), and again immediately before `terraform apply`, so an
obligation opened after a plan was approved still stops the apply. A read that merely waits
on a writer, or fails transiently, is not corruption.

Migration 0006 revalidates history: every earlier failed apply of a plan that could create
resources gets a new `uncaptured` obligation (migration 0005 had discharged some merely
because a later apply succeeded), which the worker clears only from a retained, valid
`errored.tfstate`. Obligations of plans that only delete are marked `not_needed`.

### Resource identity evidence

Every resource ID the worker learns is appended to `data/work/<deployment>/identities.jsonl`
and then imported into the `deployment_resources` table. Neither can be updated or deleted.
Appends are serialized across processes with an exclusive `flock`; imports take the shared lock (bounded wait) so a write in progress is never read as a torn record. Short writes are
completed, and a record torn by a crash is terminated before the next append. The file is
fsynced. Every directory any component creates (the data directory and its missing ancestors, the
worker lock, work directories, the Terraform runner's home and logs, the simulator) goes
through one helper that fsyncs the parent of each directory it creates. Evidence is kept
per source, so the same volume can be recorded as attached, as an observed root and from
an apply. Recording only succeeds once the exact rows are present in the table.

Two kinds of evidence are kept apart:

- **Launch-root evidence** completes an instance's identity. It is the root volume
  recorded from the apply that launched the instance: that apply's outputs
  (`launch_output`) or its errored or stored state, read without a refresh
  (`launch_state`). Root IDs written by earlier versions (`apply_output`,
  `deployment_record`, `migration`) record outputs of any create-kind apply, including
  failed repairs and refreshed values, so they count only when the deployment's history
  has exactly one create-kind apply that ran Terraform, it succeeded, and its recorded plan
  created the VM. Counts of successful jobs, or a later no-op success, prove nothing.
- **Observations** never complete identity: refreshed plan state (`terraform_state`),
  outputs of an apply that did not launch the instance, the volume currently at the
  instance's root device name (possibly a replacement), other attached disks, and tag
  inventory. Every observed resource is still reconciled against Terraform state and must
  be confirmed gone before deletion. A source label alone is not provenance.

Planning, for both repair and deletion, refuses to proceed while any known instance lacks
launch-root evidence. Deletion is complete only when every known instance, volume and
security group is confirmed gone by direct lookup. The retired schema-3
`identity_acknowledgements` rows and the removed `record-root-volume` command grant nothing.

A failed or expired plan never changes infrastructure, so you can always request a new
preview.

## Retention

- Plan work directories (saved plan, tfvars, logs, `.terraform`) are deleted by the worker
  `UNITCOMPUTE_WORKDIR_RETENTION_DAYS` days (default 7) after creation, once the plan is
  terminal. The work directory of a failed or uncertain apply is kept until every recovery
  obligation for that plan is discharged. An `uncaptured` one keeps it forever. It may
  hold Terraform's `errored.tfstate`.
- Deployment, plan, job and audit rows are kept, and deleted deployments keep their audit
  history. Audit details hold only identifiers and short redacted values.
- Chat history is stored per session and owner, and only the last
  `UNITCOMPUTE_AGENT_HISTORY_MESSAGES` messages are sent to the model.

## Sandbox verification (needs separate authorization)

Before any production use, someone with sandbox AWS access and spending authority should
run this once against the real bootstrap. No such run has been recorded yet.

1. Configure production-like settings against the sandbox bootstrap.
2. Create `demo`/8 GiB, review the preview, and approve it. One VM launches.
3. Check EC2 status checks pass, SSM shows the instance as `Online`, and
   `aws ssm start-session` works from an authorized AWS identity. Confirm IMDSv2, the
   encrypted gp3 root disk, the security group with no inbound rules and the tags.
4. Request a deletion plan and approve it.
5. Confirm no instance, volume or security group tagged with the deployment ID remains, that
   the bootstrap network, roles and bucket are unchanged, and that the state object and
   audit trail remain.
