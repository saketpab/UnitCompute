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
| `UNITCOMPUTE_AUTH_MODE=jwt`, `_AUTH_ISSUER`, `_AUTH_AUDIENCE`, `_AUTH_JWKS_URL` (https) | Token verification |
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
   the host's identity, with a short maximum session duration.
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
   job and the AWS resources tagged for each one (read-only).
2. Do not force-unlock state, delete state, or re-run old plans. The worker lock guarantees
   no earlier Terraform process is still running once a new worker starts.
3. The owner, or an operator acting through the API as the owner, requests a new preview.
   Use `POST /plan` to finish or repair the VM, or `POST /deletion-plan` to clean up. The
   preview refreshes state against AWS, and any change still needs explicit approval.
4. If the preview is rejected because AWS has tagged resources that are not in state
   (orphans), an operator must decide whether to `terraform import` them into that
   deployment's state or delete them by hand. Afterwards, request a new preview. Never let
   the application guess.

A failed or expired plan never changes infrastructure, so you can always request a new
preview.

## Retention

- Plan work directories (saved plan, tfvars, logs, `.terraform`) are deleted by the worker
  `UNITCOMPUTE_WORKDIR_RETENTION_DAYS` days (default 7) after creation, once the plan is
  terminal. Directories for plans whose deployment is still `recovery_required` are kept as
  evidence.
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
