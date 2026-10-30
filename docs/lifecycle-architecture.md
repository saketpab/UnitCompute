# Lifecycle operations: architecture and integration contract

Scope added after the round-8 safety candidate (`4f601eee7ac0c3b6f7f61ba1315446d4ca3b272c`):
a validated, configurable region; create; inspect; edit (name, larger root disk); stop and
start; delete; and a final orphan check. This page records what is supported, how, where the
boundaries are, and exactly what a persistence port has to carry over. Offline checks (tests,
moto, real offline Terraform plans) show the code and policies agree with Terraform and with
EC2's API shape. They do not show that AWS accepts these resources or permissions; that is the
separate live acceptance in the last section.

## What is supported, and what is not

| Capability | Supported | How | Not supported (and refused) |
|---|---|---|---|
| Region | one region per installation, validated at startup | `UNITCOMPUTE_AWS_REGION`, checked against `config.SUPPORTED_REGIONS` (regions with a reviewed price snapshot) | multi-region, unreviewed regions |
| Create | yes | exact-plan Terraform apply | – |
| Inspect | yes | `GET /deployments/{id}`: recorded values, `power_state`, `instance_state`, readiness | arbitrary guest inspection |
| Rename | yes | tag update (`Name`) on the VM, its disk and the security group | any other tag |
| Disk size | grow only | in-place `root_block_device.volume_size` | shrinking (EBS cannot; Terraform plans it as an update that AWS would reject at apply, so the policy refuses it), another volume type, extra volumes |
| Stop, start | yes | `aws_ec2_instance_state` (`force = false`) | forced stop, hibernate, reboot, resize of the instance type |
| Delete | yes | exact-plan destroy, verified by direct lookup of every recorded ID | – |
| Orphan check | read-only report | `unitcompute-admin orphan-report` | automatic cleanup of anything not tied to an approved plan |

Instance type, image, network, profile and metadata options are fixed by the server and are not
editable. There is no SDK-demo parity claim: that demo's source was not available.

## The mechanism, and why

Every mutation is a Terraform plan on the same reviewed template, so each one inherits, without
new code paths, the guarantees the earlier review rounds established:

- exact-plan approval (plan ID + SHA-256, 15-minute expiry, execution binding);
- a fresh expiry check after all preparation, immediately before the process is spawned
  (`base.dispatch_guard` / `check_dispatch`, called by the provisioner);
- the owner-wide recovery rule (create, edit, stop and start are blocked while any of the owner's
  earlier applies is unproven; deletion never is);
- the state and recovery guarantees: state lock, `errored.tfstate` capture bound to the plan,
  obligations, no automatic state push/import/force-unlock.

Alternatives considered and rejected:

- **boto3 for stop/start/resize.** It would need a second "plan" record with its own hash,
  expiry and approval, its own evidence and recovery story, and it would leave Terraform state
  disagreeing with AWS (a stopped instance, a grown volume). boto3 is used only to *read*.
- **A new plan kind or deployment statuses.** Both are `CHECK` constraints, which would force
  a table rebuild in SQLite and a competing schema change. Instead plans keep kind `create`
  ("converge the deployment on its requested spec": create, repair or edit in place) and a
  validated edit request is stored on the plan.

A stop or an edit creates nothing, so a failed one records a `captured` or `not_needed`
obligation and never leaves an unproven create.

### Policy for an edit

`policy.evaluate_plan` (kind `create`) allows `update` actions only on the three template
resources and only for:

- `aws_instance.vm`: `tags`, `tags_all`, `volume_tags`, and `root_block_device` where the size
  matches the request and is not smaller than before; every other attribute must be unchanged,
  the instance must still match the full reviewed shape (IMDSv2, profile, subnet, AMI, no user
  data...), and attributes the provider cannot predict for an update may be unknown only from a
  short list (the template hash pins their values);
- `aws_security_group.vm`: `tags`, `tags_all`;
- `aws_ec2_instance_state.vm`: `state` (one of `running`/`stopped`, equal to the request,
  `force` false, targeting this deployment's own instance).

Replacement (delete + create) of anything is never allowed. The plan must also match the
request it was made for (variables and tags), or it is rejected. These rules were checked
against real Terraform 1.17.1 output for each edit (`tests/test_policy_updates.py`).

### State machine

Statuses are unchanged. An edit runs `active` → `planning` → `awaiting_approval` → `applying` →
`active`. If the edit's plan is rejected, fails, expires or is refused at dispatch, the VM goes
back to `active` and nothing changed. If its apply fails, the deployment is `recovery_required`
like any other failed apply; the owner can re-submit the edit (the recorded values change only
after an apply has been verified against EC2).

## Boundaries: provider versus execution engine

The execution engine is everything that does not mention AWS resources: `services/`,
`worker.py` (claim, plan, approve, dispatch, evidence, recovery), the schemas and the API. It
talks to infrastructure only through the `Provisioner` protocol in `provisioning/base.py`:

`runtime_versions`, `network_targets`, `plan`, `apply`, `capture_stored_state`, `prior_state`,
`owned_resources`, `find_resources`, `instance_volumes`, `instance_details`,
`managed_resources`, `connection_readiness`, `self_check`, plus the dispatch guard contract
(`apply` must call `check_dispatch()` immediately before it starts a mutating process).

Everything AWS-specific sits behind it: the Terraform template, `policy.py`, `aws.py`,
`state_evidence.py`, `terraform.py`, `simulated.py`, the IAM documents. Another provider would
supply its own implementation of that protocol, template and policy; nothing else has to
change. This is the extension point and nothing more: no other provider is implemented. Honest
leaks to know about: `worker.py` still names the AWS resource addresses (`aws_instance.vm`...) in
`plan_launches_instance`, the identity ledger knows `instance`/`volume`/`security_group`, and
`state_evidence` parses AWS state. A second provider would generalise those first.

## Compatibility contract for the PostgreSQL port

Schema (additive only; no existing column, constraint or index changes). These three columns are
all the lifecycle work needs; they are migration `0008_lifecycle_operations.sql` in this tree:

| Table | Column | Type | Meaning |
|---|---|---|---|
| `deployments` | `power_state` | text, nullable | last verified desired power state, `running` or `stopped`; NULL means `running` |
| `deployments` | `instance_state` | text, nullable | EC2 state name last observed by the worker (informational) |
| `plans` | `request_json` | text/jsonb, nullable | validated edit request `{"name"?, "disk_gib"?, "power_state"?}`; NULL for create, repair and delete |

Rules the port must keep (all enforced in code, nothing in the database):

1. `plans.kind` stays `create`/`destroy`. A plan with a non-NULL `request_json` is an *edit*
   (`operation = "update"` in the API); one without is create/repair/delete.
2. `deployments.name`, `disk_gib` and `power_state` are written only by the worker, in the
   transaction that marks an apply successful, and only after the provisioner's
   `instance_details` read-back matched (state and root disk size). Planning uses
   `Worker._spec(deployment, plan)`: row values overridden by the plan's request.
3. `observe_readiness` also writes `instance_state` (`COALESCE(new, old)`).
4. The disk check constraint `disk_gib BETWEEN 8 AND 30` stays.
5. Statuses are unchanged; a failed edit plan returns the deployment to `active`
   (`_finish_plan_failure`: a plan with `request_json` on a deployment that has an
   `instance_id`).

Exact shared service and worker changes to merge (against `4f601eee`):

- `services/deployments.py`: `unresolved_create_obligation` (new, shared by quota, approval and
  the worker); `create_deployment` uses it; `approve` refuses create-kind plans while it is set;
  new `request_update`; `_enqueue_plan(edit=...)` stores `request_json` and hashes the edit into
  `config_hash`; `_plan_preview` adds `operation` and `request`; `_detail` adds `power_state`
  and `instance_state`.
- `worker.py`: `edit_request`, `_spec(deployment, plan)`, `planned_creates` (only
  `action == "create"` counts as a create), `_edit_warnings`, the cost call (`running=`),
  the "edit would change nothing" rejection, `_edit_problem` and the widened success `UPDATE`
  (`name`, `disk_gib`, `power_state`, `instance_state`), `_finish_plan_failure`'s
  `edited_vm` branch, `observe_readiness` writing `instance_state`, and
  `_require_no_uncaptured(deployment_id, owner_id)` for create-kind work.
- `api/app.py`: `POST /deployments/{id}/update-plan`; `schemas.py`: `UpdateRequest`,
  `PowerState`, the new response fields.
- `admin.py`: `orphan-report`.
- Not schema-related but in the same files: `config.py` (region validation), `pricing.py`
  (per-region snapshots, `running=`), `agent/service.py` (region).

SQL the port must re-express: the lifecycle additions use only portable SQL (`ALTER TABLE ADD
COLUMN`, joins, `LIMIT 1`). The earlier safety migrations 0006 and 0007 already contain SQLite
JSON functions (`json_valid`, `json_type`, `json_each`) in a trigger and two statements; the
port owns their translation.

## Live acceptance (owned by the parent; not run here)

Needs a sandbox account, the bootstrap network/IAM/state bucket in `us-east-1`, the role
policies from `docs/iam` filled in (including `${region}`), the pinned Terraform 1.17.1 and
provider 6.71.0, and a spending limit (the approved budget is USD 5). Suggested order, each step
captured as a screen recording plus the API JSON:

1. `unitcompute-admin recovery-report` and `orphan-report` are empty (baseline).
2. Create: preview, approve by hash, active; `aws ec2 describe-instances` shows the instance,
   tags, IMDSv2, encrypted gp3 root.
3. Inspect: `GET /deployments/{id}` (`power_state`, `instance_state`, readiness `ready`),
   SSM session starts.
4. Edit: rename and grow the disk in one preview; tags and `describe-volumes` show it; check the
   filesystem inside the VM.
5. Stop: `instance_state` `stopped`, `describe-instances` agrees. Start: `running`, readiness
   returns.
6. Delete: preview with the data-loss warning, approve; the job ends `deleted`.
7. `orphan-report` is empty and `aws ec2` by tag `ManagedBy=unitcompute` finds nothing; remove
   anything the test left behind by hand.

Things only this run can show, and where a failure would point:

- the `aws_ec2_instance_state` resource's real stop/start behaviour and its IAM needs
  (`StartInstances`/`StopInstances`);
- `ec2:ModifyVolume` and `DescribeVolumesModifications` in the apply role, and that the volume
  is tagged so the tag condition matches (volumes are tagged at launch via `volume_tags`);
- the rename statement (`CreateTags`/`DeleteTags` with `ForAllValues:StringEquals aws:TagKeys =
  [Name]`) as the AWS provider actually issues tag calls;
- that the packed session policy stays under 2048 characters with the real bucket name
  (offline limit: a 63-character bucket fits);
- `terraform state pull`, real STS latency against the dispatch-time expiry, and the instance
  public IPv4 behaviour across stop/start.
