# UnitCompute
Easy-to-use service to simplify AWS usage

## Terraform VM lifecycle

A small Terraform module (`terraform/aws_vm`) plus a Python wrapper (`unitcompute_vm`) that a
script can call to **create, inspect, edit, stop/start and delete one EC2 VM**. There is no web
API, worker or database: state lives in a folder per VM.

```python
from unitcompute_vm import AwsVMs, Network, resolve_request

vms = AwsVMs("~/.unitcompute/vms", Network("subnet-0abc...", ("sg-0abc...",)))

spec = resolve_request(translator.translate(text))  # raises MissingInputs([...]) if incomplete
plan = vms.plan_create(spec)  # saves the exact Terraform plan; creates nothing
print(plan.summary, plan.sha256)  # review it
info = vms.apply(plan)  # applies that saved plan, then reads EC2 back

vms.inspect(info.vm_id)  # recorded config next to what EC2 reports now
vms.apply(vms.plan_update(info.vm_id, name="web-2", disk_gb=20))
vms.apply(vms.plan_update(info.vm_id, power_state="stopped"))  # and "running" to start
vms.apply(vms.plan_delete(info.vm_id))
```

`resolve_request` takes the notebook's `VMRequest` (or any dict). `name`, `operating_system` and
`compute_size` are required; `region` defaults to `us-east-1`; `disk_gb` defaults to the selected
image's minimum root size (read from the image) and can be overridden (8-100 GiB).

### What is supported

| | |
|---|---|
| OS | `ubuntu` (24.04 LTS) and `windows` (Server 2022), as mapped in the notebook; images are looked up through the public SSM parameters when a VM is planned and then fixed for the life of that VM |
| Size | `small` = t3.micro, `medium` = t3.small, `large` = t3.medium |
| Region | any real AWS region, one per VM, chosen at creation |
| Network | you pass an **existing** subnet and security groups. Nothing in networking, security groups or IAM is created or changed, so how you reach the VM is up to them |
| Edit | `name`, `purpose` (tags) and `disk_gb` (grow only) |
| Power | `plan_update(power_state="stopped"/"running")`; a stop is a clean OS shutdown |
| Not editable | OS, size, region, network, shrinking the disk. Change one by deleting and creating a VM |

### How changes are governed

- `plan_*` runs `terraform plan -out`; `apply` runs that saved file and nothing else. It refuses a
  plan whose file hash differs from the one you were shown, one already used, or one made before
  a newer change to the same VM.
- A plan that would replace or destroy anything during create/edit (for example a VM that was
  terminated outside this tool), or change anything beyond tags, disk size and power state, is
  rejected before you can approve it.
  Repair after a failed or killed apply may create only what that apply never reached; once the
  instance has existed (in state, or remembered in `vm.json` through an interrupted delete), a
  missing one is never rebuilt: delete the VM and create a new one.
  `inspect` reports an instance AWS no longer knows as a problem, not as consistent.
- After an apply, EC2 is polled until the instance state, root disk size and Name tag match;
  otherwise `VerificationFailed` is raised and nothing is rolled back.
- Delete verifies that no instance or volume tagged `UnitComputeVm=<vm_id>` is left.

### State is your responsibility

Everything for one VM is in `<state_root>/<vm_id>/`: `terraform.tfstate`, saved plans, one log
per Terraform run, a state copy taken before each apply, and `vm.json`. **Keep and back up this
folder**; without the state, Terraform can no longer manage or delete the VM. It is never
deleted by this package, including after `plan_delete` + `apply`. It is not shared between
machines: one folder, one machine.

If an apply fails or is killed, the VM is `incomplete` (see `inspect().problems`) and the log
path is in `ApplyFailed`. Plan again to repair (`plan_update(vm_id)` finishes whatever the
interrupted run did not) or delete. Resources tagged for the VM but missing from state are listed
by `find_orphans` and removed only by an explicit `terminate_orphans`.

### Running it

Needs Terraform >= 1.9 on `PATH` (the AWS provider 6.71.0 is downloaded by `terraform init`; set
`TF_PLUGIN_CACHE_DIR` to reuse it) and AWS credentials from the usual environment/profile. They
need EC2 and `ssm:GetParameter` permissions; this package does not create or change any.

### Tests

`pip install -r requirements.txt` then `pytest`. The lifecycle tests run the **real Terraform
binary** against a local moto server (`AWS_ENDPOINT_URL`), so no AWS account or credentials are
used. This shows the module, plan checks and state handling work; it does not show that real AWS
accepts them. **Nothing here has been run against real AWS, and the Ubuntu and Windows image
mappings have not been launched.** moto is only a stand-in. Two test-fixture adjustments exist because of it (`tests/conftest.py`):
it will not create the AWS-reserved `/aws/service/...` SSM names through its API, and it reports
every image's root volume as 15 GiB. They affect no product code. What only real AWS can confirm:
the public SSM image parameters and root sizes, that `aws_ec2_instance_state` stop/start and
in-place root-volume growth work (and how long they take) on a real instance, the IAM
permissions needed, how Windows behaves, and that a growing disk is usable inside the OS.

Set `REQUIRE_TERRAFORM_TESTS=1` to fail instead of skip when
Terraform is missing.
