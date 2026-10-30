# UnitCompute

Easy-to-use service to simplify AWS usage.

UnitCompute gives each team member one small Linux VM on AWS through an approval-gated
workflow:

configure → preview resources and cost → explicitly approve → launch → inspect → (optionally
rename, enlarge the disk, stop or start, each previewed and approved the same way) → explicitly
delete.

It is one FastAPI service, with a LangChain assistant inside it, plus a single worker
process that runs a pinned Terraform CLI against a reviewed template. Both processes share
a SQLite database on persistent local disk.

| Fixed by the server | Chosen by the user |
|---|---|
| Region `us-east-1` by default (configurable and validated), official Amazon Linux 2023 x86_64 AMI (frozen at plan time), `t3.micro`, `cpu_credits=standard`, IMDSv2, approved public subnet and SSM instance profile, dedicated security group with no inbound rules | `name` (3–32 lowercase letters, digits, hyphens) and `disk_gib` (8–30 GiB encrypted gp3 root disk) |

Access is through AWS Systems Manager Session Manager only. There is no SSH, and a
UnitCompute login alone does not grant shell access.

## Status

This is a foundation, not a deployed service. Everything below was verified offline:
unit, API and agent tests; Terraform `fmt`, `validate` and `test` with a mocked provider;
real offline `terraform plan` output checked against the plan policy; and moto-emulated
boto3 calls. No real AWS sandbox lifecycle has been run yet. Passing offline tests does
not show that AWS will accept these resources or IAM policies.

## Layout

```
src/unitcompute/
  api/            FastAPI app, routes, middleware (request IDs, size limit, CORS, errors)
  auth.py         JWT/JWKS verification (PyJWT); development-only dev tokens
  services/       Authorization-aware deployment operations shared by REST and the agent
  agent/          LangChain assistant: read/validate tools only, offline scripted fake model
  provisioning/   Terraform runner and provisioner, plan policy, AWS reads, simulator
    templates/ec2_vm_v2/   Reviewed Terraform template, provider lock file, module tests
  db/             SQLite access and versioned SQL migrations
  worker.py       Single job worker (plan/apply), recovery and housekeeping
  admin.py        Operator CLI: migrate, check-config, recovery-report, orphan-report
docs/             API guide, operations and bootstrap prerequisites, example IAM policies
examples/         Offline HTTP client walkthrough
tests/            pytest suite (API, auth, policy, worker recovery, agent, Terraform)
```

## Local development (offline, no AWS)

Requires [uv](https://docs.astral.sh/uv/) and, for the Terraform checks, Terraform
**1.17.1** from <https://releases.hashicorp.com/terraform/1.17.1/> (check the SHA-256 against
the published `SHA256SUMS`).

```sh
uv sync --locked --all-extras        # Python 3.13 venv from uv.lock
export UNITCOMPUTE_PROVISIONER=simulated  # labelled simulator; never touches AWS
export UNITCOMPUTE_AGENT_MODEL=fake:offline   # optional; labelled offline fake model
uv run unitcompute-admin migrate
uv run unitcompute-worker &          # one worker per data directory (file-locked)
uv run unitcompute-api               # http://127.0.0.1:8000/docs
uv run python examples/offline_client.py
```

Development mode uses `Authorization: Bearer dev:<name>` tokens. They only work when
`UNITCOMPUTE_ENVIRONMENT=development` and `UNITCOMPUTE_AUTH_MODE=dev`, and the API refuses to
bind dev auth to a non-loopback address. Dev auth can never be combined with
`UNITCOMPUTE_PROVISIONER=terraform`: real provisioning always requires verified JWT team
authentication. With no configuration, provisioning is
**disabled**: `POST /deployments` returns `503 provisioning_disabled`.

Settings are `UNITCOMPUTE_*` environment variables (see `src/unitcompute/config.py`).
Unknown `UNITCOMPUTE_*` variables are rejected so that a misspelt security setting cannot
silently fall back to a default.

## Checks

```sh
uv run ruff format --check . && uv run ruff check .
uv run mypy
uv run pytest                        # includes Terraform tests when terraform is on PATH
uv export --locked --all-extras --no-emit-project --format requirements-txt > /tmp/req.txt
uv run pip-audit --strict --disable-pip --require-hashes -r /tmp/req.txt   # known CVEs
gitleaks git --redact                # secret scan
```

CI runs the same checks (`.github/workflows/ci.yml`). It does not build images and does
not use AWS credentials.

## Further reading

- [docs/api.md](docs/api.md): HTTP contract, errors, idempotency and a client walkthrough
- [docs/operations.md](docs/operations.md): production configuration, AWS bootstrap
  prerequisites, IAM, recovery, retention
- [docs/agent.md](docs/agent.md): what the assistant can and cannot do
