# UnitCompute HTTP API

The machine-readable contract is the OpenAPI document served at `/openapi.json`, with
interactive docs at `/docs`. This page covers the parts a client author needs that the
schema does not show.

## Authentication

Every route needs `Authorization: Bearer <token>`.

- **Production:** an OIDC/JWT access token from the configured issuer. It must be signed
  with an allowed asymmetric algorithm, have the configured `aud` and `iss`, carry `exp`,
  `iat` and `sub`, and list the configured team group in the groups claim. The token `sub`
  is the owner of everything the caller creates.
- **Development only:** `dev:<lowercase-name>`, for example `Bearer dev:alice`.

Bearer tokens are used instead of cookies, so cross-site request forgery does not apply.
CORS is off unless `UNITCOMPUTE_CORS_ORIGINS` lists explicit origins, and credentials are
never allowed cross-origin.

## Routes

| Route | Purpose | Success |
|---|---|---|
| `POST /agent/messages` | Chat with the assistant; returns a reply, an optional server-validated `proposal`, and `clarifications` | 200 |
| `POST /deployments` | `{name, disk_gib}`: reserve your single VM slot and queue a plan preview | 202 `{deployment_id, plan_id, job_id, status}` |
| `GET /deployments` | Your deployments (up to 50, newest first) | 200 |
| `GET /deployments/{id}` | Status, current plan preview (changes, warnings, cost, hash, expiry), latest job, resources and SSM access instructions | 200 |
| `POST /deployments/{id}/plan` | Refresh the create/repair preview; supersedes any earlier plan and its approvability | 202 |
| `POST /deployments/{id}/deletion-plan` | Preview deletion, including the irreversible data-loss warning | 202 |
| `POST /deployments/{id}/approve` | `{plan_id, plan_hash}` of the plan you reviewed; queues exactly that saved plan | 202 |
| `GET /jobs/{id}` | Job status, timestamps, safe error or result | 200 |

### Deployment statuses

`planning` → `awaiting_approval` → `applying` → `active` → `deletion_planning` →
`awaiting_deletion_approval` → `deleting` → `deleted`.

Other statuses:

- `plan_failed`: the preview failed or policy rejected it; nothing was changed. Request a new
  plan or a deletion plan.
- `recovery_required`: an apply was interrupted, failed, or could not be verified, so AWS
  may hold partially created or deleted, possibly billable, resources. Request a new plan
  (to repair) or a deletion plan (to clean up). Each still needs explicit approval. If AWS
  holds tagged resources that Terraform does not track, the preview is rejected and an
  operator must reconcile them.

Your VM slot stays reserved until a deletion is verified, including while a deployment is in
`plan_failed` or `recovery_required`.

### Plans and approval

A plan preview is a saved Terraform plan. Its `plan_hash` is the SHA-256 of the saved plan
file. Approval must send the exact `plan_id` and `plan_hash` you were shown, within 15
minutes of the preview being created. The server rejects approval if the plan:

- belongs to another deployment or user (`409 plan_not_current`; other users' deployments
  return `404`)
- was superseded by a newer preview (`409 plan_not_current`)
- was already approved or applied (`409 plan_not_approvable`)
- has expired (`409 plan_expired`)
- has a different hash (`409 plan_hash_mismatch`)
- was produced by a different template, Terraform or provider version (`409 plan_stale`)
- is the wrong plan type for the deployment's state (`409 invalid_state`)

The worker repeats these checks, and re-hashes the plan file, immediately before running
`terraform apply tfplan`. Nothing is ever re-planned and applied silently. A chat message
saying "yes" is not an approval.

## Errors

All errors share one shape:

```json
{"error": {"code": "plan_expired", "message": "...", "request_id": "…", "details": {}}}
```

| Status | Meaning |
|---|---|
| 401 | Missing, invalid or expired token (`WWW-Authenticate: Bearer`) |
| 403 | Valid token, but not a member of the team group |
| 404 | Not found **or not yours**; the two cases are indistinguishable by design |
| 409 | Conflict: `quota_exceeded`, `job_in_progress`, `invalid_state`, `idempotency_key_reused`, plan errors above, `session_turn_limit` |
| 413 | Body larger than `UNITCOMPUTE_MAX_REQUEST_BYTES` (default 16 KiB) |
| 422 | Invalid input, including unknown fields. Input values are not echoed back. |
| 429 | `rate_limited`: assistant daily message cap per user (`UNITCOMPUTE_AGENT_MAX_MESSAGES_PER_DAY`) |
| 503 | `provisioning_disabled`, `agent_unavailable`, `agent_timeout`, `database_busy` (retry) |

Every response carries `X-Request-ID`. Quote it when reporting a problem.

## Idempotency

Mutating routes accept an optional `Idempotency-Key` header: 8–128 characters from
`A-Z a-z 0-9 . _ : -`. Keys are scoped to the caller and route.

- The same key with the same body returns the original status and body without repeating
  the action.
- The same key with a different body returns `409 idempotency_key_reused`.

Idempotency makes retries of *requests* safe. It does not make AWS execution exactly-once.

## Costs

Previews include an estimate from a versioned price snapshot (`price_snapshot.version`,
`recorded_on` and `sources`). It is not a live quote. The baseline for a 730-hour month is
EC2 t3.micro $7.59 + public IPv4 $3.65 + 8 GiB gp3 $0.64 = **$11.88**, and disk cost scales
with size. Taxes, data transfer, snapshots and control-plane usage are excluded. No Free
Tier eligibility is assumed. AWS budget alerts notify you but do not cap spending.

## Client walkthrough

[`examples/offline_client.py`](../examples/offline_client.py) drives the whole flow with
`httpx` against a local API that uses the simulated provisioner:

1. `POST /agent/messages` asking for a VM (only if an agent model is configured).
2. `POST /deployments {"name": "demo", "disk_gib": 8}` with an `Idempotency-Key`.
3. Poll `GET /jobs/{job_id}` until it succeeds, then read the preview from
   `GET /deployments/{id}`.
4. Show the resource changes, warnings and cost to the user. On their explicit approval,
   `POST /deployments/{id}/approve {"plan_id", "plan_hash"}`.
5. Poll the job, then `GET /deployments/{id}` until it is `active`, and show the SSM
   instructions.
6. `POST /deployments/{id}/deletion-plan`, poll, and show the data-loss warning.
7. Approve the deletion plan, poll, and confirm the status is `deleted`.
