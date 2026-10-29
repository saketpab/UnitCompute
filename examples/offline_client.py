"""Walk the full UnitCompute flow against a local, offline API.

Start the services first (see README "Local development"), with
UNITCOMPUTE_PROVISIONER=simulated so nothing touches AWS:

    uv run python examples/offline_client.py [--base-url http://127.0.0.1:8000]

In a real client, the approval steps are taken only after a person reviews the preview.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from typing import Any

import httpx


def poll_job(client: httpx.Client, job_id: str, timeout: float = 120) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job: dict[str, Any] = client.get(f"/jobs/{job_id}").raise_for_status().json()
        if job["status"] not in {"queued", "running"}:
            return job
        time.sleep(1)
    raise TimeoutError(f"job {job_id} did not finish")


def show_preview(deployment: dict[str, Any]) -> dict[str, Any]:
    plan: dict[str, Any] = deployment["current_plan"]
    print(f"\nPlan {plan['plan_id']} ({plan['kind']}), expires {plan['expires_at']}")
    print(f"  hash: {plan['plan_hash']}")
    for change in plan["resource_changes"]:
        print(f"  {change['action']:>6} {change['address']}: {json.dumps(change['summary'])}")
    for warning in plan["warnings"]:
        print(f"  ! {warning}")
    if plan["cost"]:
        print(
            f"  estimated ${plan['cost']['monthly_total_usd']}/month ({plan['cost']['disclaimer']})"
        )
    return plan


def approve(client: httpx.Client, deployment_id: str, plan: dict[str, Any]) -> dict[str, Any]:
    response = client.post(
        f"/deployments/{deployment_id}/approve",
        json={"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]},
        headers={"Idempotency-Key": f"approve-{plan['plan_id']}"},
    )
    body: dict[str, Any] = response.raise_for_status().json()
    return body


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--user", default="alice")
    args = parser.parse_args()
    client = httpx.Client(
        base_url=args.base_url, timeout=30, headers={"Authorization": f"Bearer dev:{args.user}"}
    )

    chat = client.post("/agent/messages", json={"message": "I need a small VM called demo"})
    if chat.status_code == 200:
        print("assistant:", chat.json()["reply"])
    else:
        print("assistant unavailable:", chat.json()["error"]["code"])

    created = client.post(
        "/deployments",
        json={"name": "demo", "disk_gib": 8},
        headers={"Idempotency-Key": f"create-{uuid.uuid4().hex}"},
    )
    if created.status_code == 409:
        print("You already have a deployment:", created.json()["error"]["details"])
        return 1
    accepted = created.raise_for_status().json()
    deployment_id = accepted["deployment_id"]
    print("requested", deployment_id)

    poll_job(client, accepted["job_id"])
    plan = show_preview(client.get(f"/deployments/{deployment_id}").json())

    job = poll_job(client, approve(client, deployment_id, plan)["job_id"])
    deployment = client.get(f"/deployments/{deployment_id}").json()
    print(f"\napply job {job['status']}; deployment {deployment['status']}")
    if deployment["access"]:
        print("access:", deployment["access"]["command"] or "(simulated: none)")
        for requirement in deployment["access"]["requirements"]:
            print("  -", requirement)

    deletion = client.post(f"/deployments/{deployment_id}/deletion-plan").raise_for_status()
    poll_job(client, deletion.json()["job_id"])
    plan = show_preview(client.get(f"/deployments/{deployment_id}").json())

    job = poll_job(client, approve(client, deployment_id, plan)["job_id"])
    final = client.get(f"/deployments/{deployment_id}").json()
    print(f"\ndelete job {job['status']}; deployment {final['status']}")
    return 0 if final["status"] == "deleted" else 1


if __name__ == "__main__":
    sys.exit(main())
