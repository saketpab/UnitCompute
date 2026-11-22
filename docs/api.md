# UniCompute chat API

The frontend sends the user's prompt to FastAPI. FastAPI calls the existing agent in `agent/` through the graph assembled in `run_agent.py`, then returns JSON for the frontend to display.

## Run locally

From the repository root, install the dependencies in your Python environment and start the server:

```sh
python -m pip install -r requirements.txt
python -m uvicorn api:app --reload
```

Set `GOOGLE_API_KEY` in your environment or in the repository's local `.env` file to try the agent. Keep the key on the backend. Open [interactive API docs](http://127.0.0.1:8000/docs), select an endpoint, and choose **Try it out**. Use `GET /health` to confirm the server responds with `{"status":"ok"}`.

## Start a conversation

Send `POST /api/chats` with `Content-Type: application/json`:

```json
{"message":"I need an EC2 instance for a class project."}
```

A successful request returns HTTP 201. One possible response is:

```json
{
  "chat_id": "8791d364-b42e-432f-8ae1-d34e82b57f25",
  "type": "missing_detail",
  "interrupt_id": "example-question-id",
  "field": "operating_system",
  "question": "Which operating system should the VM use: Ubuntu or Windows?"
}
```

## Continue the conversation

Send `POST /api/chats/{chat_id}/messages` with `Content-Type: application/json`. Replace `{chat_id}` with the ID from the response and send the latest `interrupt_id` verbatim. The IDs below illustrate the format. A successful follow-up returns HTTP 200.

**Answer a clarification**

```json
{"action":"clarify","interrupt_id":"example-question-id","message":"Ubuntu, small, in us-east-2."}
```

The agent may ask another question or return a plan for review. An abbreviated plan response looks like this:

```json
{
  "chat_id": "8791d364-b42e-432f-8ae1-d34e82b57f25",
  "type": "approval",
  "interrupt_id": "example-plan-id",
  "question": "Do you approve this VM plan?",
  "plan": {"operating_system":"ubuntu","compute_size":"small (t3.micro)","region":"us-east-2","disk_gb":30}
}
```

**Request a revision**

```json
{"action":"change","interrupt_id":"example-plan-id","changes":"Increase the disk to 40 GB."}
```

**Approve the revised plan**

```json
{"action":"approve","interrupt_id":"example-revised-plan-id"}
```

Approval submits the approved plan for launch in the same request when a provisioning service is configured. The final response includes `"type":"approved"`, the `chat_id`, the approved `plan`, and these launch fields:

| Launch status | Resource ID | What to display |
| --- | --- | --- |
| `accepted` | UniCompute resource UUID | Show **Launching** and use the dashboard to check its state. |
| `not_configured` | `null` | Show that the plan was approved and launch is unavailable in this environment. |

## Frontend behavior

| Response type | What to display |
| --- | --- |
| `missing_detail` | Show `question` and a reply field. |
| `approval` | Show `plan` and controls to approve it or request changes. |
| `approved` | Show the approved `plan` and the result indicated by `launch_status`. |
| `message` | Show the agent's text from `message`. |

Keep the latest reply for each chat so the controls send its current `interrupt_id`. A 409 means the reply is stale, the chat is complete, or the action does not match what the agent is waiting for. A 404 means the chat was not found. A 422 means the request failed validation. A 503 means the agent is missing its Gemini configuration.

The API currently uses in-memory checkpoints and is intended for local development. Restarting the server clears chats.

## Connect a browser frontend

If the frontend calls FastAPI directly from a different origin, set `UNICOMPUTE_ALLOWED_ORIGINS` in the backend shell before starting Uvicorn:

```sh
export UNICOMPUTE_ALLOWED_ORIGINS=http://localhost:3000
python -m uvicorn api:app --reload
```

Use the frontend's exact scheme, hostname, and port, with no path or trailing slash. For multiple frontend URLs, separate the origins with commas. Restart Uvicorn after changing the setting. Leave it unset for a same-origin frontend or a frontend development proxy.

## Instance dashboard

`GET /api/instances` returns HTTP 200 with a list of instance summaries, or an empty list when the caller has no instances. Example:

```json
[
  {
    "id": "483039ee-356f-4e40-a432-dda7dc92848f",
    "name": "Class VM",
    "region": "us-east-2",
    "status": "running"
  }
]
```

Use the returned UniCompute resource ID in `POST /api/instances/{instance_id}/actions`. Send a JSON body such as `{"action":"stop"}`. Supported actions are `start`, `stop`, `reboot`, and `terminate`. HTTP 202 with an empty body means the service accepted the action. Refresh the instance list to see its current state. HTTP 404 means the instance is unavailable to the caller.

Both routes currently return HTTP 503 because there is no configured instance service. The integration point is `get_instance_service()` in `api.py`. The future implementation must supply a service scoped to the authenticated user, resolve UniCompute IDs to AWS instance IDs and regions, and check ownership before submitting any action. The chat endpoints can be used independently of this service.

## Wire up provisioning

Provide a caller-scoped `ProvisioningService` from `get_provisioning_service()` in `api.py` once authentication and database ownership are connected. Its `owns_chat()` method checks chat ownership before FastAPI accepts an approval that could launch an instance.

`submit_launch(chat_id=..., plan=..., request_id=...)` receives the agent's structured `VMPlan`. Persist the approved plan and its owner, submit that plan to the AWS service, and return the UniCompute resource ID. Use `request_id` to deduplicate the submission in storage and in the AWS call. Persist launch progress, including the AWS instance ID and status, so the dashboard can display it. The service must own recovery for launches it has accepted, since an already-consumed chat approval returns HTTP 409 if posted again.
