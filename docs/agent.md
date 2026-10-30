# The UnitCompute assistant

`POST /agent/messages` runs a LangChain agent (`create_agent`) inside the API process. It
helps a user choose a VM name and disk size, explains previews and costs, and reports
status. It cannot change anything.

## Tools

Each tool is bound to the authenticated caller when the request starts. The model never
supplies an owner or user ID.

| Tool | Effect |
|---|---|
| `check_deployment_config(name, disk_gib)` | Validates input with the same schema as `POST /deployments`. On success the **server** builds the `proposal` returned to the client. |
| `estimate_monthly_cost(disk_gib)` | Price-snapshot estimate |
| `list_my_deployments()` | The caller's deployments and their statuses |
| `get_deployment_preview(deployment_id)` | Sanitized status and preview for one of the caller's deployments. It omits the plan hash, file paths, raw plan and state. |

There are no tools to create, approve, apply, delete, run commands, write Terraform or
change policy. If a model invents one, LangChain returns a tool error and nothing happens.
Tool arguments are validated strictly, so extra fields such as `region` or `user_data` are
rejected.

## Trust boundaries

- User messages, chat history, deployment names, tool output and model output are all
  untrusted. The `proposal` comes only from a successful server-side validation, never
  from model text. Model replies are length-capped and redacted.
- Approval requires `POST /deployments/{id}/approve` with the exact plan ID and hash. The
  model claiming "approved", or the user typing "yes", does nothing.
- Each request is admitted atomically before the provider is called: the daily per-user
  attempt count and the session's turn count are reserved in one database transaction, so
  concurrent requests cannot exceed them. Failed, timed-out and cancelled attempts stay
  counted. An `Idempotency-Key` replays a completed reply without constructing or calling
  the model, so replays work even while the provider is unavailable. A reservation left
  behind by a crashed or cancelled request expires after its lease and stays counted.
- Limits: model calls and tool calls per message, a wall-clock timeout, message length,
  history length, total turns per session, messages per user per day and output tokens are
  all configurable (`UNITCOMPUTE_AGENT_*`).
- The model never receives credentials, raw plans or state, plan hashes, or other users'
  data. Owners are identified only by their token subject, which is not sent to the model.
  LangSmith/LangChain tracing is forced off.
- The runtime model is explicit configuration (`UNITCOMPUTE_AGENT_MODEL`), so any provider
  outage or missing key returns `503 agent_unavailable`. The REST workflow does not depend
  on the assistant.

`fake:offline` (development only) and the `ScriptedChatModel` used in tests are offline
fakes. Their replies start with `[offline fake model]`, and passing tests with them does not
show how a real model behaves.
