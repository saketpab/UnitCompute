CREATE TABLE deployments (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    name TEXT NOT NULL,
    disk_gib INTEGER NOT NULL CHECK (disk_gib BETWEEN 8 AND 30),
    region TEXT NOT NULL,
    instance_type TEXT NOT NULL,
    provisioner TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'planning', 'awaiting_approval', 'plan_failed', 'applying', 'active',
        'deletion_planning', 'awaiting_deletion_approval', 'deleting', 'deleted',
        'recovery_required'
    )),
    status_reason TEXT,
    current_plan_id TEXT,
    apply_attempted INTEGER NOT NULL DEFAULT 0,
    ami_id TEXT,
    instance_id TEXT,
    security_group_id TEXT,
    ssm_ping_status TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Quota: at most one live (reserved or provisioned) deployment per owner.
CREATE UNIQUE INDEX deployments_one_live_per_owner
    ON deployments (owner_id) WHERE status <> 'deleted';
CREATE INDEX deployments_owner ON deployments (owner_id, created_at);

CREATE TABLE plans (
    id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL REFERENCES deployments (id),
    owner_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('create', 'destroy')),
    status TEXT NOT NULL CHECK (status IN (
        'pending', 'ready', 'rejected', 'failed', 'superseded', 'expired',
        'approved', 'applied', 'apply_failed'
    )),
    provisioner TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    region TEXT NOT NULL,
    state_key TEXT NOT NULL,
    template_version TEXT NOT NULL,
    template_hash TEXT,
    terraform_version TEXT,
    provider_versions_json TEXT,
    account_id TEXT,
    ami_id TEXT,
    plan_path TEXT,
    plan_hash TEXT,
    preview_json TEXT,
    cost_json TEXT,
    created_at TEXT NOT NULL,
    ready_at TEXT,
    expires_at TEXT,
    approved_by TEXT,
    approved_at TEXT,
    error_code TEXT,
    error_message TEXT
);
CREATE INDEX plans_deployment ON plans (deployment_id, created_at);

CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL REFERENCES deployments (id),
    plan_id TEXT NOT NULL REFERENCES plans (id),
    kind TEXT NOT NULL CHECK (kind IN ('plan', 'apply')),
    status TEXT NOT NULL CHECK (status IN (
        'queued', 'running', 'succeeded', 'failed', 'recovery_required'
    )),
    idempotency_scope TEXT,
    idempotency_key TEXT,
    payload_hash TEXT NOT NULL,
    worker_id TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    heartbeat_at TEXT,
    finished_at TEXT,
    error_code TEXT,
    error_message TEXT,
    result_json TEXT
);
-- One queued/running job per deployment: serialises plan/apply for a deployment.
CREATE UNIQUE INDEX jobs_one_active_per_deployment
    ON jobs (deployment_id) WHERE status IN ('queued', 'running');
CREATE INDEX jobs_queue ON jobs (status, created_at);

CREATE TABLE idempotency_records (
    owner_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (owner_id, scope, idempotency_key)
);

CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    deployment_id TEXT,
    plan_id TEXT,
    job_id TEXT,
    request_id TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_events_deployment ON audit_events (deployment_id, id);

CREATE TABLE chat_sessions (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    turns INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES chat_sessions (id),
    role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX chat_messages_session ON chat_messages (session_id, id);

CREATE TABLE worker_heartbeats (
    worker_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL
);
