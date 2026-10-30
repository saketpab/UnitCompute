-- Execution binding and resource identities recorded with each plan.
ALTER TABLE plans ADD COLUMN execution_hash TEXT;
ALTER TABLE plans ADD COLUMN prior_resource_ids_json TEXT;

-- Durable identities used to verify deletion independently of tags, and connection
-- readiness kept separate from infrastructure success.
ALTER TABLE deployments ADD COLUMN root_volume_id TEXT;
ALTER TABLE deployments ADD COLUMN ec2_status TEXT;
ALTER TABLE deployments ADD COLUMN connection_ready INTEGER NOT NULL DEFAULT 0;
ALTER TABLE deployments ADD COLUMN readiness_checked_at TEXT;

-- Worker self-check (Terraform version, AWS role identities) reported to readiness.
ALTER TABLE worker_heartbeats ADD COLUMN healthy INTEGER NOT NULL DEFAULT 0;
ALTER TABLE worker_heartbeats ADD COLUMN checks_json TEXT NOT NULL DEFAULT '{}';

-- Every assistant model invocation is reserved before the provider is called, and stays
-- counted whether it succeeds, fails, times out or is cancelled.
CREATE TABLE agent_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id TEXT NOT NULL,
    session_id TEXT NOT NULL REFERENCES chat_sessions (id),
    status TEXT NOT NULL CHECK (status IN ('reserved', 'succeeded', 'failed')),
    idempotency_key TEXT,
    payload_hash TEXT,
    response_json TEXT,
    created_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE INDEX agent_attempts_owner ON agent_attempts (owner_id, created_at);
CREATE UNIQUE INDEX agent_attempts_idempotency
    ON agent_attempts (owner_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
