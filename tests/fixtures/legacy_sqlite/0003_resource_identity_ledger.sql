-- Append-only record of every resource identity ever associated with a deployment. Rows are
-- never updated or deleted, so a lost Terraform state, removed tag or failed lookup can never
-- make the application forget something that may still be billable.
CREATE TABLE deployment_resources (
    deployment_id TEXT NOT NULL REFERENCES deployments (id),
    resource_type TEXT NOT NULL CHECK (resource_type IN ('instance', 'volume', 'security_group')),
    resource_id TEXT NOT NULL,
    parent_id TEXT,
    source TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
-- The same ID may be recorded again once its parent instance becomes known.
CREATE UNIQUE INDEX deployment_resources_unique ON deployment_resources (deployment_id, resource_id, IFNULL(parent_id, ''));
CREATE TRIGGER deployment_resources_no_update BEFORE UPDATE ON deployment_resources BEGIN SELECT RAISE(ABORT, 'deployment_resources is append-only'); END;
CREATE TRIGGER deployment_resources_no_delete BEFORE DELETE ON deployment_resources BEGIN SELECT RAISE(ABORT, 'deployment_resources is append-only'); END;

-- Operator statements that a known instance's root disk is confirmed gone even though its ID
-- was never recorded (for example deployments created before identities were tracked).
CREATE TABLE identity_acknowledgements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    deployment_id TEXT NOT NULL REFERENCES deployments (id),
    instance_id TEXT NOT NULL,
    operator TEXT NOT NULL,
    reason TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE TRIGGER identity_acknowledgements_no_update BEFORE UPDATE ON identity_acknowledgements BEGIN SELECT RAISE(ABORT, 'identity_acknowledgements is append-only'); END;
CREATE TRIGGER identity_acknowledgements_no_delete BEFORE DELETE ON identity_acknowledgements BEGIN SELECT RAISE(ABORT, 'identity_acknowledgements is append-only'); END;

-- Backfill from schema 2 so upgraded deployments keep everything already known.
INSERT OR IGNORE INTO deployment_resources (deployment_id, resource_type, resource_id, parent_id, source, recorded_at) SELECT id, 'instance', instance_id, NULL, 'migration', updated_at FROM deployments WHERE instance_id IS NOT NULL;
INSERT OR IGNORE INTO deployment_resources (deployment_id, resource_type, resource_id, parent_id, source, recorded_at) SELECT id, 'security_group', security_group_id, NULL, 'migration', updated_at FROM deployments WHERE security_group_id IS NOT NULL;
INSERT OR IGNORE INTO deployment_resources (deployment_id, resource_type, resource_id, parent_id, source, recorded_at) SELECT id, 'volume', root_volume_id, instance_id, 'migration', updated_at FROM deployments WHERE root_volume_id IS NOT NULL;
INSERT OR IGNORE INTO deployment_resources (deployment_id, resource_type, resource_id, parent_id, source, recorded_at) SELECT plans.deployment_id, CASE WHEN value LIKE 'i-%' THEN 'instance' WHEN value LIKE 'vol-%' THEN 'volume' ELSE 'security_group' END, value, NULL, 'migration', plans.created_at FROM plans, json_each(plans.prior_resource_ids_json) WHERE plans.prior_resource_ids_json IS NOT NULL AND (value LIKE 'i-%' OR value LIKE 'vol-%' OR value LIKE 'sg-%');

-- Deterministic chat-attempt leases: a reservation older than its lease is no longer in flight.
ALTER TABLE agent_attempts ADD COLUMN lease_expires_at TEXT;
