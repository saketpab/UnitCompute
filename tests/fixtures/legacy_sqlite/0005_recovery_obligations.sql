-- An apply that failed, was interrupted or could not be verified may have changed AWS. It
-- leaves a durable obligation that is independent of Terraform state, tags or the known-ID
-- set. Evidence: 'captured' (what that apply stored was read and recorded), 'not_needed'
-- (the plan could not create resources), or 'uncaptured' (it could have, and nothing valid
-- was read). Only captured/not_needed obligations can ever be discharged, and only by a later
-- verified apply; 'uncaptured' blocks every plan and verified deletion for the deployment.
CREATE TABLE recovery_obligations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    deployment_id TEXT NOT NULL REFERENCES deployments (id),
    job_id TEXT,
    plan_id TEXT,
    reason TEXT NOT NULL,
    evidence TEXT NOT NULL CHECK (evidence IN ('captured', 'not_needed', 'uncaptured')),
    created_at TEXT NOT NULL,
    discharged_at TEXT,
    discharged_by_job_id TEXT
);
CREATE INDEX recovery_obligations_open ON recovery_obligations (deployment_id, discharged_at);
CREATE TRIGGER recovery_obligations_no_delete BEFORE DELETE ON recovery_obligations BEGIN SELECT RAISE(ABORT, 'recovery obligations cannot be deleted'); END;
CREATE TRIGGER recovery_obligations_forward_only BEFORE UPDATE ON recovery_obligations WHEN NOT (NEW.id = OLD.id AND NEW.deployment_id = OLD.deployment_id AND NEW.job_id IS OLD.job_id AND NEW.plan_id IS OLD.plan_id AND NEW.reason = OLD.reason AND NEW.created_at = OLD.created_at AND OLD.discharged_at IS NULL AND ((OLD.evidence = 'uncaptured' AND NEW.evidence = 'captured' AND NEW.discharged_at IS NULL) OR (OLD.evidence IN ('captured', 'not_needed') AND NEW.evidence = OLD.evidence AND NEW.discharged_at IS NOT NULL))) BEGIN SELECT RAISE(ABORT, 'recovery obligations only move forward'); END;

-- Backfill: every earlier failed apply. Unresolved ones (no later successful apply) start
-- 'uncaptured' so the worker must capture that apply's stored state before anything else;
-- resolved ones are recorded as discharged so their work directories can be pruned.
INSERT INTO recovery_obligations (deployment_id, job_id, plan_id, reason, evidence, created_at) SELECT p.deployment_id, j.id, p.id, 'legacy_unresolved_apply', 'uncaptured', p.created_at FROM plans p JOIN jobs j ON j.plan_id = p.id AND j.kind = 'apply' WHERE p.status = 'apply_failed' AND NOT EXISTS (SELECT 1 FROM jobs later WHERE later.deployment_id = p.deployment_id AND later.kind = 'apply' AND later.status = 'succeeded' AND later.rowid > j.rowid);
INSERT INTO recovery_obligations (deployment_id, job_id, plan_id, reason, evidence, created_at, discharged_at) SELECT p.deployment_id, j.id, p.id, 'legacy_resolved_apply', 'not_needed', p.created_at, p.created_at FROM plans p JOIN jobs j ON j.plan_id = p.id AND j.kind = 'apply' WHERE p.status = 'apply_failed' AND EXISTS (SELECT 1 FROM jobs later WHERE later.deployment_id = p.deployment_id AND later.kind = 'apply' AND later.status = 'succeeded' AND later.rowid > j.rowid);
