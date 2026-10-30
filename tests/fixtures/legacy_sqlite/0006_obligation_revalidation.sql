-- Round 6. Evidence for an apply is accepted only when it is bound to that apply's saved plan
-- (see provisioning/state_evidence.py). Two corrections to schema 5:
--
-- 1. An open 'uncaptured' obligation may become 'not_needed' only when the plan's recorded
--    changes show it creates nothing (deletions only, or no changes). Unreadable changes
--    count as creating. The predicate matches worker.plan_may_create.
-- 2. Every earlier obligation of a plan that could create resources and was not
--    'uncaptured' was resolved by rules that are no longer sufficient: migration 0005
--    discharged failed applies merely because a later apply succeeded, and schema 5 accepted
--    empty or unbound state. Each gets a new 'uncaptured' obligation. The worker can still
--    capture it from a retained, valid errored.tfstate; otherwise it needs a support decision.
DROP TRIGGER recovery_obligations_forward_only;
CREATE TRIGGER recovery_obligations_forward_only BEFORE UPDATE ON recovery_obligations WHEN NOT (NEW.id = OLD.id AND NEW.deployment_id = OLD.deployment_id AND NEW.job_id IS OLD.job_id AND NEW.plan_id IS OLD.plan_id AND NEW.reason = OLD.reason AND NEW.created_at = OLD.created_at AND OLD.discharged_at IS NULL AND ((OLD.evidence = 'uncaptured' AND NEW.evidence = 'captured' AND NEW.discharged_at IS NULL) OR (OLD.evidence = 'uncaptured' AND NEW.evidence = 'not_needed' AND NEW.discharged_at IS NULL AND EXISTS (SELECT 1 FROM plans p WHERE p.id = NEW.plan_id AND json_valid(p.preview_json) AND json_type(p.preview_json, '$.changes') = 'array' AND NOT EXISTS (SELECT 1 FROM json_each(p.preview_json, '$.changes') c WHERE c.type <> 'object' OR json_type(c.value, '$.action') IS NOT 'text' OR json_extract(c.value, '$.action') <> 'delete'))) OR (OLD.evidence IN ('captured', 'not_needed') AND NEW.evidence = OLD.evidence AND NEW.discharged_at IS NOT NULL))) BEGIN SELECT RAISE(ABORT, 'recovery obligations only move forward'); END;

-- Backfilled failed deletions (and other plans that create nothing) need no capture.
UPDATE recovery_obligations SET evidence = 'not_needed' WHERE discharged_at IS NULL AND evidence = 'uncaptured' AND job_id IS NOT NULL AND EXISTS (SELECT 1 FROM plans p WHERE p.id = recovery_obligations.plan_id AND json_valid(p.preview_json) AND json_type(p.preview_json, '$.changes') = 'array' AND NOT EXISTS (SELECT 1 FROM json_each(p.preview_json, '$.changes') c WHERE c.type <> 'object' OR json_type(c.value, '$.action') IS NOT 'text' OR json_extract(c.value, '$.action') <> 'delete'));

INSERT INTO recovery_obligations (deployment_id, job_id, plan_id, reason, evidence, created_at) SELECT o.deployment_id, o.job_id, o.plan_id, 'evidence_revalidation', 'uncaptured', MIN(o.created_at) FROM recovery_obligations o WHERE o.job_id IS NOT NULL AND o.evidence <> 'uncaptured' AND NOT EXISTS (SELECT 1 FROM plans p WHERE p.id = o.plan_id AND json_valid(p.preview_json) AND json_type(p.preview_json, '$.changes') = 'array' AND NOT EXISTS (SELECT 1 FROM json_each(p.preview_json, '$.changes') c WHERE c.type <> 'object' OR json_type(c.value, '$.action') IS NOT 'text' OR json_extract(c.value, '$.action') <> 'delete')) GROUP BY o.deployment_id, o.job_id, o.plan_id;
