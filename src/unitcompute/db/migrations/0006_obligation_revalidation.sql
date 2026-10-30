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
DROP TRIGGER recovery_obligations_forward_only ON recovery_obligations;

CREATE OR REPLACE FUNCTION plan_proves_no_create(plan_id TEXT) RETURNS BOOLEAN LANGUAGE SQL STABLE AS $$
 SELECT EXISTS (SELECT 1 FROM plans p WHERE p.id=plan_id AND jsonb_typeof(p.preview_json->'changes')='array'
 AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(p.preview_json->'changes')='array' THEN p.preview_json->'changes' ELSE '[]'::jsonb END) c
 WHERE jsonb_typeof(c)<>'object' OR jsonb_typeof(c->'action') IS DISTINCT FROM 'string' OR c->>'action'<>'delete'));
$$;
CREATE OR REPLACE FUNCTION enforce_obligation_forward() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'recovery obligations cannot be deleted' USING ERRCODE='23514'; END IF;
 IF (to_jsonb(NEW) - ARRAY['evidence','discharged_at','discharged_by_job_id']) IS DISTINCT FROM
    (to_jsonb(OLD) - ARRAY['evidence','discharged_at','discharged_by_job_id']) OR OLD.discharged_at IS NOT NULL OR NOT (
   (OLD.evidence='uncaptured' AND (NEW.evidence='captured'  OR (NEW.evidence = 'not_needed' AND plan_proves_no_create(NEW.plan_id))) AND NEW.discharged_at IS NULL AND NEW.discharged_by_job_id IS NOT DISTINCT FROM OLD.discharged_by_job_id)
   OR (OLD.evidence IN ('captured','not_needed') AND NEW.evidence=OLD.evidence AND NEW.discharged_at IS NOT NULL)
 ) THEN RAISE EXCEPTION 'recovery obligations only move forward' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER recovery_obligations_forward_only BEFORE UPDATE OR DELETE ON recovery_obligations FOR EACH ROW EXECUTE FUNCTION enforce_obligation_forward();
-- Backfilled failed deletions (and other plans that create nothing) need no capture.
UPDATE recovery_obligations SET evidence = 'not_needed' WHERE discharged_at IS NULL AND evidence = 'uncaptured' AND job_id IS NOT NULL AND EXISTS (SELECT 1 FROM plans p WHERE p.id = recovery_obligations.plan_id
 AND jsonb_typeof(p.preview_json->'changes') = 'array'
 AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(p.preview_json->'changes')='array' THEN p.preview_json->'changes' ELSE '[]'::jsonb END) c
 WHERE jsonb_typeof(c) <> 'object' OR jsonb_typeof(c->'action') IS DISTINCT FROM 'string' OR c->>'action' <> 'delete'));

INSERT INTO recovery_obligations (deployment_id, job_id, plan_id, reason, evidence, created_at) SELECT o.deployment_id, o.job_id, o.plan_id, 'evidence_revalidation', 'uncaptured', MIN(o.created_at) FROM recovery_obligations o WHERE o.job_id IS NOT NULL AND o.evidence <> 'uncaptured' AND NOT EXISTS (SELECT 1 FROM plans p WHERE p.id = o.plan_id
 AND jsonb_typeof(p.preview_json->'changes') = 'array'
 AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(p.preview_json->'changes')='array' THEN p.preview_json->'changes' ELSE '[]'::jsonb END) c
 WHERE jsonb_typeof(c) <> 'object' OR jsonb_typeof(c->'action') IS DISTINCT FROM 'string' OR c->>'action' <> 'delete')) GROUP BY o.deployment_id, o.job_id, o.plan_id;
