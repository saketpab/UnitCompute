-- Validate final states as well as forward transitions. Never rewrite corrupt history.
CREATE FUNCTION recovery_obligation_valid(dep TEXT, source_job TEXT, source_plan TEXT,
 evidence TEXT, discharged_at TIMESTAMPTZ, discharge_job TEXT)
RETURNS BOOLEAN LANGUAGE SQL STABLE AS $$
 SELECT recovery_links_valid(dep,source_job,source_plan,discharge_job)
 AND (discharge_job IS NULL OR discharged_at IS NOT NULL)
 AND (evidence <> 'uncaptured' OR (discharged_at IS NULL AND discharge_job IS NULL))
 AND (source_job IS NULL OR discharge_job IS NULL OR EXISTS (
  SELECT 1 FROM jobs src JOIN jobs dst ON dst.id=discharge_job
  WHERE src.id=source_job AND dst.sequence>src.sequence));
$$;
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM recovery_obligations o WHERE NOT recovery_obligation_valid(
 o.deployment_id,o.job_id,o.plan_id,o.evidence,o.discharged_at,o.discharged_by_job_id)) THEN
  RAISE EXCEPTION 'invalid recovery obligation completion' USING ERRCODE='23514';
 END IF;
END $$;
ALTER TABLE recovery_obligations ADD CONSTRAINT recovery_uncaptured_not_discharged
 CHECK (evidence <> 'uncaptured' OR (discharged_at IS NULL AND discharged_by_job_id IS NULL));
CREATE OR REPLACE FUNCTION enforce_recovery_bindings() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='recovery_obligations' THEN
  IF NOT recovery_obligation_valid(NEW.deployment_id,NEW.job_id,NEW.plan_id,NEW.evidence,
      NEW.discharged_at,NEW.discharged_by_job_id) THEN
   RAISE EXCEPTION 'invalid recovery obligation completion' USING ERRCODE='23514';
  END IF;
 ELSE
  IF EXISTS (SELECT 1 FROM recovery_obligations o WHERE
      (o.job_id=NEW.id OR o.discharged_by_job_id=NEW.id) AND NOT
      recovery_obligation_valid(o.deployment_id,o.job_id,o.plan_id,o.evidence,
      o.discharged_at,o.discharged_by_job_id)) THEN
   RAISE EXCEPTION 'invalid recovery obligation completion' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NULL;
END $$;

CREATE FUNCTION assistant_reply_readable(reply JSONB) RETURNS BOOLEAN LANGUAGE SQL IMMUTABLE AS $$
 SELECT (jsonb_typeof(reply)='object'
 AND reply ?& ARRAY['session_id','reply','model','proposal','clarifications','tool_calls','approval_note']
 AND jsonb_typeof(reply->'session_id')='string' AND jsonb_typeof(reply->'reply')='string'
 AND jsonb_typeof(reply->'model')='string' AND jsonb_typeof(reply->'approval_note')='string'
 AND jsonb_typeof(reply->'clarifications')='array' AND jsonb_typeof(reply->'tool_calls')='array'
 AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN
 jsonb_typeof(reply->'clarifications')='array' THEN reply->'clarifications' ELSE '[]'::jsonb END) v
 WHERE jsonb_typeof(v)<>'string')
 AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN
 jsonb_typeof(reply->'tool_calls')='array' THEN reply->'tool_calls' ELSE '[]'::jsonb END) v
 WHERE jsonb_typeof(v)<>'string')) IS TRUE;
$$;
ALTER TABLE agent_attempts ADD CONSTRAINT completed_assistant_reply
 CHECK (status <> 'succeeded' OR assistant_reply_readable(response_json));
