-- Recovery evidence belongs to one deployment, its plans and its apply jobs.
ALTER TABLE plans ADD CONSTRAINT plans_id_deployment UNIQUE (id,deployment_id);
ALTER TABLE jobs ADD CONSTRAINT jobs_id_deployment UNIQUE (id,deployment_id);
ALTER TABLE jobs ADD CONSTRAINT jobs_id_deployment_plan UNIQUE (id,deployment_id,plan_id);
ALTER TABLE recovery_obligations ADD CONSTRAINT recovery_owned_plan
 FOREIGN KEY (plan_id,deployment_id) REFERENCES plans (id,deployment_id);
ALTER TABLE recovery_obligations ADD CONSTRAINT recovery_owned_job
 FOREIGN KEY (job_id,deployment_id) REFERENCES jobs (id,deployment_id);
ALTER TABLE recovery_obligations ADD CONSTRAINT recovery_job_plan
 FOREIGN KEY (job_id,deployment_id,plan_id) REFERENCES jobs (id,deployment_id,plan_id);
ALTER TABLE recovery_obligations ADD CONSTRAINT recovery_owned_discharge
 FOREIGN KEY (discharged_by_job_id,deployment_id) REFERENCES jobs (id,deployment_id);
ALTER TABLE recovery_obligations ADD CONSTRAINT recovery_discharge_time
 CHECK (discharged_by_job_id IS NULL OR discharged_at IS NOT NULL);

CREATE INDEX recovery_source_job ON recovery_obligations (job_id);
CREATE INDEX recovery_source_plan ON recovery_obligations (plan_id);
CREATE INDEX recovery_discharge_job ON recovery_obligations (discharged_by_job_id);

CREATE FUNCTION recovery_links_valid(dep TEXT, source_job TEXT, source_plan TEXT, discharge_job TEXT)
RETURNS BOOLEAN LANGUAGE SQL STABLE AS $$
 SELECT EXISTS (SELECT 1 FROM deployments d WHERE d.id=dep
 AND (source_plan IS NULL OR EXISTS (SELECT 1 FROM plans p WHERE p.id=source_plan
      AND p.deployment_id=d.id AND p.owner_id=d.owner_id))
 AND (source_job IS NULL OR EXISTS (SELECT 1 FROM jobs j WHERE j.id=source_job
      AND j.deployment_id=d.id AND j.owner_id=d.owner_id AND j.kind='apply'
      AND (source_plan IS NULL OR j.plan_id=source_plan)))
 AND (discharge_job IS NULL OR EXISTS (SELECT 1 FROM jobs j WHERE j.id=discharge_job
      AND j.deployment_id=d.id AND j.owner_id=d.owner_id AND j.kind='apply' AND j.status='succeeded')));
$$;
-- Reject existing corrupt history atomically, preserving every row for offline investigation.
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM recovery_obligations o WHERE NOT
 recovery_links_valid(o.deployment_id,o.job_id,o.plan_id,o.discharged_by_job_id)) THEN
  RAISE EXCEPTION 'invalid recovery obligation apply binding' USING ERRCODE='23514';
 END IF;
END $$;

CREATE FUNCTION enforce_recovery_bindings() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='recovery_obligations' THEN
  IF NOT recovery_links_valid(NEW.deployment_id,NEW.job_id,NEW.plan_id,NEW.discharged_by_job_id) THEN
   RAISE EXCEPTION 'invalid recovery obligation apply binding' USING ERRCODE='23514';
  END IF;
 ELSE
  IF EXISTS (SELECT 1 FROM recovery_obligations o WHERE
      (o.job_id=NEW.id OR o.discharged_by_job_id=NEW.id) AND NOT
      recovery_links_valid(o.deployment_id,o.job_id,o.plan_id,o.discharged_by_job_id)) THEN
   RAISE EXCEPTION 'invalid recovery obligation apply binding' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NULL;
END $$;
-- Successful applies update their job and discharge obligations in the same transaction.
CREATE CONSTRAINT TRIGGER recovery_apply_bindings AFTER INSERT OR UPDATE ON recovery_obligations
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enforce_recovery_bindings();
CREATE CONSTRAINT TRIGGER jobs_recovery_bindings AFTER UPDATE ON jobs
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enforce_recovery_bindings();
