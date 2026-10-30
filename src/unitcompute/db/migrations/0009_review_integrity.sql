-- Validate the cyclic current-plan edge at commit, after both records exist.
ALTER TABLE deployments ADD CONSTRAINT deployments_owned_current_plan
 FOREIGN KEY (current_plan_id,id,owner_id) REFERENCES plans (id,deployment_id,owner_id)
 DEFERRABLE INITIALLY DEFERRED;

CREATE OR REPLACE FUNCTION sync_compute_resource() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE approved plans%ROWTYPE;
BEGIN
 SELECT * INTO approved FROM plans WHERE deployment_id=NEW.id AND owner_id=NEW.owner_id AND approved_at IS NOT NULL
 -- A draft must retain the actual approval, including when timestamps tie.
 ORDER BY CASE WHEN id=NEW.current_plan_id THEN 0
 WHEN id=(SELECT r.approved_config->>'plan_id' FROM resources r WHERE r.id=NEW.uuid) THEN 1
 ELSE 2 END,approved_at DESC,created_at DESC,id DESC LIMIT 1;
 INSERT INTO resources (id,user_id,owner_id,chat_id,deployment_id,name,provider,account_scope,region,native_type,provider_resource_id,execution_mechanism,os,cpu_count,memory_gb,storage_gb,status,provider_config,approved_config,approved_at,created_at,updated_at)
 SELECT NEW.uuid,u.id,NEW.owner_id,c.uuid,NEW.id,NEW.name,'aws',
 CASE WHEN NEW.provisioner='simulated' THEN 'simulation' ELSE COALESCE(approved.account_id,(SELECT r.account_scope FROM resources r WHERE r.id=NEW.uuid)) END,
 NEW.region,'ec2:instance',NEW.instance_id,NEW.provisioner,'linux',2,1,NEW.disk_gib,NEW.status,
 jsonb_build_object('schema_version',1,'kind','compute','settings',jsonb_build_object('name',NEW.name,'disk_gib',NEW.disk_gib,'instance_type',NEW.instance_type,'region',NEW.region)),
 CASE WHEN approved.id IS NOT NULL THEN approved.requested_config || jsonb_build_object('config_hash',approved.config_hash,'plan_id',approved.id,'plan_hash',approved.plan_hash) END,
 approved.approved_at,NEW.created_at,NEW.updated_at
 FROM users u LEFT JOIN chat_sessions c ON c.id=NEW.chat_id AND c.owner_id=NEW.owner_id WHERE u.owner_id=NEW.owner_id
 ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,chat_id=EXCLUDED.chat_id,
 account_scope=COALESCE(EXCLUDED.account_scope,resources.account_scope), provider_resource_id=EXCLUDED.provider_resource_id,
 storage_gb=EXCLUDED.storage_gb,status=EXCLUDED.status,provider_config=EXCLUDED.provider_config,
 approved_config=COALESCE(EXCLUDED.approved_config,resources.approved_config),
 approved_at=COALESCE(EXCLUDED.approved_at,resources.approved_at),updated_at=EXCLUDED.updated_at;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION valid_provider_settings(config JSONB) RETURNS BOOLEAN LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE entry RECORD;
BEGIN
 IF jsonb_typeof(config) IS DISTINCT FROM 'object'
 OR NOT config ?& ARRAY['schema_version','kind','settings']
 OR jsonb_typeof(config->'settings') IS DISTINCT FROM 'object'
 OR jsonb_typeof(config->'kind') IS DISTINCT FROM 'string'
 OR config->>'kind' NOT IN ('compute','network','storage','identity') THEN RETURN FALSE; END IF;
 IF config->'schema_version' IS DISTINCT FROM '1'::jsonb THEN RETURN FALSE; END IF;
 FOR entry IN SELECT * FROM jsonb_each(config->'settings') LOOP
  IF entry.key='disk_gib' THEN
   IF jsonb_typeof(entry.value)<>'number' THEN RETURN FALSE; END IF;
   IF (entry.value::text)::numeric NOT BETWEEN 1 AND 16384 OR trunc((entry.value::text)::numeric)<>(entry.value::text)::numeric THEN RETURN FALSE; END IF;
  ELSE
   IF jsonb_typeof(entry.value)<>'string' OR length(entry.value#>>'{}') NOT BETWEEN 1 AND 200 THEN RETURN FALSE; END IF;
  END IF;
 END LOOP;
 RETURN TRUE;
END $$;

-- Revalidate existing provider rows instead of silently normalizing unknown data.
ALTER TABLE resources DROP CONSTRAINT resources_typed_config;
ALTER TABLE resources ADD CONSTRAINT resources_typed_config CHECK (valid_provider_settings(provider_config) IS TRUE);
UPDATE deployments SET updated_at=updated_at;
