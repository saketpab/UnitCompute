-- Lifecycle operations beyond create/delete (round 9). Additive only: no CHECK constraint is
-- widened, so plans keep kind 'create' (converge the deployment on its requested spec: create,
-- repair or edit in place) or 'destroy', and deployments keep their statuses.
--
-- deployments.power_state:   the power state UnitCompute last verified it applied
--                            ('running' or 'stopped'); NULL means 'running'. Terraform plans
--                            are computed from it, so a plan that does not mention power
--                            never starts or stops anything.
-- deployments.instance_state: the EC2 state name last observed by the worker (informational).
-- plans.request_json:        the validated edit request this plan was made for
--                            ({"name", "disk_gib", "power_state"}, any subset); NULL for
--                            create, repair and deletion plans.
ALTER TABLE deployments ADD COLUMN power_state TEXT;
ALTER TABLE deployments ADD COLUMN instance_state TEXT;
ALTER TABLE plans ADD COLUMN request_json TEXT;
