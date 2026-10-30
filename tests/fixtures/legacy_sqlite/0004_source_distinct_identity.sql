-- Evidence is distinct per source: the same volume seen first as an attached disk and later
-- from Terraform state must both be kept. The append-only triggers are unchanged; only the
-- uniqueness rule is widened. Rows suppressed by the old index are re-imported from each
-- deployment's evidence file on the next import.
DROP INDEX deployment_resources_unique;
CREATE UNIQUE INDEX deployment_resources_unique ON deployment_resources (deployment_id, resource_id, IFNULL(parent_id, ''), source);
