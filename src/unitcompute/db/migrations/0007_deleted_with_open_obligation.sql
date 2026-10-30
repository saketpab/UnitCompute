-- Round 7. Migration 0006 can leave a deployment 'deleted' with an open 'uncaptured'
-- recovery obligation (a schema-4 failed create followed by an empty successful deletion):
-- what the failed apply created was never established, so the deletion is unproven. Such a
-- deployment is surfaced as 'recovery_required' (quota held, deletion unverified). The
-- one-live-VM-per-owner unique index allows one non-deleted row per owner, so an owner who
-- already has a newer live deployment keeps the old row 'deleted'; its obligation stays open,
-- is listed by `unitcompute-admin recovery-report`, and the service refuses new reservations
-- for that owner until it is resolved.
UPDATE deployments SET status = 'recovery_required', status_reason = 'An earlier failed apply was never captured, so this deletion cannot be verified. AWS may still hold resources; this needs a support decision.' WHERE status = 'deleted' AND NOT EXISTS (SELECT 1 FROM deployments live WHERE live.owner_id = deployments.owner_id AND live.status <> 'deleted') AND id = (SELECT d.id FROM deployments d WHERE d.owner_id = deployments.owner_id AND d.status = 'deleted' AND EXISTS (SELECT 1 FROM recovery_obligations o WHERE o.deployment_id = d.id AND o.discharged_at IS NULL AND o.evidence = 'uncaptured') ORDER BY d.created_at DESC, d.sequence DESC LIMIT 1);
