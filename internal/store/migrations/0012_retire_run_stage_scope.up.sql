-- Retire the remnants of the old linear-pipeline, scope-gated architecture. The graph
-- engine has no ordered stages, so run_stage is dead; scope/allowlist gating was
-- removed, so scope_snapshot and run.scope_id are dead. The run table and
-- entity_fact.run_pk stay as the hook the run-tracking redesign will build on.
BEGIN;

DROP TABLE IF EXISTS run_stage;
ALTER TABLE run DROP COLUMN IF EXISTS scope_id;
DROP TABLE IF EXISTS scope_snapshot;

COMMIT;
