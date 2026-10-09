-- Row-level security for run_stage.
--
-- 0001 enabled row-level security on every tenant table except this one, so any
-- tenant could read every other tenant's run stages: names, statuses, durations
-- and notes. run_stage has no org_id of its own, so it is isolated through its
-- parent run, the same way asset_attribute and asset_observation are isolated
-- through their parent asset.
--
-- FORCE is set for the reason given in 0001: without it a table owner bypasses
-- its own policy.

BEGIN;

ALTER TABLE run_stage ENABLE ROW LEVEL SECURITY;
ALTER TABLE run_stage FORCE ROW LEVEL SECURITY;

CREATE POLICY run_stage_rls ON run_stage USING (
    run_pk IN (SELECT id FROM run WHERE org_id = current_org_id())
);

COMMIT;
