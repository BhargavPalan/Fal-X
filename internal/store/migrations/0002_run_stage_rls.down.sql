-- Rollback of 0002_run_stage_rls.up.sql.
--
-- This puts run_stage back to the state 0001 left it in, which is not isolated
-- between tenants. It exists so a rollback is possible, not because that state
-- is wanted.

BEGIN;

DROP POLICY IF EXISTS run_stage_rls ON run_stage;
ALTER TABLE run_stage NO FORCE ROW LEVEL SECURITY;
ALTER TABLE run_stage DISABLE ROW LEVEL SECURITY;

COMMIT;
