-- Rollback of 0001_core.up.sql.
--
-- Order matters for the foreign keys: observations and attributes before the
-- assets they reference, stages before runs.

BEGIN;

DROP TABLE IF EXISTS asset_observation;
DROP TABLE IF EXISTS asset_attribute;
DROP TABLE IF EXISTS asset;
DROP TABLE IF EXISTS run_stage;
DROP TABLE IF EXISTS run;
DROP TABLE IF EXISTS scope_snapshot;
DROP TABLE IF EXISTS app_user;
DROP TABLE IF EXISTS org;
DROP TABLE IF EXISTS schema_fingerprint;

DROP FUNCTION IF EXISTS current_org_id();

COMMIT;