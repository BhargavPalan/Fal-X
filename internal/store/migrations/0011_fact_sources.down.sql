BEGIN;

ALTER TABLE entity_fact DROP COLUMN sources;

COMMIT;
