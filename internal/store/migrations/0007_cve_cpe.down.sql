-- Rollback of 0007_cve_cpe.up.sql.

BEGIN;

DROP TABLE IF EXISTS cve_cpe;

COMMIT;
