-- Rollback of 0004_nvd.up.sql.

BEGIN;

DROP TABLE IF EXISTS cve_nvd;

COMMIT;
