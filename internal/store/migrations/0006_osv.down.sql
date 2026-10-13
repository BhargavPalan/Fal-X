-- Rollback of 0006_osv.up.sql. Aliases and affected packages go before the
-- advisories they reference.

BEGIN;

DROP TABLE IF EXISTS cve_alias;
DROP TABLE IF EXISTS osv_affected;
DROP TABLE IF EXISTS osv_advisory;

COMMIT;
