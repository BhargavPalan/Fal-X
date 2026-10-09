-- Rollback of 0003_intel.up.sql. Source rows go before the cve rows they
-- reference.

BEGIN;

DROP TABLE IF EXISTS source_watermark;
DROP TABLE IF EXISTS cve_epss;
DROP TABLE IF EXISTS cve_kev_cisa;
DROP TABLE IF EXISTS cve;

COMMIT;
