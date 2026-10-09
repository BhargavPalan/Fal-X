-- NVD detail for the CVEs a tenant actually cares about.
--
-- NVD is fetched on demand for CVEs that appear in findings, not mirrored: its
-- bulk feeds are hundreds of megabytes and its keyless API allows five requests
-- per thirty seconds, which is ample for a handful of finding CVEs and hopeless
-- for the whole corpus. This is global reference data like the other cve tables,
-- so it has no org_id and no row-level security; the isolation test names it.
--
-- One score is kept per CVE: the newest CVSS version available, preferring the
-- NVD's own (primary) assessment over a secondary one. The version is stored with
-- the score because a 7.5 under v2 and a 7.5 under v4 do not mean the same thing.

BEGIN;

CREATE TABLE IF NOT EXISTS cve_nvd (
    cve_id        text        PRIMARY KEY REFERENCES cve (cve_id) ON DELETE CASCADE,
    cvss_version  text        NOT NULL DEFAULT '',
    cvss_score    real        CHECK (cvss_score BETWEEN 0 AND 10),
    cvss_severity text        NOT NULL DEFAULT '',
    cvss_vector   text        NOT NULL DEFAULT '',
    description   text        NOT NULL DEFAULT '',
    published_at  timestamptz,
    modified_at   timestamptz,
    vuln_status   text        NOT NULL DEFAULT '',
    cwes          text[]      NOT NULL DEFAULT '{}',
    fetched_at    timestamptz NOT NULL DEFAULT now()
);

COMMIT;
