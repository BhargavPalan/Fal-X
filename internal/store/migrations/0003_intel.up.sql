-- Vulnerability intelligence: the CVE spine and the first two sources.
--
-- These tables are reference data, the same for every tenant, so they carry no
-- org_id and have no row-level security. That is a decision, not an omission: the
-- tenant isolation test lists them by name as the global tables, so adding
-- another table without isolating it still fails.
--
-- The CVE id is the spine every source hangs off. A source row cannot exist
-- without its cve row, so a feed that names a CVE no other feed has seen still
-- lands cleanly.

BEGIN;

CREATE TABLE IF NOT EXISTS cve (
    cve_id        text        PRIMARY KEY
                  CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now()
);

-- CISA's Known Exploited Vulnerabilities catalogue. Its presence is the
-- strongest single signal that a CVE is exploited in the wild.
CREATE TABLE IF NOT EXISTS cve_kev_cisa (
    cve_id             text    PRIMARY KEY REFERENCES cve (cve_id) ON DELETE CASCADE,
    vendor_project     text    NOT NULL DEFAULT '',
    product            text    NOT NULL DEFAULT '',
    vulnerability_name text    NOT NULL DEFAULT '',
    date_added         date    NOT NULL,
    short_description  text    NOT NULL DEFAULT '',
    required_action    text    NOT NULL DEFAULT '',
    due_date           date,
    known_ransomware   boolean NOT NULL DEFAULT false,
    notes              text    NOT NULL DEFAULT '',
    cwes               text[]  NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS cve_kev_cisa_added_idx ON cve_kev_cisa (date_added DESC);

-- EPSS: the modelled probability that a CVE is exploited in the next 30 days. It
-- is the current score only; history is not kept.
CREATE TABLE IF NOT EXISTS cve_epss (
    cve_id        text PRIMARY KEY REFERENCES cve (cve_id) ON DELETE CASCADE,
    epss          real NOT NULL CHECK (epss BETWEEN 0 AND 1),
    percentile    real NOT NULL CHECK (percentile BETWEEN 0 AND 1),
    score_date    date NOT NULL,
    model_version text NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS cve_epss_score_idx ON cve_epss (epss DESC);

-- What was last fetched from each source. The validators let the next sync ask the
-- server "has this changed" and skip the download when it has not, which is what
-- makes a sync cheap to repeat and safe to schedule.
CREATE TABLE IF NOT EXISTS source_watermark (
    source        text        PRIMARY KEY,
    etag          text        NOT NULL DEFAULT '',
    last_modified text        NOT NULL DEFAULT '',
    version       text        NOT NULL DEFAULT '',
    records       integer     NOT NULL DEFAULT 0,
    synced_at     timestamptz NOT NULL DEFAULT now()
);

COMMIT;
