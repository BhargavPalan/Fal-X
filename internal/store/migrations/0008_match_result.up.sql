-- Which known vulnerabilities an organization's assets are matched to, and why.
--
-- Unlike the CVE tables this is tenant data: it says what one organization runs, so
-- it carries org_id and row-level security forced on, like the asset table it hangs
-- off.
--
-- Each row records the evidence it came from, the product that evidence was read as
-- and the version, so a match can be audited back to the banner that produced it.
-- A matcher run replaces the organization's rows as a set, which is how a CVE stops
-- being reported once the software is upgraded and seen again.
--
-- tier says what kind of claim the row is:
--   affected     the observed version is inside a range NVD lists as vulnerable
--   conditional  the same, but NVD lists it only together with something else
--                (a particular operating system); conditions says what
--   possible     the product is known and the version is not, and the CVE is
--                known to be exploited in the wild
--   unverified   the product was guessed from its name alone
-- confidence is the matcher's own estimate of how much to trust that claim.

BEGIN;

CREATE TABLE IF NOT EXISTS match_result (
    id         bigserial   PRIMARY KEY,
    org_id     bigint      NOT NULL REFERENCES org (id) ON DELETE CASCADE,
    asset_id   bigint      NOT NULL REFERENCES asset (id) ON DELETE CASCADE,
    evidence   text        NOT NULL,
    software   text        NOT NULL,
    version    text        NOT NULL DEFAULT '',
    vendor     text        NOT NULL,
    product    text        NOT NULL,
    cve_id     text        NOT NULL REFERENCES cve (cve_id) ON DELETE CASCADE,
    tier       text        NOT NULL
               CHECK (tier IN ('affected', 'conditional', 'possible', 'unverified')),
    confidence text        NOT NULL CHECK (confidence IN ('high', 'medium', 'low')),
    reason     text        NOT NULL DEFAULT '',
    conditions text        NOT NULL DEFAULT '',
    caveat     text        NOT NULL DEFAULT '',
    matched_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (asset_id, evidence, vendor, product, cve_id)
);

CREATE INDEX IF NOT EXISTS match_result_org_cve_idx ON match_result (org_id, cve_id);

ALTER TABLE match_result ENABLE ROW LEVEL SECURITY;
ALTER TABLE match_result FORCE ROW LEVEL SECURITY;

CREATE POLICY match_result_rls ON match_result USING (org_id = current_org_id());

COMMIT;
