-- OSV advisories and the aliases that tie them to CVE ids.
--
-- Like the other intelligence tables these are the same for every tenant, so they
-- carry no org_id and no row-level security; the tenant isolation test lists them
-- by name as global tables.
--
-- An advisory is keyed by the ecosystem it was synced from as well as its id,
-- because the same advisory is published once per ecosystem it affects and each
-- ecosystem is synced, and replaced, on its own. Deleting an advisory takes its
-- affected packages and aliases with it, which is how an advisory OSV has dropped
-- stops being reported.

BEGIN;

CREATE TABLE IF NOT EXISTS osv_advisory (
    ecosystem text        NOT NULL,
    osv_id    text        NOT NULL,
    modified  timestamptz NOT NULL,
    published timestamptz,
    withdrawn timestamptz,
    summary   text        NOT NULL DEFAULT '',
    details   text        NOT NULL DEFAULT '',
    PRIMARY KEY (ecosystem, osv_id)
);

-- One row per package an advisory names. The version ranges are kept exactly as
-- OSV states them, because turning them into a comparison depends on the
-- ecosystem's own version scheme and belongs to the matcher.
CREATE TABLE IF NOT EXISTS osv_affected (
    ecosystem         text    NOT NULL,
    osv_id            text    NOT NULL,
    seq               integer NOT NULL,
    package_ecosystem text    NOT NULL DEFAULT '',
    package_name      text    NOT NULL DEFAULT '',
    purl              text    NOT NULL DEFAULT '',
    ranges            jsonb   NOT NULL DEFAULT '[]',
    versions          jsonb   NOT NULL DEFAULT '[]',
    PRIMARY KEY (ecosystem, osv_id, seq),
    FOREIGN KEY (ecosystem, osv_id) REFERENCES osv_advisory (ecosystem, osv_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS osv_affected_package_idx ON osv_affected (package_ecosystem, package_name);

-- Every other identifier an advisory carries (its own id, GHSA ids, vendor ids),
-- mapped to each CVE it names, so any of them resolves to one CVE record.
CREATE TABLE IF NOT EXISTS cve_alias (
    alias     text NOT NULL,
    cve_id    text NOT NULL REFERENCES cve (cve_id) ON DELETE CASCADE,
    ecosystem text NOT NULL,
    osv_id    text NOT NULL,
    PRIMARY KEY (alias, cve_id, ecosystem, osv_id),
    FOREIGN KEY (ecosystem, osv_id) REFERENCES osv_advisory (ecosystem, osv_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS cve_alias_cve_idx ON cve_alias (cve_id);
CREATE INDEX IF NOT EXISTS cve_alias_advisory_idx ON cve_alias (ecosystem, osv_id);

COMMIT;
