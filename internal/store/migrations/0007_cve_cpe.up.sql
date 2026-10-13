-- The CPE configurations NVD attaches to a CVE: which products and versions it
-- affects, with the AND/OR structure around them.
--
-- Global reference data like the other cve tables, so no org_id and no row-level
-- security; the tenant isolation test names it. 0004 describes NVD as fetched on
-- demand only; the bulk mirror added alongside this table fills cve_nvd and
-- cve_cpe for the whole corpus, and the on-demand lookup still works for a single
-- CVE.
--
-- A configuration is a tree: configurations hold nodes, nodes hold CPE matches.
-- A CVE that affects "product X when running on OS Y" is an AND configuration with
-- two nodes, and flattening it into rows loses that, so every row keeps its place
-- (config_seq, node_seq, match_seq) and the operators above it. The matcher needs
-- all of it to tell "affected" from "merely installed beside something affected".

BEGIN;

CREATE TABLE IF NOT EXISTS cve_cpe (
    cve_id          text    NOT NULL REFERENCES cve (cve_id) ON DELETE CASCADE,
    config_seq      integer NOT NULL,
    node_seq        integer NOT NULL,
    match_seq       integer NOT NULL,
    config_operator text    NOT NULL DEFAULT '',
    node_operator   text    NOT NULL DEFAULT '',
    negate          boolean NOT NULL DEFAULT false,
    vulnerable      boolean NOT NULL,
    criteria        text    NOT NULL,
    part            text    NOT NULL DEFAULT '',
    vendor          text    NOT NULL DEFAULT '',
    product         text    NOT NULL DEFAULT '',
    version         text    NOT NULL DEFAULT '',
    start_including text    NOT NULL DEFAULT '',
    start_excluding text    NOT NULL DEFAULT '',
    end_including   text    NOT NULL DEFAULT '',
    end_excluding   text    NOT NULL DEFAULT '',
    match_id        text    NOT NULL DEFAULT '',
    PRIMARY KEY (cve_id, config_seq, node_seq, match_seq)
);

-- The lookup the matcher makes: which CVEs name this product.
CREATE INDEX IF NOT EXISTS cve_cpe_product_idx ON cve_cpe (vendor, product) WHERE vulnerable;

COMMIT;
