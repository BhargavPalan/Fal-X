-- Make matching graph-native and retire the asset inventory.
--
-- The entity graph (0009) supersedes the file-based pipeline's asset inventory. The
-- matcher now reads its evidence from entity_fact and keys its results on entity, so
-- match_result moves from asset_id to entity_id. Operator-set criticality, the one
-- piece of asset state the scorer needs, moves onto the entity. The asset,
-- asset_attribute and asset_observation tables are then dropped.

BEGIN;

ALTER TABLE entity ADD COLUMN criticality integer NOT NULL DEFAULT 0
    CHECK (criticality BETWEEN 0 AND 100);

-- match_result, re-keyed on entity.
DROP TABLE IF EXISTS match_result;

CREATE TABLE match_result (
    id         bigserial   PRIMARY KEY,
    org_id     bigint      NOT NULL REFERENCES org (id) ON DELETE CASCADE,
    entity_id  bigint      NOT NULL REFERENCES entity (id) ON DELETE CASCADE,
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
    UNIQUE (entity_id, evidence, vendor, product, cve_id)
);

CREATE INDEX match_result_org_cve_idx ON match_result (org_id, cve_id);

ALTER TABLE match_result ENABLE ROW LEVEL SECURITY;
ALTER TABLE match_result FORCE ROW LEVEL SECURITY;
CREATE POLICY match_result_rls ON match_result USING (org_id = current_org_id());

-- Retire the asset inventory.
DROP TABLE IF EXISTS asset_observation;
DROP TABLE IF EXISTS asset_attribute;
DROP TABLE IF EXISTS asset;

COMMIT;
