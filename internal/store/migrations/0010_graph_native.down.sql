-- Rollback of 0010_graph_native.up.sql: recreate the asset inventory (as 0001
-- defined it), re-key match_result on asset (as 0008 defined it), and drop the
-- entity criticality column.

BEGIN;

CREATE TABLE asset (
    id             bigserial PRIMARY KEY,
    org_id         bigint      NOT NULL REFERENCES org (id) ON DELETE CASCADE,
    kind           text        NOT NULL
                   CHECK (kind IN ('domain', 'host', 'ip', 'url', 'service',
                                   'certificate', 'repository')),
    identifier     text        NOT NULL,
    first_seen_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz NOT NULL DEFAULT now(),
    criticality    integer     NOT NULL DEFAULT 0
                   CHECK (criticality BETWEEN 0 AND 100),
    internet_face  boolean,
    UNIQUE (org_id, kind, identifier)
);

CREATE INDEX asset_org_kind_idx  ON asset (org_id, kind);
CREATE INDEX asset_org_ident_idx ON asset (org_id, identifier);
CREATE INDEX asset_org_seen_idx  ON asset (org_id, last_seen_at DESC);

CREATE TABLE asset_attribute (
    id            bigserial PRIMARY KEY,
    asset_id      bigint      NOT NULL REFERENCES asset (id) ON DELETE CASCADE,
    key           text        NOT NULL,
    value         text        NOT NULL,
    source        text        NOT NULL DEFAULT '',
    confidence    real        NOT NULL DEFAULT 1.0 CHECK (confidence BETWEEN 0 AND 1),
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (asset_id, key, value)
);

CREATE INDEX asset_attribute_asset_idx ON asset_attribute (asset_id, key);

CREATE TABLE asset_observation (
    id          bigserial PRIMARY KEY,
    asset_id    bigint      NOT NULL REFERENCES asset (id) ON DELETE CASCADE,
    run_pk      bigint      NOT NULL REFERENCES run (id) ON DELETE CASCADE,
    stage       text        NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (asset_id, run_pk, stage)
);

CREATE INDEX asset_observation_run_idx   ON asset_observation (run_pk);
CREATE INDEX asset_observation_asset_idx ON asset_observation (asset_id, observed_at DESC);

ALTER TABLE asset             ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_attribute   ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_observation ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset             FORCE ROW LEVEL SECURITY;
ALTER TABLE asset_attribute   FORCE ROW LEVEL SECURITY;
ALTER TABLE asset_observation FORCE ROW LEVEL SECURITY;

CREATE POLICY asset_rls ON asset USING (org_id = current_org_id());
CREATE POLICY asset_attribute_rls ON asset_attribute USING (
    asset_id IN (SELECT id FROM asset WHERE org_id = current_org_id())
);
CREATE POLICY asset_observation_rls ON asset_observation USING (
    asset_id IN (SELECT id FROM asset WHERE org_id = current_org_id())
);

DROP TABLE IF EXISTS match_result;

CREATE TABLE match_result (
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

CREATE INDEX match_result_org_cve_idx ON match_result (org_id, cve_id);

ALTER TABLE match_result ENABLE ROW LEVEL SECURITY;
ALTER TABLE match_result FORCE ROW LEVEL SECURITY;
CREATE POLICY match_result_rls ON match_result USING (org_id = current_org_id());

ALTER TABLE entity DROP COLUMN criticality;

COMMIT;
