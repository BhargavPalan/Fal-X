-- The entity graph: the typed assets a run discovers, the relationships between
-- them, and the per-fact evidence behind each.
--
-- This is tenant data like the asset inventory it will eventually supersede, so
-- every table carries org_id and forces row-level security. The shape is an open
-- asset model: entity holds nodes, entity_edge holds typed directed relationships,
-- and entity_fact holds observed facts with their source, whether the observation
-- touched the target, a confidence and the run that saw it.
--
-- Why a separate graph rather than an extension of asset: asset.kind is a seven-
-- value CHECK and (org_id, kind, identifier) leaves no room for the ~30 entity
-- types, the typed edges, or the per-fact provenance and temporal columns the
-- engine needs. Keeping asset intact lets the matcher and importer keep working
-- while the graph is built alongside.
--
-- entity.seed_distance is how many host-hops the entity is from a run seed. It is
-- the brake the engine bounds recursion with, recorded so a result can be audited.
-- first_seen_at/last_seen_at on every table make run-over-run diffing a query.
--
-- source_cache lets a passive source skip a repeated third-party call within a TTL,
-- so re-running a scan does not re-query the same provider.

BEGIN;

CREATE TABLE IF NOT EXISTS entity (
    id            bigserial   PRIMARY KEY,
    org_id        bigint      NOT NULL REFERENCES org (id) ON DELETE CASCADE,
    type          text        NOT NULL,
    -- Canonical identity for the type: lowercase host, bare IP, cert SHA-256.
    key           text        NOT NULL,
    display       text        NOT NULL DEFAULT '',
    seed_distance integer     NOT NULL DEFAULT 0,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, type, key)
);

CREATE INDEX IF NOT EXISTS entity_org_type_idx ON entity (org_id, type);
CREATE INDEX IF NOT EXISTS entity_org_seen_idx ON entity (org_id, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS entity_edge (
    id            bigserial   PRIMARY KEY,
    org_id        bigint      NOT NULL REFERENCES org (id) ON DELETE CASCADE,
    src_id        bigint      NOT NULL REFERENCES entity (id) ON DELETE CASCADE,
    dst_id        bigint      NOT NULL REFERENCES entity (id) ON DELETE CASCADE,
    rel           text        NOT NULL,
    confidence    real        NOT NULL DEFAULT 1.0 CHECK (confidence BETWEEN 0 AND 1),
    -- Inferred edges (sibling_of, origin_of) are hypotheses, not observed truth.
    inferred      boolean     NOT NULL DEFAULT false,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, src_id, dst_id, rel)
);

CREATE INDEX IF NOT EXISTS entity_edge_src_idx ON entity_edge (org_id, src_id, rel);
CREATE INDEX IF NOT EXISTS entity_edge_dst_idx ON entity_edge (org_id, dst_id, rel);

CREATE TABLE IF NOT EXISTS entity_fact (
    id            bigserial   PRIMARY KEY,
    entity_id     bigint      NOT NULL REFERENCES entity (id) ON DELETE CASCADE,
    key           text        NOT NULL,
    value         text        NOT NULL,
    -- The source that observed the fact, e.g. 'native/ct' or 'premium/shodan'.
    source        text        NOT NULL DEFAULT '',
    -- Whether obtaining it touched the target (active) or came from a third party.
    passive       boolean     NOT NULL DEFAULT true,
    confidence    real        NOT NULL DEFAULT 1.0 CHECK (confidence BETWEEN 0 AND 1),
    run_pk        bigint      REFERENCES run (id) ON DELETE SET NULL,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (entity_id, key, value)
);

CREATE INDEX IF NOT EXISTS entity_fact_entity_idx ON entity_fact (entity_id, key);

CREATE TABLE IF NOT EXISTS source_cache (
    id         bigserial   PRIMARY KEY,
    org_id     bigint      NOT NULL REFERENCES org (id) ON DELETE CASCADE,
    source     text        NOT NULL,
    input_key  text        NOT NULL,
    fetched_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    payload    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (org_id, source, input_key)
);

CREATE INDEX IF NOT EXISTS source_cache_expiry_idx ON source_cache (expires_at);

-- Row-level security, matching the idiom in 0001: enable, force so the owner role
-- cannot bypass it, and one policy per table keyed on the org_id GUC. The child
-- tables (entity_edge is keyed directly; entity_fact derives through its entity)
-- follow the asset_attribute pattern.

ALTER TABLE entity       ENABLE ROW LEVEL SECURITY;
ALTER TABLE entity_edge  ENABLE ROW LEVEL SECURITY;
ALTER TABLE entity_fact  ENABLE ROW LEVEL SECURITY;
ALTER TABLE source_cache ENABLE ROW LEVEL SECURITY;

ALTER TABLE entity       FORCE ROW LEVEL SECURITY;
ALTER TABLE entity_edge  FORCE ROW LEVEL SECURITY;
ALTER TABLE entity_fact  FORCE ROW LEVEL SECURITY;
ALTER TABLE source_cache FORCE ROW LEVEL SECURITY;

CREATE POLICY entity_rls       ON entity       USING (org_id = current_org_id());
CREATE POLICY entity_edge_rls  ON entity_edge  USING (org_id = current_org_id());
CREATE POLICY source_cache_rls ON source_cache USING (org_id = current_org_id());
CREATE POLICY entity_fact_rls  ON entity_fact  USING (
    entity_id IN (SELECT id FROM entity WHERE org_id = current_org_id())
);

COMMIT;
