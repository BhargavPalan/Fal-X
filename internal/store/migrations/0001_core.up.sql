-- Fal-X core schema. Phase 0 covers run bookkeeping and the asset inventory.
-- Vulnerability data arrives with the intelligence core in a later phase.
--
-- Conventions:
--   * Timestamps are timestamptz in UTC. The caller is responsible for the
--     timezone; the column is not.
--   * Every tenant-scoped table carries org_id and participates in row-level
--     security, set up at the bottom of this file.
--   * Identifiers are bigint so they stay compact in indexes. Public
--     identifiers such as CVE IDs are text, because those are the join keys
--     against external data.

BEGIN;

-- ---------------------------------------------------------------------------
-- Tenancy
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS org (
    id          bigserial PRIMARY KEY,
    slug        text        NOT NULL UNIQUE,
    name        text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz
);

CREATE TABLE IF NOT EXISTS app_user (
    id            bigserial PRIMARY KEY,
    org_id        bigint      NOT NULL REFERENCES org (id) ON DELETE CASCADE,
    external_sub  text        NOT NULL,          -- OIDC subject
    email         text,
    display_name  text,
    role          text        NOT NULL DEFAULT 'operator'
                  CHECK (role IN ('operator', 'lead', 'admin', 'auditor')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    disabled_at   timestamptz,
    UNIQUE (org_id, external_sub)
);

CREATE INDEX IF NOT EXISTS app_user_org_idx ON app_user (org_id);

-- ---------------------------------------------------------------------------
-- Scope
-- ---------------------------------------------------------------------------
-- The effective authorization for a run, recorded so a report can be tied to
-- the approval that produced it. Entry lists are stored verbatim; scope_fingerprint
-- is a digest of the parsed form so a change is detectable without storing a
-- second copy.

CREATE TABLE IF NOT EXISTS scope_snapshot (
    id                bigserial PRIMARY KEY,
    org_id            bigint      NOT NULL REFERENCES org (id) ON DELETE CASCADE,
    allowlist_path    text,
    denylist_path     text,
    allowlist_digest  text        NOT NULL,
    denylist_digest   text,
    allow_private     boolean     NOT NULL DEFAULT false,
    allow_any         boolean     NOT NULL DEFAULT false,
    consent_acked    boolean     NOT NULL DEFAULT false,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scope_snapshot_org_idx ON scope_snapshot (org_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Runs
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS run (
    id             bigserial PRIMARY KEY,
    org_id         bigint      NOT NULL REFERENCES org (id) ON DELETE CASCADE,
    run_id         text        NOT NULL,          -- the human-facing timestamp label
    label          text        NOT NULL,
    mode           text        NOT NULL DEFAULT 'domain'
                   CHECK (mode IN ('domain', 'ip', 'asn')),
    status         text        NOT NULL DEFAULT 'running'
                   CHECK (status IN ('running', 'completed', 'completed_with_failures',
                                     'failed', 'interrupted')),
    targets        text[]      NOT NULL DEFAULT '{}',
    org_name       text,
    scope_id       bigint      REFERENCES scope_snapshot (id) ON DELETE SET NULL,
    profile        text        NOT NULL DEFAULT 'normal',
    tool_versions  jsonb       NOT NULL DEFAULT '{}'::jsonb,
    network_stats  jsonb       NOT NULL DEFAULT '{}'::jsonb,
    started_at     timestamptz NOT NULL DEFAULT now(),
    finished_at    timestamptz,
    duration_secs  integer
);

CREATE UNIQUE INDEX IF NOT EXISTS run_org_runid_idx ON run (org_id, run_id);
CREATE INDEX IF NOT EXISTS run_org_started_idx ON run (org_id, started_at DESC);

-- Stage records. This is the artifact that makes a clean result
-- distinguishable from a crashed stage: an empty output file means the stage
-- ran and found nothing, a missing output means it never got that far.
CREATE TABLE IF NOT EXISTS run_stage (
    id             bigserial PRIMARY KEY,
    run_pk         bigint      NOT NULL REFERENCES run (id) ON DELETE CASCADE,
    name           text        NOT NULL,
    seq            integer     NOT NULL,          -- execution order
    status         text        NOT NULL
                   CHECK (status IN ('succeeded', 'failed', 'skipped', 'running')),
    exit_code      integer     NOT NULL DEFAULT 0,
    duration_secs  integer     NOT NULL DEFAULT 0,
    inputs         bigint      NOT NULL DEFAULT 0,
    outputs        bigint      NOT NULL DEFAULT 0,
    note           text        NOT NULL DEFAULT '',
    started_at     timestamptz,
    finished_at    timestamptz,
    UNIQUE (run_pk, name)
);

CREATE INDEX IF NOT EXISTS run_stage_run_idx ON run_stage (run_pk, seq);

-- ---------------------------------------------------------------------------
-- Asset inventory
-- ---------------------------------------------------------------------------
-- One row per distinct thing discovered. A host observed by several runs is one
-- row with several observations, which is what makes run-over-run diffing a
-- query rather than a file comparison.

CREATE TABLE IF NOT EXISTS asset (
    id             bigserial PRIMARY KEY,
    org_id         bigint      NOT NULL REFERENCES org (id) ON DELETE CASCADE,
    kind           text        NOT NULL
                   CHECK (kind IN ('domain', 'host', 'ip', 'url', 'service',
                                   'certificate', 'repository')),
    -- Canonical value: lowercase host, bare IP, full URL, or CPE 2.3 string.
    identifier     text        NOT NULL,
    first_seen_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz NOT NULL DEFAULT now(),
    -- Criticality comes from the operator, never inferred. 0 means unset.
    criticality    integer     NOT NULL DEFAULT 0
                   CHECK (criticality BETWEEN 0 AND 100),
    internet_face  boolean,
    UNIQUE (org_id, kind, identifier)
);

CREATE INDEX IF NOT EXISTS asset_org_kind_idx  ON asset (org_id, kind);
CREATE INDEX IF NOT EXISTS asset_org_ident_idx ON asset (org_id, identifier);
CREATE INDEX IF NOT EXISTS asset_org_seen_idx  ON asset (org_id, last_seen_at DESC);

-- Observable facts about an asset: software and version, banner, certificate
-- fingerprint, page title. Kept as rows rather than columns so a new detector
-- does not need a migration.
CREATE TABLE IF NOT EXISTS asset_attribute (
    id           bigserial PRIMARY KEY,
    asset_id     bigint      NOT NULL REFERENCES asset (id) ON DELETE CASCADE,
    key          text        NOT NULL,             -- 'software', 'version', 'banner', 'title', 'tech'
    value        text        NOT NULL,
    -- Where the fact came from: the stage and tool that observed it.
    source       text        NOT NULL DEFAULT '',
    -- 0 to 1. Fingerprint-derived facts carry a lower value than a version
    -- reported by the product itself.
    confidence   real        NOT NULL DEFAULT 1.0
                 CHECK (confidence BETWEEN 0 AND 1),
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (asset_id, key, value)
);

CREATE INDEX IF NOT EXISTS asset_attribute_asset_idx ON asset_attribute (asset_id, key);

-- Which runs observed an asset. The join table that makes run-over-run diffing
-- a single query.
CREATE TABLE IF NOT EXISTS asset_observation (
    id         bigserial PRIMARY KEY,
    asset_id   bigint      NOT NULL REFERENCES asset (id) ON DELETE CASCADE,
    run_pk     bigint      NOT NULL REFERENCES run (id) ON DELETE CASCADE,
    stage      text        NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (asset_id, run_pk, stage)
);

CREATE INDEX IF NOT EXISTS asset_observation_run_idx   ON asset_observation (run_pk);
CREATE INDEX IF NOT EXISTS asset_observation_asset_idx ON asset_observation (asset_id, observed_at DESC);

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------
-- Enforcement is per statement through the org_id GUC, set by the connection
-- pool on every checkout. The policy is the only thing standing between one
-- tenant and another's inventory.
--
-- Two things are deliberate here:
--
--   * org is NOT covered by a policy. A session must be able to look up its own
--     org row before it has an org id, and org rows are not tenant data.
--
--   * FORCE is set. Without it a table owner bypasses its own policies, which
--     would mean the migration connection, and any connection reusing the owner
--     role, reads every tenant. Forcing it means the policy holds regardless of
--     which role is in use.

CREATE OR REPLACE FUNCTION current_org_id() RETURNS bigint
    LANGUAGE sql STABLE AS $$
        SELECT NULLIF(current_setting('falx.org_id', true), '')::bigint
    $$;

ALTER TABLE app_user           ENABLE ROW LEVEL SECURITY;
ALTER TABLE scope_snapshot     ENABLE ROW LEVEL SECURITY;
ALTER TABLE run                ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset              ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_attribute    ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_observation  ENABLE ROW LEVEL SECURITY;

ALTER TABLE app_user           FORCE ROW LEVEL SECURITY;
ALTER TABLE scope_snapshot     FORCE ROW LEVEL SECURITY;
ALTER TABLE run                FORCE ROW LEVEL SECURITY;
ALTER TABLE asset              FORCE ROW LEVEL SECURITY;
ALTER TABLE asset_attribute    FORCE ROW LEVEL SECURITY;
ALTER TABLE asset_observation  FORCE ROW LEVEL SECURITY;

CREATE POLICY app_user_rls        ON app_user        USING (org_id = current_org_id());
CREATE POLICY scope_snapshot_rls  ON scope_snapshot  USING (org_id = current_org_id());
CREATE POLICY run_rls             ON run             USING (org_id = current_org_id());
CREATE POLICY asset_rls           ON asset           USING (org_id = current_org_id());
CREATE POLICY asset_attribute_rls  ON asset_attribute USING (
    asset_id IN (SELECT id FROM asset WHERE org_id = current_org_id())
);
CREATE POLICY asset_observation_rls ON asset_observation USING (
    asset_id IN (SELECT id FROM asset WHERE org_id = current_org_id())
);

-- Fingerprint of the live schema shape, written by the migration runner once
-- the migrations are applied. Row-level security is not modelled here because
-- this table holds one global row, not per-tenant data.
--
-- It exists so an out-of-band change to the live schema is detectable. The
-- ledger checksums in schema_migration only catch a migration file being edited
-- after the fact; they say nothing about a dropped policy or a disabled RLS
-- flag. Losing either of those would silently remove tenant isolation while
-- every migration still reported itself as applied.
CREATE TABLE schema_fingerprint (
    id          int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    fingerprint text NOT NULL,
    captured_at timestamptz NOT NULL DEFAULT now()
);

COMMIT;