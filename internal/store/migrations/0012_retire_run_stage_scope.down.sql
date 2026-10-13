-- Recreate the retired tables as 0001, 0002 and 0005 left them, so the migration
-- chain reverses cleanly.
BEGIN;

CREATE TABLE IF NOT EXISTS scope_snapshot (
    id                bigserial PRIMARY KEY,
    org_id            bigint      NOT NULL REFERENCES org (id) ON DELETE CASCADE,
    allowlist_path    text,
    denylist_path     text,
    allowlist_digest  text        NOT NULL,
    denylist_digest   text,
    allow_private     boolean     NOT NULL DEFAULT false,
    allow_any         boolean     NOT NULL DEFAULT false,
    consent_acked     boolean     NOT NULL DEFAULT false,
    created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS scope_snapshot_org_idx ON scope_snapshot (org_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS scope_snapshot_identity_idx ON scope_snapshot (
    org_id, allowlist_digest, (COALESCE(denylist_digest, '')), allow_private, allow_any
);
ALTER TABLE scope_snapshot ENABLE ROW LEVEL SECURITY;
ALTER TABLE scope_snapshot FORCE ROW LEVEL SECURITY;
CREATE POLICY scope_snapshot_rls ON scope_snapshot USING (org_id = current_org_id());

ALTER TABLE run ADD COLUMN IF NOT EXISTS scope_id bigint REFERENCES scope_snapshot (id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS run_stage (
    id             bigserial PRIMARY KEY,
    run_pk         bigint      NOT NULL REFERENCES run (id) ON DELETE CASCADE,
    name           text        NOT NULL,
    seq            integer     NOT NULL,
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
ALTER TABLE run_stage ENABLE ROW LEVEL SECURITY;
ALTER TABLE run_stage FORCE ROW LEVEL SECURITY;
CREATE POLICY run_stage_rls ON run_stage USING (
    run_pk IN (SELECT id FROM run WHERE org_id = current_org_id())
);

COMMIT;
