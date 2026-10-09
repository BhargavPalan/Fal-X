-- One scope snapshot per distinct scope.
--
-- UpsertRun looked for an identical snapshot and inserted one when it found none,
-- with nothing in the database to arbitrate. Runs recorded at the same moment each
-- found nothing and each inserted, so identical scopes were stored more than once.
-- A unique index makes the database the arbiter.
--
-- Databases that already hold duplicates are repaired first: every run is pointed
-- at the oldest identical snapshot and the extras are deleted, so the index can be
-- built. run and scope_snapshot have row-level security FORCEd, which applies even
-- to their owner, so a migration (which has no tenant) would see no rows at all.
-- The FORCE flag is lifted for the repair and put back before the migration ends;
-- the schema fingerprint is recaptured after migrations, so it ends where it began.

BEGIN;

ALTER TABLE run            NO FORCE ROW LEVEL SECURITY;
ALTER TABLE scope_snapshot NO FORCE ROW LEVEL SECURITY;

WITH ranked AS (
    SELECT id,
           min(id) OVER (PARTITION BY org_id, allowlist_digest,
                                      COALESCE(denylist_digest, ''),
                                      allow_private, allow_any) AS keep_id
    FROM scope_snapshot
)
UPDATE run r SET scope_id = ranked.keep_id
FROM ranked
WHERE r.scope_id = ranked.id AND ranked.id <> ranked.keep_id;

WITH ranked AS (
    SELECT id,
           min(id) OVER (PARTITION BY org_id, allowlist_digest,
                                      COALESCE(denylist_digest, ''),
                                      allow_private, allow_any) AS keep_id
    FROM scope_snapshot
)
DELETE FROM scope_snapshot s
USING ranked
WHERE s.id = ranked.id AND ranked.id <> ranked.keep_id;

ALTER TABLE run            FORCE ROW LEVEL SECURITY;
ALTER TABLE scope_snapshot FORCE ROW LEVEL SECURITY;

CREATE UNIQUE INDEX IF NOT EXISTS scope_snapshot_identity_idx ON scope_snapshot (
    org_id, allowlist_digest, (COALESCE(denylist_digest, '')), allow_private, allow_any
);

COMMIT;
