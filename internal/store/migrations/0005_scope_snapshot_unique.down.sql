-- Rollback of 0005_scope_snapshot_unique.up.sql.
--
-- Removes the unique index. The merged duplicate snapshots are not restored: they
-- were identical copies, so nothing is lost.

BEGIN;

DROP INDEX IF EXISTS scope_snapshot_identity_idx;

COMMIT;
