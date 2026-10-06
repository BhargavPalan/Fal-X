package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// schemaFingerprint hashes the parts of the live schema that, if lost, would
// silently remove tenant isolation.
//
// This is deliberately narrow. It is not a pg_dump comparison and it does not
// track columns, types, or indexes: those change legitimately as the product
// grows, and a fingerprint that fires on ordinary schema movement trains people
// to ignore it. What it does track is the set of tables and, for each one,
// whether row-level security is enabled and forced and how many policies it
// carries.
//
// The ledger checksums answer a different question. They catch a migration file
// being edited after it was applied. They say nothing about somebody dropping a
// policy or clearing a FORCE flag directly in the database, which is precisely
// the change that would let one organisation read another's rows while every
// migration still reported itself as applied.
func schemaFingerprint(ctx context.Context, d *DB) (string, error) {
	const q = `
		SELECT c.relname,
		       c.relrowsecurity,
		       c.relforcerowsecurity,
		       (SELECT count(*)::int
		          FROM pg_policies p
		         WHERE p.schemaname = 'public'
		           AND p.tablename  = c.relname)
		  FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE c.relkind = 'r'
		   AND n.nspname = 'public'
		   AND c.relname <> 'schema_fingerprint'
		 ORDER BY c.relname`

	rows, err := d.sql.QueryContext(ctx, q)
	if err != nil {
		return "", fmt.Errorf("store: read schema fingerprint: %w", err)
	}
	defer rows.Close()

	h := sha256.New()
	for rows.Next() {
		var (
			table       string
			rls, force  bool
			policyCount int
		)
		if err := rows.Scan(&table, &rls, &force, &policyCount); err != nil {
			return "", fmt.Errorf("store: scan schema fingerprint: %w", err)
		}
		fmt.Fprintf(h, "%s rls=%t force=%t policies=%d\n", table, rls, force, policyCount)
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("store: read schema fingerprint: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// CaptureFingerprint records the current schema shape as the new baseline.
//
// It is the escape hatch for the schema-drift report, and it is deliberately
// explicit: accepting an unexplained change to the live schema is a decision
// somebody has to make out loud.
func (d *DB) CaptureFingerprint(ctx context.Context) error {
	return d.captureFingerprint(ctx)
}

// captureFingerprint records the fingerprint the schema has right now.
func (d *DB) captureFingerprint(ctx context.Context) error {
	fp, err := schemaFingerprint(ctx, d)
	if err != nil {
		return err
	}
	if _, err := d.sql.ExecContext(ctx,
		`INSERT INTO schema_fingerprint (id, fingerprint, captured_at)
		 VALUES (1, $1, now())
		 ON CONFLICT (id) DO UPDATE
		    SET fingerprint = EXCLUDED.fingerprint,
		        captured_at = now()`, fp); err != nil {
		return fmt.Errorf("store: record schema fingerprint: %w", err)
	}
	return nil
}

// recordedFingerprint returns the fingerprint stored at the last apply.
func (d *DB) recordedFingerprint(ctx context.Context) (string, error) {
	var fp string
	err := d.sql.QueryRowContext(ctx,
		"SELECT fingerprint FROM schema_fingerprint WHERE id = 1").Scan(&fp)
	switch {
	case err == nil:
		return fp, nil
	case isNoRows(err):
		// Absent means the ledger predates the fingerprint table, which is not
		// drift. It is a missing measurement, and the next apply writes one.
		return "", nil
	default:
		return "", fmt.Errorf("store: read schema fingerprint: %w", err)
	}
}
