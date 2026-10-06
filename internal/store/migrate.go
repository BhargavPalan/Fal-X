package store

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed all:migrations
var migrationFS embed.FS

// Migration is one versioned schema change.
type Migration struct {
	Version int
	Name    string
	Up      string
	Down    string
}

// splitVersioned splits a migration stem into its version and name.
//
// The stem is leading digits followed by an optional underscore and a name, so
// 0001_core yields (1, "core"). Requiring the leading digits keeps files named
// core.sql or README.sql out of the migration set.
func splitVersioned(stem string) (int, string, error) {
	i := 0
	for i < len(stem) && stem[i] >= '0' && stem[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, "", fmt.Errorf("no leading version number in %q", stem)
	}
	version, err := strconv.Atoi(stem[:i])
	if err != nil {
		return 0, "", fmt.Errorf("bad version in %q: %w", stem, err)
	}
	name := strings.TrimSpace(strings.TrimLeft(stem[i:], "_- "))
	if name == "" {
		return 0, "", fmt.Errorf("no name in %q", stem)
	}
	return version, name, nil
}

// LoadMigrations reads the embedded migration set, sorted ascending by version.
//
// Both directions must be present. A migration with no rollback cannot be
// reverted, which would make a failed deployment unrecoverable without a manual
// restore, so that is treated as a build-time error rather than a runtime one.
func LoadMigrations() ([]Migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("store: read migrations: %w", err)
	}

	var out []Migration
	seen := map[int]string{}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".sql")

		// The down direction is collected in its own pass below. Skipping it
		// here keeps version parsing and duplicate detection single-pass.
		if strings.HasSuffix(base, ".down") {
			continue
		}
		if !strings.HasSuffix(base, ".up") {
			return nil, fmt.Errorf("store: migration %q is neither .up.sql nor .down.sql", e.Name())
		}
		prefix := strings.TrimSuffix(base, ".up")
		version, name, err := splitVersioned(prefix)
		if err != nil {
			return nil, fmt.Errorf("store: migration %q: %w", e.Name(), err)
		}

		body, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("store: read %s: %w", e.Name(), err)
		}

		switch {
		case strings.HasSuffix(base, ".up"):
			out = append(out, Migration{Version: version, Name: name, Up: string(body)})
			if _, dup := seen[version]; dup {
				return nil, fmt.Errorf("store: duplicate migration version %04d (%s and %s)", version, seen[version], name)
			}
			seen[version] = name
		case strings.HasSuffix(base, ".down"):
			// Attached below; the up direction is the anchor.
		default:
			return nil, fmt.Errorf("store: unexpected migration file %q", e.Name())
		}
	}

	downs := map[int]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".down.sql") {
			continue
		}
		base := strings.TrimSuffix(strings.TrimSuffix(e.Name(), ".sql"), ".down")
		v, _, err := splitVersioned(base)
		if err != nil {
			return nil, fmt.Errorf("store: migration %q: %w", e.Name(), err)
		}
		body, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("store: read %s: %w", e.Name(), err)
		}
		downs[v] = string(body)
	}

	kept := out[:0]
	for _, m := range out {
		down, ok := downs[m.Version]
		if !ok {
			return nil, fmt.Errorf("store: migration %04d_%s has no matching .down.sql", m.Version, m.Name)
		}
		m.Down = down
		kept = append(kept, m)
	}

	sort.Slice(kept, func(i, j int) bool { return kept[i].Version < kept[j].Version })
	return kept, nil
}

// migrationLedger is the table recording what has been applied.
const ledgerDDL = `
CREATE TABLE IF NOT EXISTS schema_migration (
    version     integer     PRIMARY KEY,
    name        text        NOT NULL,
    applied_at  timestamptz NOT NULL DEFAULT now(),
    duration_ms integer     NOT NULL DEFAULT 0,
    checksum    text        NOT NULL DEFAULT ''
)`

// appliedVersion returns 0 when the migration has not been applied.
func appliedVersion(ctx context.Context, db *DB, version int) (bool, int, error) {
	var checksum string
	var dur int
	err := db.sql.QueryRowContext(ctx,
		"SELECT checksum, duration_ms FROM schema_migration WHERE version = $1", version).
		Scan(&checksum, &dur)
	switch {
	case err == nil:
		return true, dur, nil
	case isNoRows(err):
		return false, 0, nil
	default:
		return false, 0, fmt.Errorf("store: read ledger: %w", err)
	}
}

// Migrate applies every migration not yet in the ledger.
//
// Each migration runs in its own transaction so a failure leaves the ledger
// and the schema consistent with each other.
func (d *DB) Migrate(ctx context.Context) (applied int, err error) {
	if _, err := d.sql.ExecContext(ctx, ledgerDDL); err != nil {
		return 0, fmt.Errorf("store: create ledger: %w", err)
	}

	migrations, err := LoadMigrations()
	if err != nil {
		return 0, err
	}

	for _, m := range migrations {
		done, _, err := appliedVersion(ctx, d, m.Version)
		if err != nil {
			return applied, err
		}
		if done {
			continue
		}

		start := time.Now()
		if err := d.applyOne(ctx, m); err != nil {
			return applied, fmt.Errorf("store: migration %04d_%s: %w", m.Version, m.Name, err)
		}
		elapsed := int(time.Since(start).Milliseconds())

		if _, err := d.sql.ExecContext(ctx,
			`INSERT INTO schema_migration (version, name, duration_ms, checksum)
			 VALUES ($1, $2, $3, $4)`,
			m.Version, m.Name, elapsed, checksum(m.Up)); err != nil {
			return applied, fmt.Errorf("store: record migration %04d: %w", m.Version, err)
		}
		applied++
	}

	// Capture the schema fingerprint only once the migrations have all landed,
	// so the stored value describes the finished schema.
	if applied > 0 {
		if err := d.captureFingerprint(ctx); err != nil {
			return applied, err
		}
	}
	return applied, nil
}

// Rollback reverts the most recently applied migration. A target of 0 reverts
// everything.
func (d *DB) Rollback(ctx context.Context, target int) (reverted int, err error) {
	if _, err := d.sql.ExecContext(ctx, ledgerDDL); err != nil {
		return 0, fmt.Errorf("store: create ledger: %w", err)
	}

	migrations, err := LoadMigrations()
	if err != nil {
		return 0, err
	}
	byVersion := map[int]Migration{}
	for _, m := range migrations {
		byVersion[m.Version] = m
	}

	applied, err := d.appliedVersions(ctx)
	if err != nil {
		return 0, err
	}

	for _, v := range applied {
		if v <= target {
			break
		}
		m, ok := byVersion[v]
		if !ok {
			return reverted, fmt.Errorf("store: version %04d is in the ledger but not on disk", v)
		}
		if err := d.applyOne(ctx, Migration{
			Version: m.Version, Name: m.Name, Up: m.Down,
		}); err != nil {
			return reverted, fmt.Errorf("store: rollback %04d_%s: %w", m.Version, m.Name, err)
		}
		if _, err := d.sql.ExecContext(ctx,
			"DELETE FROM schema_migration WHERE version = $1", v); err != nil {
			return reverted, err
		}
		reverted++
	}
	return reverted, nil
}

// MigrationStatus is one row for the CLI and the health endpoint.
type MigrationStatus struct {
	Version   int    `json:"version"`
	Name      string `json:"name"`
	Applied   bool   `json:"applied"`
	AppliedAt string `json:"applied_at,omitempty"`
	Duration  int    `json:"duration_ms"`
	Checksum  string `json:"checksum,omitempty"`
	// Drift is true when the on-disk SQL no longer matches what was applied.
	// Editing an applied migration is a bug; this makes it visible.
	Drift bool `json:"drift"`

	// SchemaDrift is true when the live schema no longer matches the shape
	// recorded when the migrations were applied. Unlike Drift, this catches an
	// out-of-band change to the database itself, such as a dropped row-level
	// security policy, which would otherwise remove tenant isolation silently.
	SchemaDrift bool `json:"schema_drift"`
}

// Status reports the state of every migration.
func (d *DB) Status(ctx context.Context) ([]MigrationStatus, error) {
	if _, err := d.sql.ExecContext(ctx, ledgerDDL); err != nil {
		return nil, err
	}
	migrations, err := LoadMigrations()
	if err != nil {
		return nil, err
	}

	out := make([]MigrationStatus, 0, len(migrations))
	for _, m := range migrations {
		st := MigrationStatus{
			Version:  m.Version,
			Name:     m.Name,
			Checksum: checksum(m.Up),
		}
		var appliedAt time.Time
		err := d.sql.QueryRowContext(ctx,
			"SELECT applied_at, duration_ms, checksum FROM schema_migration WHERE version = $1",
			m.Version).Scan(&appliedAt, &st.Duration, &st.Checksum)
		switch {
		case err == nil:
			st.Applied = true
			st.AppliedAt = appliedAt.UTC().Format(time.RFC3339)
			st.Drift = st.Checksum != checksum(m.Up)
		case isNoRows(err):
			st.Applied = false
		default:
			return nil, err
		}
		out = append(out, st)
	}

	// The live-schema check is a property of the database as a whole, not of
	// any one migration, so it is reported on the first row where it applies.
	if recorded, err := d.recordedFingerprint(ctx); err != nil {
		return nil, err
	} else if recorded != "" {
		live, err := schemaFingerprint(ctx, d)
		if err != nil {
			return nil, err
		}
		if recorded != live {
			for i := range out {
				if out[i].Applied {
					out[i].SchemaDrift = true
					break
				}
			}
		}
	}

	return out, nil
}

// applyOne runs one migration body inside its own transaction.
func (d *DB) applyOne(ctx context.Context, m Migration) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, m.Up); err != nil {
		return err
	}
	return tx.Commit()
}

// appliedVersions reads the migration ledger, newest first. The rows are closed
// before it returns, so the connection is free for the statements that follow.
func (d *DB) appliedVersions(ctx context.Context) ([]int, error) {
	rows, err := d.sql.QueryContext(ctx,
		"SELECT version FROM schema_migration ORDER BY version DESC")
	if err != nil {
		return nil, fmt.Errorf("store: read ledger: %w", err)
	}
	defer rows.Close()

	var applied []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("store: read ledger: %w", err)
		}
		applied = append(applied, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read ledger: %w", err)
	}
	return applied, nil
}
