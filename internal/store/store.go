// Package store owns the Postgres connection, the migration ledger, and the
// repositories that read and write tenant-scoped data.
//
// Tenancy is enforced by Postgres row-level security, not by Go-side WHERE
// clauses. Every connection sets the org_id GUC on checkout, and the policies in
// this package's migrations/0001_core.up.sql are the only thing standing between
// one tenant and another's inventory. Go-side filters are a convenience, never
// the control.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver
)

// ErrNoSchema is returned when a query needs tables that no migration created.
var ErrNoSchema = errors.New("store: schema not present, run migrations")

// Options configures a connection pool.
type Options struct {
	// DSN is a libpq-style URL, for example
	// postgres://user:pass@localhost:5432/falx?sslmode=disable
	DSN string

	// OrgID is written to the falx.org_id GUC on every connection, which is
	// what the row-level security policies read. Zero means no tenancy filter,
	// which is only appropriate for migrations and the auditor role.
	OrgID int64

	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration

	// ConnectTimeout bounds the initial connection and ping.
	ConnectTimeout time.Duration
}

// DefaultOptions returns sane pool settings.
func DefaultOptions(dsn string) Options {
	return Options{
		DSN:             dsn,
		MaxOpenConns:    16,
		MaxIdleConns:    8,
		ConnMaxLifetime: 30 * time.Minute,
		ConnMaxIdleTime: 5 * time.Minute,
		ConnectTimeout:  10 * time.Second,
	}
}

// DB is a handle on Postgres with migrations and repositories attached.
type DB struct {
	sql  *sql.DB
	opts Options
}

// Open connects and verifies the connection.
//
// The verification matters: a Postgres instance accepts the first connection and
// only fails when a backend actually forks, so a successful Dial is not proof
// the server works. Ping forces that.
func Open(ctx context.Context, opts Options) (*DB, error) {
	if strings.TrimSpace(opts.DSN) == "" {
		return nil, errors.New("store: empty DSN")
	}
	if opts.MaxOpenConns <= 0 {
		opts.MaxOpenConns = 16
	}
	if opts.MaxIdleConns <= 0 {
		opts.MaxIdleConns = 8
	}
	if opts.ConnMaxLifetime <= 0 {
		opts.ConnMaxLifetime = 30 * time.Minute
	}
	if opts.ConnMaxIdleTime <= 0 {
		opts.ConnMaxIdleTime = 5 * time.Minute
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = 10 * time.Second
	}

	db, err := sql.Open("pgx", opts.DSN)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(opts.MaxOpenConns)
	db.SetMaxIdleConns(opts.MaxIdleConns)
	db.SetConnMaxLifetime(opts.ConnMaxLifetime)
	db.SetConnMaxIdleTime(opts.ConnMaxIdleTime)

	pingCtx, cancel := context.WithTimeout(ctx, opts.ConnectTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}

	out := &DB{sql: db, opts: opts}
	if opts.OrgID != 0 {
		if err := out.setOrg(ctx, opts.OrgID); err != nil {
			db.Close()
			return nil, err
		}
	}
	return out, nil
}

// SQL exposes the underlying handle for callers that need raw access.
func (d *DB) SQL() *sql.DB { return d.sql }

// Opts returns the options the pool was opened with.
func (d *DB) Opts() Options { return d.opts }

// Close releases the pool.
func (d *DB) Close() error {
	if d == nil || d.sql == nil {
		return nil
	}
	return d.sql.Close()
}

// setOrg writes the org_id GUC that the row-level security policies read.
func (d *DB) setOrg(ctx context.Context, orgID int64) error {
	// The value goes through set_config rather than SET so it is parameterised,
	// which is what keeps it out of the SQL text. The explicit ::text cast is
	// required: set_config's second argument is text, and without the cast the
	// driver has no type to encode into and fails at execution time.
	if _, err := d.sql.ExecContext(ctx,
		"SELECT set_config('falx.org_id', $1::text, false)",
		strconv.FormatInt(orgID, 10)); err != nil {
		return fmt.Errorf("store: set org %d: %w", orgID, err)
	}
	return nil
}

// WithOrg returns a shallow copy bound to a different tenant. The pool is
// shared; only the GUC changes.
//
// Callers must pass the org id through from an authenticated session. Treating
// it as user input is the whole vulnerability.
func (d *DB) WithOrg(ctx context.Context, orgID int64) (*DB, error) {
	clone := &DB{sql: d.sql, opts: d.opts}
	clone.opts.OrgID = orgID
	if err := clone.setOrg(ctx, orgID); err != nil {
		return nil, err
	}
	return clone, nil
}

// Ping verifies the connection still works.
func (d *DB) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return d.sql.PingContext(ctx)
}

// Stats reports pool statistics, for the health endpoint.
func (d *DB) Stats() sql.DBStats { return d.sql.Stats() }

// DSNFromEnv reads a connection string from the environment, returning empty
// when unset so callers can decide whether that is an error.
func DSNFromEnv() string {
	for _, key := range []string{"FALX_DSN", "DATABASE_URL", "PGDSN"} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
	}
	return ""
}
