// Package store owns the Postgres connection, the migration ledger, and the
// repositories that read and write tenant-scoped data.
//
// Tenancy is enforced by Postgres row-level security, not by Go-side WHERE
// clauses. Every connection sets the org_id GUC on checkout, and the policies in
// this package's migrations/0001_core.up.sql are the primary thing standing
// between one tenant and another's inventory. A few tenant reads also carry an
// explicit org_id = current_org_id() predicate as defence in depth: it reads the
// same GUC the policies do, so it still scopes the read even if the connecting
// role were to bypass RLS. RLS remains the control; the Go-side predicate is a
// backstop, not a substitute.
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

	"github.com/BhargavPalan/Fal-X/internal/logging"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver
)

// ErrNoSchema is returned when a query needs tables that no migration created.
var ErrNoSchema = errors.New("store: schema not present, run migrations")

// Options configures a connection pool.
type Options struct {
	// DSN is a libpq-style URL, for example
	// postgres://user:pass@localhost:5432/falx?sslmode=disable
	DSN string

	// OrgID is the tenant every InTx call runs as. It is applied inside each
	// transaction, never on the shared pool: a session-level setting lives on one
	// physical connection, and the pool hands connections to whoever asks, so a
	// tenant's queries could run as another tenant or as none. Zero means no
	// tenancy filter, which is only appropriate for migrations and the auditor
	// role.
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

	// Tenant isolation is enforced by row-level security, which a superuser or a
	// BYPASSRLS role ignores — so such a role would silently serve every tenant every
	// other tenant's data. Warn loudly rather than pretend the guarantee holds. The
	// tenant reads also carry an explicit org_id predicate, which still scopes them
	// even for such a role, but the right fix is a NOSUPERUSER NOBYPASSRLS role.
	if bypass, err := roleBypassesRLS(pingCtx, db); err == nil && bypass {
		logging.Warn("store: the database role bypasses row-level security (superuser or BYPASSRLS); " +
			"run Fal-X as a NOSUPERUSER NOBYPASSRLS role so tenant isolation is enforced")
	}

	out := &DB{sql: db, opts: opts}
	return out, nil
}

// roleBypassesRLS reports whether the connected role ignores row-level security.
func roleBypassesRLS(ctx context.Context, db *sql.DB) (bool, error) {
	var bypass bool
	err := db.QueryRowContext(ctx,
		"SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user").Scan(&bypass)
	return bypass, err
}

// Now returns the database server's current time. Callers that compare against
// first_seen_at/last_seen_at (which the database stamps) must use this clock, not the
// application host's, so a scan's own inserts land on the expected side of a window.
func (d *DB) Now(ctx context.Context) (time.Time, error) {
	var t time.Time
	if err := d.sql.QueryRowContext(ctx, "SELECT now()").Scan(&t); err != nil {
		return time.Time{}, fmt.Errorf("store: now: %w", err)
	}
	return t, nil
}

// SQL exposes the underlying handle for callers that need raw access.
//
// A statement run directly on it carries no tenant context, so row-level
// security sees no org and returns nothing or rejects the write. Use InTx for
// anything that touches tenant tables.
func (d *DB) SQL() *sql.DB { return d.sql }

// Close releases the pool.
func (d *DB) Close() error {
	if d == nil || d.sql == nil {
		return nil
	}
	return d.sql.Close()
}

// InTx runs fn in a transaction that executes as the DB's tenant.
//
// The org id is written with a transaction-local set_config, so it exists only
// for this transaction and cannot outlive it on a pooled connection. The value
// goes through set_config rather than SET so it is parameterised, which keeps it
// out of the SQL text. The explicit ::text cast is required: set_config's second
// argument is text, and without it the driver has no type to encode into.
//
// fn's error rolls the transaction back and is returned unchanged.
func (d *DB) InTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	if d.opts.OrgID != 0 {
		if _, err := tx.ExecContext(ctx,
			"SELECT set_config('falx.org_id', $1::text, true)",
			strconv.FormatInt(d.opts.OrgID, 10)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: set org %d: %w", d.opts.OrgID, err)
		}
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// WithOrg returns a shallow copy bound to a different tenant. The pool is
// shared and nothing is sent to the database: the tenant is applied per
// transaction by InTx.
//
// Callers must pass the org id through from an authenticated session. Treating
// it as user input is the whole vulnerability.
func (d *DB) WithOrg(_ context.Context, orgID int64) (*DB, error) {
	clone := &DB{sql: d.sql, opts: d.opts}
	clone.opts.OrgID = orgID
	return clone, nil
}

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
