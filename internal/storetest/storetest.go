// Package storetest provides the shared Postgres harness the database-backed tests use,
// so the open/lock/migrate boilerplate lives in one place instead of once per package.
package storetest

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/store"
)

// lockID serialises every DB-backed test across packages onto one advisory lock: the
// tests share one database, and the integration suite runs with -p 1, so a single lock
// keeps them from seeing each other's rows.
const lockID = 7263001

// NewTestDB opens the integration database named by FALX_TEST_DSN, takes the shared
// advisory lock, applies the migrations, and returns the handle. It skips the test when
// no DSN is set, so the unit tests still run without a database.
func NewTestDB(t *testing.T) *store.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("FALX_TEST_DSN"))
	if dsn == "" {
		t.Skip("set FALX_TEST_DSN to run database integration tests")
	}
	ctx := context.Background()
	db, err := store.Open(ctx, store.DefaultOptions(dsn))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	lock, err := db.SQL().Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lock.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = lock.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", lockID)
		_ = lock.Close()
	})
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}
