package main

import (
	"context"
	"database/sql"
	"os"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/store"
)

// defaultOrg is the organization used when none is named. A single-user install has
// exactly one, so it should not have to be spelled out.
const defaultOrg = "default"

// orgSlug picks the organization: the flag, then FALX_ORG, then the default.
func orgSlug(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if v := strings.TrimSpace(os.Getenv("FALX_ORG")); v != "" {
		return v
	}
	return defaultOrg
}

// openDB connects to Postgres using the --dsn flag, falling back to the environment
// (FALX_DSN, then DATABASE_URL, then PGDSN). It is a usage error to have none.
func openDB(ctx context.Context, dsnFlag string) (*store.DB, error) {
	dsn := dsnFlag
	if dsn == "" {
		dsn = store.DSNFromEnv()
	}
	if dsn == "" {
		return nil, logging.Usagef("no database connection string; pass --dsn or set FALX_DSN")
	}
	db, err := store.Open(ctx, store.DefaultOptions(dsn))
	if err != nil {
		return nil, logging.Runtimef("%v", err)
	}
	return db, nil
}

// withOrg runs fn in a transaction as the organization with this slug.
func withOrg(ctx context.Context, db *store.DB, slug string, fn func(*sql.Tx) error) error {
	id, err := db.EnsureOrg(ctx, slug, slug)
	if err != nil {
		return logging.Runtimef("%v", err)
	}
	scoped, err := db.WithOrg(ctx, id)
	if err != nil {
		return logging.Runtimef("%v", err)
	}
	if err := scoped.InTx(ctx, fn); err != nil {
		return logging.Runtimef("%v", err)
	}
	return nil
}
