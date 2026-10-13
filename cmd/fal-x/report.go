package main

import (
	"context"

	"github.com/BhargavPalan/Fal-X/internal/logging"
)

// runReport renders the entity graph and the ranked findings a scan produced, as a
// Markdown document read from the database. It contacts nothing: a report cannot
// widen what was scanned.
func runReport(ctx context.Context, args []string) error {
	fs := flagSet("report")
	dsn := fs.String("dsn", "", "Postgres connection string (default $FALX_DSN)")
	org := fs.String("org", "", "organization slug (default $FALX_ORG, then \"default\")")
	out := fs.String("out", "", "write to this file instead of standard output")
	if err := parseFlags(fs, "fal-x report [--out file] [--org slug]", args); err != nil {
		return err
	}

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	id, err := db.EnsureOrg(ctx, orgSlug(*org), orgSlug(*org))
	if err != nil {
		return logging.Runtimef("%v", err)
	}
	scoped, err := db.WithOrg(ctx, id)
	if err != nil {
		return logging.Runtimef("%v", err)
	}
	b, err := renderGraphReport(ctx, scoped)
	if err != nil {
		return logging.Runtimef("%v", err)
	}
	return writeOut(*out, b)
}
