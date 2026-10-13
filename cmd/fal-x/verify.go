package main

import (
	"context"

	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/verify"
)

// runVerify re-checks the stored exposure findings against the live target, read-only,
// and records whether each still holds.
func runVerify(ctx context.Context, args []string) error {
	fs := flagSet("verify")
	dsn := fs.String("dsn", "", "Postgres connection string (default $FALX_DSN)")
	org := fs.String("org", "", "organization slug (default $FALX_ORG, then \"default\")")
	quiet := fs.Bool("quiet", false, "log errors only")
	debug := fs.Bool("debug", false, "verbose internal logging")
	asJSON := fs.Bool("json", false, "machine-readable logging")
	if err := parseFlags(fs, "fal-x verify [--org slug]", args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return logging.Usagef("verify takes no arguments, got %q", fs.Arg(0))
	}
	applyLogging(&globals{debug: *debug, quiet: *quiet, json: *asJSON})

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

	sum, err := verify.Run(ctx, scoped, id, verify.NewHTTPChecker())
	if err != nil {
		return logging.Runtimef("%v", err)
	}
	logging.Ok("verification complete: %d confirmed, %d refuted, %d inconclusive",
		sum.Confirmed, sum.Refuted, sum.Inconclusive)
	return nil
}
