package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/store"
)

// runMigrate applies, reverts or reports on the database migrations.
func runMigrate(ctx context.Context, args []string) error {
	fs := flagSet("migrate")
	dsn := fs.String("dsn", "", "Postgres connection string (default $FALX_DSN)")
	recapture := fs.Bool("recapture", false,
		"accept the live schema as the new baseline, discarding a schema-drift report")
	if err := parseFlags(fs, "fal-x migrate <up|down|status> [flags]", args); err != nil {
		return err
	}

	action := "status"
	if rest := fs.Args(); len(rest) > 0 {
		action = rest[0]
	}
	switch action {
	case "up", "apply", "down", "rollback", "status", "":
	default:
		return logging.Usagef("unknown migrate action: %s (expected up, down, or status)", action)
	}

	// Migrations issue DDL, so the connected role needs schema rights. They run
	// outside any tenant transaction — they change the schema, not tenant rows — so
	// no org_id is set and row-level security stays enabled throughout.
	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	switch action {
	case "up", "apply":
		return migrateUp(ctx, db)
	case "down", "rollback":
		reverted, err := db.Rollback(ctx, 0)
		if err != nil {
			return err
		}
		logging.Ok("reverted %d migration(s)", reverted)
		return nil
	default:
		return migrateStatus(ctx, db, *recapture)
	}
}

// migrateUp applies pending migrations, refusing to run over a schema that was
// changed outside the runner.
func migrateUp(ctx context.Context, db *store.DB) error {
	drift, err := schemaDrift(ctx, db)
	if err != nil {
		return err
	}
	if drift {
		return logging.Runtimef(
			"refusing to migrate: the live schema no longer matches the recorded fingerprint.\n" +
				"Row-level security may have been changed outside the migration runner.\n" +
				"Investigate the difference first. Once the change is understood and intentional,\n" +
				"accept it with: fal-x migrate status --recapture")
	}

	applied, err := db.Migrate(ctx)
	if err != nil {
		return err
	}
	if applied == 0 {
		logging.Ok("schema already current")
	} else {
		logging.Ok("applied %d migration(s)", applied)
	}
	return nil
}

// migrateStatus prints the ledger, first re-baselining the schema fingerprint when
// asked, and warns on stderr if the live schema has drifted from it.
func migrateStatus(ctx context.Context, db *store.DB, recapture bool) error {
	if recapture {
		if err := db.CaptureFingerprint(ctx); err != nil {
			return err
		}
		logging.Ok("recorded the live schema as the new baseline")
	}

	status, err := db.Status(ctx)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "VERSION\tNAME\tSTATUS\tMS\tAPPLIED AT")
	drift := false
	for _, st := range status {
		state := "pending"
		switch {
		case st.SchemaDrift:
			state, drift = "SCHEMA DRIFT", true
		case st.Drift:
			state = "FILE DRIFT"
		case st.Applied:
			state = "applied"
		}
		fmt.Fprintf(w, "%04d\t%s\t%s\t%d\t%s\n",
			st.Version, st.Name, state, st.Duration, st.AppliedAt)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if drift {
		fmt.Fprintln(os.Stderr,
			"\nwarning: the live schema does not match the recorded fingerprint.\n"+
				"Row-level security may have been altered outside the migration runner.")
	}
	return nil
}

// schemaDrift reports whether the live schema differs from the fingerprint
// recorded at the last apply.
func schemaDrift(ctx context.Context, db *store.DB) (bool, error) {
	status, err := db.Status(ctx)
	if err != nil {
		return false, err
	}
	for _, st := range status {
		if st.SchemaDrift {
			return true, nil
		}
	}
	return false, nil
}

// notBuilt reports a subcommand that is part of the CLI surface but is not
// available yet. A command that accepts flags and does nothing is worse than one
// that says so, and the message names the command only.
func notBuilt(cmd string) error {
	return logging.Usagef("%s is not available yet", cmd)
}

func runExploit(_ context.Context, _ []string) error { return notBuilt("exploit") }
func runSession(_ context.Context, _ []string) error { return notBuilt("session") }
func runServe(_ context.Context, _ []string) error   { return notBuilt("serve") }
