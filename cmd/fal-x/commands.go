package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/BhargavPalan/Fal-X/internal/config"
	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/store"
)

func runMigrate(ctx context.Context, args []string) error {
	fs := flagSet("migrate")
	dsn := fs.String("dsn", "", "Postgres connection string (default $FALX_DSN)")
	recapture := fs.Bool("recapture", false,
		"accept the live schema as the new baseline, discarding a schema-drift report")
	if err := parseFlags(fs, "fal-x migrate <up|down|status> [flags]", args); err != nil {
		return err
	}

	rest := fs.Args()
	action := "status"
	if len(rest) > 0 {
		action = rest[0]
	}

	target := *dsn
	if target == "" {
		target = store.DSNFromEnv()
	}
	if target == "" {
		return logging.Usagef("no database connection string; pass --dsn or set FALX_DSN")
	}

	// Migrations need DDL rights, which is why this runs as the migration role
	// rather than the application role. Row-level security is disabled for the
	// duration of a migration anyway.
	db, err := store.Open(ctx, store.DefaultOptions(target))
	if err != nil {
		return err
	}
	defer db.Close()

	switch action {
	case "up", "apply":
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

	case "down", "rollback":
		reverted, err := db.Rollback(ctx, 0)
		if err != nil {
			return err
		}
		logging.Ok("reverted %d migration(s)", reverted)
		return nil

	case "status", "":
		if *recapture {
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
		for _, st := range status {
			state := "pending"
			switch {
			case st.SchemaDrift:
				state = "SCHEMA DRIFT"
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

		if drift, err := schemaDrift(ctx, db); err != nil {
			return err
		} else if drift {
			fmt.Fprintln(os.Stderr,
				"\nwarning: the live schema does not match the recorded fingerprint.\n"+
					"Row-level security may have been altered outside the migration runner.")
		}
		return nil

	default:
		return logging.Usagef("unknown migrate action: %s (expected up, down, or status)", action)
	}
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

// notBuilt reports a subcommand that exists in the CLI surface but whose phase
// has not landed yet.
//
// This is deliberate rather than a silent no-op: a command that accepts flags
// and does nothing is worse than one that says it is not available.
func notBuilt(cmd, phase string) error {
	return logging.Usagef("%s is not available yet; it lands in %s. See docs/ROADMAP.md", cmd, phase)
}

func runIntel(_ context.Context, _ []string) error {
	return notBuilt("intel", "phase 2, the intelligence core")
}
func runAssets(_ context.Context, _ []string) error {
	return notBuilt("assets", "phase 2, the asset graph")
}
func runMatch(_ context.Context, _ []string) error {
	return notBuilt("match", "phase 3, the matching engine")
}
func runPrioritize(_ context.Context, _ []string) error {
	return notBuilt("prioritize", "phase 4, the prioritization engine")
}
func runVerify(_ context.Context, _ []string) error {
	return notBuilt("verify", "phase 5, verification")
}
func runExploit(_ context.Context, _ []string) error {
	return notBuilt("exploit", "phase 6, exploitation")
}
func runSession(_ context.Context, _ []string) error {
	return notBuilt("session", "phase 7, post-exploitation")
}
func runReport(_ context.Context, _ []string) error { return notBuilt("report", "phase 3, reporting") }
func runServe(_ context.Context, _ []string) error  { return notBuilt("serve", "phase 8, the HTTP API") }

var _ = config.Version
