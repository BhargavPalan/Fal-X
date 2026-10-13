package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/store"
)

// runDiff reports what changed in the graph since a point in time: new assets, assets
// no longer seen, and new facts on known assets. It is the change-detection view that
// makes a repeated scan a monitor rather than a one-shot inventory.
func runDiff(ctx context.Context, args []string) error {
	fs := flagSet("diff")
	dsn := fs.String("dsn", "", "Postgres connection string (default $FALX_DSN)")
	org := fs.String("org", "", "organization slug (default $FALX_ORG, then \"default\")")
	since := fs.String("since", "24h", "compare against this point: a duration (e.g. 24h, 7d-as-168h) or an RFC3339 timestamp")
	limit := fs.Int("limit", 200, "maximum rows per section")
	if err := parseFlags(fs, "fal-x diff [--since 24h|<RFC3339>] [flags]", args); err != nil {
		return err
	}

	cutoff, err := parseSince(*since)
	if err != nil {
		return logging.Usagef("%v", err)
	}

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	return withOrg(ctx, db, orgSlug(*org), func(tx *sql.Tx) error {
		added, gone, changed, err := store.Diff(ctx, tx, cutoff, *limit)
		if err != nil {
			return err
		}
		fmt.Printf("changes since %s\n\n", cutoff.UTC().Format(time.RFC3339))
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintf(w, "NEW (%d)\n", len(added))
		for _, r := range added {
			fmt.Fprintf(w, "  + %s\t%s\n", r.Kind, r.Identifier)
		}
		fmt.Fprintf(w, "GONE (%d)\n", len(gone))
		for _, r := range gone {
			fmt.Fprintf(w, "  - %s\t%s\t(last seen %s)\n", r.Kind, r.Identifier, r.LastSeen.UTC().Format(time.RFC3339))
		}
		fmt.Fprintf(w, "CHANGED (%d)\n", len(changed))
		for _, f := range changed {
			fmt.Fprintf(w, "  ~ %s\t%s\t%s=%s\n", f.Kind, f.Identifier, f.Key, f.Value)
		}
		return w.Flush()
	})
}

// parseSince interprets a diff cutoff as either a duration before now or an absolute
// RFC3339 timestamp.
func parseSince(s string) (time.Time, error) {
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("--since must be a duration (24h) or an RFC3339 timestamp, got %q", s)
}
