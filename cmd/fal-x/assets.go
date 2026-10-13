package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/intel"
	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/store"
	"github.com/BhargavPalan/Fal-X/internal/util"
)

const assetsUsage = "fal-x assets <list|show|criticality> [flags]"

// runAssets manages the asset inventory held in Postgres.
func runAssets(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return logging.Usagef("usage: %s", assetsUsage)
	}
	sub, rest := args[0], args[1:]

	fs := flagSet("assets " + sub)
	dsn := fs.String("dsn", "", "Postgres connection string (default $FALX_DSN)")
	org := fs.String("org", "", "organization slug (default $FALX_ORG, then \"default\")")
	kind := fs.String("kind", "", "list: only this kind (domain, host, ip, url, service)")
	limit := fs.Int("limit", 100, "list: how many assets to show")
	if err := parseFlags(fs, "fal-x assets "+sub+" [flags]", rest); err != nil {
		return err
	}

	rating, err := checkAssetsArgs(sub, fs.Args())
	if err != nil {
		return err
	}

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	slug := orgSlug(*org)
	switch sub {
	case "list":
		return assetsList(ctx, db, slug, *kind, *limit)
	case "criticality":
		return assetsCriticality(ctx, db, slug, fs.Arg(0), rating)
	default:
		return assetsShow(ctx, db, slug, fs.Arg(0))
	}
}

// checkAssetsArgs validates the subcommand and its arguments before any database
// work, and returns the parsed rating for `criticality`.
func checkAssetsArgs(sub string, args []string) (rating int, err error) {
	switch sub {
	case "list":
	case "show":
		if len(args) != 1 {
			return 0, logging.Usagef("usage: fal-x assets show <identifier>")
		}
	case "criticality":
		if len(args) != 2 {
			return 0, logging.Usagef("usage: fal-x assets criticality <identifier> <0-100>  (0 clears the rating)")
		}
		n, convErr := strconv.Atoi(args[1])
		if convErr != nil || n < 0 || n > 100 {
			return 0, logging.Usagef("criticality must be a whole number from 0 to 100, got %q", args[1])
		}
		return n, nil
	default:
		return 0, logging.Usagef("unknown assets subcommand %q; usage: %s", sub, assetsUsage)
	}
	return 0, nil
}

func assetsList(ctx context.Context, db *store.DB, slug, kind string, limit int) error {
	return withOrg(ctx, db, slug, func(tx *sql.Tx) error {
		rows, err := store.ListAssets(ctx, tx, kind, limit)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "KIND\tIDENTIFIER\tRUNS\tLAST SEEN")
		for _, r := range rows {
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", r.Kind, r.Identifier, r.Runs, r.LastSeen.UTC().Format(time.RFC3339))
		}
		return w.Flush()
	})
}

func assetsCriticality(ctx context.Context, db *store.DB, slug, id string, rating int) error {
	return withOrg(ctx, db, slug, func(tx *sql.Tx) error {
		n, err := store.SetCriticality(ctx, tx, id, rating)
		if err != nil {
			return err
		}
		if n == 0 {
			return logging.Runtimef("no asset named %q in org %q", id, slug)
		}
		logging.Ok("rated %d asset(s) named %s at %d", n, id, rating)
		return nil
	})
}

func assetsShow(ctx context.Context, db *store.DB, slug, id string) error {
	return withOrg(ctx, db, slug, func(tx *sql.Tx) error {
		found, err := store.GetAsset(ctx, tx, id)
		if err != nil {
			return err
		}
		if len(found) == 0 {
			return logging.Runtimef("no asset named %q in org %q", id, slug)
		}
		for _, a := range found {
			fmt.Printf("%s  %s\n  first seen %s, last seen %s\n", a.Kind, a.Identifier,
				a.FirstSeen.UTC().Format(time.RFC3339), a.LastSeen.UTC().Format(time.RFC3339))
			for _, at := range a.Attributes {
				// Trust reflects corroboration (independent sources agreeing) and freshness
				// decay (a stale observation is weaker than a recent one).
				prov := fmt.Sprintf("%s, trust %.2f", at.Source, at.Effective())
				if at.SourceCount > 1 {
					prov = fmt.Sprintf("%s +%d sources, trust %.2f", at.Source, at.SourceCount-1, at.Effective())
				}
				fmt.Printf("  %-8s %s  (%s)\n", at.Key, at.Value, prov)
			}
			if err := printIntelFor(ctx, tx, a.Attributes); err != nil {
				return err
			}
			fmt.Println()
		}
		return nil
	})
}

// printIntelFor shows what the synced intelligence says about every CVE named in an
// asset's findings. It prints nothing when no feed has been synced.
func printIntelFor(ctx context.Context, tx *sql.Tx, attrs []store.Attribute) error {
	var ids []string
	seen := map[string]bool{}
	for _, at := range attrs {
		if at.Key != "finding" {
			continue
		}
		for _, id := range intel.CVEsIn(at.Value) {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	for _, id := range ids {
		d, err := intel.Show(ctx, tx, id)
		if err != nil {
			return logging.Runtimef("%v", err)
		}
		if !d.Known {
			continue
		}
		line := "  intel    " + id + ": "
		if d.KEV != nil {
			line += "KNOWN EXPLOITED (CISA KEV, added " + d.KEV.DateAdded.Format(util.DateOnly) + ")"
		} else {
			line += "not in CISA KEV"
		}
		if d.NVD != nil && d.NVD.CVSSScore != nil {
			line += fmt.Sprintf(", CVSS %.1f %s", *d.NVD.CVSSScore, d.NVD.CVSSSeverity)
		}
		if d.EPSS != nil {
			line += fmt.Sprintf(", EPSS %.4f (%.1f%% percentile)", d.EPSS.Score, d.EPSS.Percentile*100)
		}
		fmt.Println(line)
	}
	return nil
}
