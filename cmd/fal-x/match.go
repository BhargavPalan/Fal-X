package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/match"
	"github.com/BhargavPalan/Fal-X/internal/store"
)

const matchUsage = "fal-x match [run|list] [flags]"

// runMatch joins the inventory to the vulnerability data.
func runMatch(ctx context.Context, args []string) error {
	sub := "run"
	if len(args) > 0 && (args[0] == "run" || args[0] == "list") {
		sub, args = args[0], args[1:]
	}

	fs := flagSet("match " + sub)
	dsn := fs.String("dsn", "", "Postgres connection string (default $FALX_DSN)")
	org := fs.String("org", "", "organization slug (default $FALX_ORG, then \"default\")")
	limit := fs.Int("limit", 30, "list: how many matches to show")
	asset := fs.String("asset", "", "list: only this asset identifier")
	if err := parseFlags(fs, matchUsage, args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return logging.Usagef("match takes no arguments, got %q; usage: %s", fs.Arg(0), matchUsage)
	}

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	slug := orgSlug(*org)
	if sub == "list" {
		return matchList(ctx, db, slug, *asset, *limit)
	}
	return matchRun(ctx, db, slug, *limit)
}

func matchRun(ctx context.Context, db *store.DB, slug string, limit int) error {
	orgID, err := db.EnsureOrg(ctx, slug, slug)
	if err != nil {
		return logging.Runtimef("%v", err)
	}
	var sum match.Summary
	if err := withOrg(ctx, db, slug, func(tx *sql.Tx) error {
		var err error
		sum, err = match.Run(ctx, tx, orgID)
		return err
	}); err != nil {
		return err
	}

	if sum.Observations == 0 {
		fmt.Println("no software was observed on any asset; scan something with FALX_DSN set, or run: fal-x assets import --from <run directory>")
		return nil
	}
	logging.Ok("read %d sighting(s) of %d product(s); %d match(es) on %d asset(s)",
		sum.Observations, sum.Products, sum.Total(), sum.Assets)
	tiers := make([]string, 0, len(sum.Matches))
	for t := range sum.Matches {
		tiers = append(tiers, t)
	}
	sort.Strings(tiers)
	for _, t := range tiers {
		fmt.Printf("  %-12s %d\n", t, sum.Matches[t])
	}
	if sum.Total() == 0 {
		fmt.Println("nothing matched; if no CVE data is synced yet, run: fal-x intel sync --source nvd")
		return nil
	}
	fmt.Println()
	return matchList(ctx, db, slug, "", limit)
}

func matchList(ctx context.Context, db *store.DB, slug, asset string, limit int) error {
	return withOrg(ctx, db, slug, func(tx *sql.Tx) error {
		rows, err := match.List(ctx, tx, asset, limit)
		if err != nil {
			return logging.Runtimef("%v", err)
		}
		if len(rows) == 0 {
			fmt.Println("no matches stored; run: fal-x match")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ASSET\tSOFTWARE\tCVE\tKEV\tCVSS\tTIER\tCONFIDENCE")
		for _, r := range rows {
			kev, cvss := "-", "-"
			if r.KEV {
				kev = "yes"
			}
			if r.CVSS != nil {
				cvss = fmt.Sprintf("%.1f", *r.CVSS)
			}
			fmt.Fprintf(w, "%s\t%s %s\t%s\t%s\t%s\t%s\t%s\n",
				r.Asset, r.Software, r.Version, r.CVE, kev, cvss, r.Tier, r.Confidence)
		}
		if err := w.Flush(); err != nil {
			return err
		}
		// A caveat describes the asset's banner, so it is said once per asset and
		// not once per CVE.
		said := map[string]bool{}
		for _, r := range rows {
			if r.Caveat != "" && !said[r.Asset+r.Caveat] {
				said[r.Asset+r.Caveat] = true
				fmt.Printf("\n%s: %s\n", r.Asset, r.Caveat)
			}
		}
		for _, r := range rows {
			if r.Conditions != "" {
				fmt.Printf("\n%s on %s\n  %s\n", r.CVE, r.Asset, r.Conditions)
			}
		}
		return nil
	})
}
