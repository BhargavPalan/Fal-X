package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/intel"
	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/store"
	"github.com/BhargavPalan/Fal-X/internal/util"
)

const intelUsage = "fal-x intel <sync|enrich|status|show|search> [flags]"

// runIntel manages the vulnerability intelligence that findings are ranked against.
func runIntel(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return logging.Usagef("usage: %s", intelUsage)
	}
	sub, rest := args[0], args[1:]

	fs := flagSet("intel " + sub)
	dsn := fs.String("dsn", "", "Postgres connection string (default $FALX_DSN)")
	sources := fs.String("source", "", "sync: comma-separated sources (default all: kev, epss)")
	force := fs.Bool("force", false, "sync, enrich: fetch again even if the data is current")
	allowShrink := fs.Bool("allow-shrink", false, "sync: accept a feed with far fewer records than last time")
	limit := fs.Int("limit", 50, "search: how many results to show")
	org := fs.String("org", "", "enrich: organization whose findings to look up (default $FALX_ORG, then \"default\")")
	if err := parseFlags(fs, "fal-x intel "+sub+" [flags]", rest); err != nil {
		return err
	}

	if err := checkIntelArgs(sub, fs.NArg()); err != nil {
		return err
	}

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	switch sub {
	case "sync":
		return intelSync(ctx, db, *sources, intel.Options{Force: *force, AllowShrink: *allowShrink})
	case "enrich":
		return enrichFromNVD(ctx, db, orgSlug(*org), fs.Args(), *force)
	case "status":
		return intelStatus(ctx, db)
	case "show":
		return intelShow(ctx, db, fs.Arg(0))
	default:
		return intelSearch(ctx, db, strings.Join(fs.Args(), " "), *limit)
	}
}

// checkIntelArgs validates the subcommand and its argument count before any
// database work.
func checkIntelArgs(sub string, nargs int) error {
	switch sub {
	case "sync", "status", "enrich":
	case "show":
		if nargs != 1 {
			return logging.Usagef("usage: fal-x intel show <CVE-ID>")
		}
	case "search":
		if nargs < 1 {
			return logging.Usagef("usage: fal-x intel search <text>")
		}
	default:
		return logging.Usagef("unknown intel subcommand %q; usage: %s", sub, intelUsage)
	}
	return nil
}

func intelSync(ctx context.Context, db *store.DB, sources string, opts intel.Options) error {
	var names []string
	if sources != "" {
		names = strings.Split(sources, ",")
	}
	srcs, err := intel.Lookup(names)
	if err != nil {
		return logging.Usagef("%v", err)
	}

	failed := 0
	for _, src := range srcs {
		res, err := intel.Sync(ctx, db, src, opts)
		switch {
		case err != nil:
			failed++
			logging.Error("%s: %v", src.Name, err)
		case res.NotModified:
			logging.Ok("%s: already current, nothing downloaded", src.Name)
		default:
			note := ""
			if res.Skipped > 0 {
				note = fmt.Sprintf(", %d malformed row(s) skipped", res.Skipped)
			}
			logging.Ok("%s: %d record(s)%s, version %s, %s", src.Name, res.Records, note,
				orUnset(res.Version), res.Took.Round(time.Millisecond))
		}
	}
	if failed > 0 {
		return logging.Runtimef("%d source(s) failed to sync", failed)
	}
	return nil
}

func intelStatus(ctx context.Context, db *store.DB) error {
	return db.InTx(ctx, func(tx *sql.Tx) error {
		srcs, cves, err := intel.Status(ctx, tx)
		if err != nil {
			return logging.Runtimef("%v", err)
		}
		if len(srcs) == 0 {
			fmt.Println("nothing synced yet; run: fal-x intel sync")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "SOURCE\tRECORDS\tVERSION\tLAST SYNC")
		for _, s := range srcs {
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", s.Source, s.Records, orUnset(s.Version),
				s.SyncedAt.UTC().Format(time.RFC3339))
		}
		if err := w.Flush(); err != nil {
			return err
		}
		fmt.Printf("\n%d distinct CVE(s) known\n", cves)
		return nil
	})
}

func intelShow(ctx context.Context, db *store.DB, id string) error {
	return db.InTx(ctx, func(tx *sql.Tx) error {
		d, err := intel.Show(ctx, tx, id)
		if err != nil {
			return logging.Runtimef("%v", err)
		}
		printDetail(d)
		return nil
	})
}

func intelSearch(ctx context.Context, db *store.DB, text string, limit int) error {
	return db.InTx(ctx, func(tx *sql.Tx) error {
		hits, err := intel.Search(ctx, tx, text, limit)
		if err != nil {
			return logging.Runtimef("%v", err)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "CVE\tADDED\tEPSS\tVENDOR / PRODUCT\tNAME")
		for _, h := range hits {
			epss := "-"
			if h.EPSS != nil {
				epss = fmt.Sprintf("%.3f", *h.EPSS)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s / %s\t%s\n", h.CVE, h.DateAdded.Format(util.DateOnly),
				epss, h.Vendor, h.Product, h.Name)
		}
		return w.Flush()
	})
}

// printDetail renders one CVE. "Not in any source" and "in a source but not listed
// as exploited" are different statements and are worded differently.
func printDetail(d *intel.Detail) {
	fmt.Println(d.CVE)
	if !d.Known {
		fmt.Println("  not present in any synced source (run: fal-x intel sync)")
		return
	}
	if d.KEV != nil {
		k := d.KEV
		fmt.Printf("  CISA KEV   KNOWN EXPLOITED, added %s\n", k.DateAdded.Format(util.DateOnly))
		fmt.Printf("             %s / %s: %s\n", k.VendorProject, k.Product, k.Name)
		if k.KnownRansomware {
			fmt.Println("             used in ransomware campaigns")
		}
		if k.DueDate != nil {
			fmt.Printf("             remediation due %s\n", k.DueDate.Format(util.DateOnly))
		}
		fmt.Printf("             action: %s\n", k.RequiredAction)
	} else {
		fmt.Println("  CISA KEV   not listed")
	}
	if d.NVD != nil {
		n := d.NVD
		if n.CVSSScore != nil {
			fmt.Printf("  CVSS       %.1f %s (v%s)  %s\n", *n.CVSSScore, n.CVSSSeverity, n.CVSSVersion, n.CVSSVector)
		} else {
			fmt.Println("  CVSS       NVD has no score for it")
		}
		if n.Description != "" {
			fmt.Printf("  NVD        %s\n", firstLine(n.Description, 200))
		}
	} else {
		fmt.Println("  CVSS       not fetched (run: fal-x intel enrich " + d.CVE + ")")
	}
	if d.EPSS != nil {
		fmt.Printf("  EPSS       %.4f probability, %.1f%% percentile (model %s, %s)\n",
			d.EPSS.Score, d.EPSS.Percentile*100, d.EPSS.Model, d.EPSS.ScoreDate.Format(util.DateOnly))
	} else {
		fmt.Println("  EPSS       no score")
	}
}

// firstLine shortens text to at most n bytes on one line.
func firstLine(text string, n int) string {
	return util.Truncate(strings.Join(strings.Fields(text), " "), n)
}

// storedCVEs returns every CVE named in the organization's stored findings.
func storedCVEs(ctx context.Context, db *store.DB, slug string) ([]string, error) {
	var ids []string
	err := withOrg(ctx, db, slug, func(tx *sql.Tx) error {
		rows, err := store.ListFindings(ctx, tx)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, r := range rows {
			for _, id := range intel.CVEsIn(r.Value) {
				if !seen[id] {
					seen[id] = true
					ids = append(ids, id)
				}
			}
		}
		return nil
	})
	return ids, err
}

// enrichFromNVD fetches NVD detail for the CVEs named on the command line, or for
// every CVE in the organization's stored findings. NVD_API_KEY, if set, raises the
// rate limit; its value is never printed.
func enrichFromNVD(ctx context.Context, db *store.DB, slug string, args []string, force bool) error {
	ids := args
	if len(ids) == 0 {
		var err error
		if ids, err = storedCVEs(ctx, db, slug); err != nil {
			return err
		}
		if len(ids) == 0 {
			fmt.Println("no CVEs in the stored findings; name some: fal-x intel enrich CVE-2023-48795")
			return nil
		}
	}

	key := strings.TrimSpace(os.Getenv("NVD_API_KEY"))
	tier := "keyless"
	if key != "" {
		tier = "keyed"
	}
	logging.Info("looking up %d CVE(s) in NVD (about %s at the %s rate limit)",
		len(ids), (time.Duration(len(ids)) * intel.NVDDelay(key != "")).Round(time.Second), tier)

	res, err := intel.EnrichNVD(ctx, db, ids, intel.NVDOptions{
		APIKey: key, Force: force,
		Progress: func(id, outcome string) { logging.Ok("%s: %s", id, outcome) },
	})
	if err != nil {
		logging.Warn("stopped early: %v", err)
		logging.Info("kept %d record(s); run again to continue where it stopped", res.Fetched)
		return logging.Runtimef("%v", err)
	}
	logging.Ok("done: %d fetched, %d already fresh, %d not in NVD", res.Fetched, res.Fresh, res.NotInNVD)
	return nil
}
