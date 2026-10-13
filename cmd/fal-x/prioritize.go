package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/prioritize"
)

// runPrioritize ranks the stored findings by urgency and shows its working.
func runPrioritize(ctx context.Context, args []string) error {
	fs := flagSet("prioritize")
	dsn := fs.String("dsn", "", "Postgres connection string (default $FALX_DSN)")
	org := fs.String("org", "", "organization slug (default $FALX_ORG, then \"default\")")
	top := fs.Int("top", 20, "how many findings to show (0 shows all)")
	noMatches := fs.Bool("no-matches", false, "rank only what the scanner reported, not CVEs inferred from the software each asset runs")
	explain := fs.Bool("explain", false, "print the full derivation of each score")
	asJSON := fs.Bool("json", false, "shorthand for --format json")
	format := fs.String("format", "table", "table, md (a document to hand over, with every derivation) or json")
	out := fs.String("out", "", "write md or json to this file instead of standard output")
	if err := parseFlags(fs, "fal-x prioritize [--top N] [--explain] [--no-matches] [--format table|md|json] [--out file] [--org slug]", args); err != nil {
		return err
	}
	if *asJSON {
		*format = "json"
	}
	switch *format {
	case "table", "md", "json":
	default:
		return logging.Usagef("unknown format %q (expected table, md or json)", *format)
	}
	if *out != "" && *format == "table" {
		return logging.Usagef("--out needs --format md or json; the table is for the terminal")
	}
	if fs.NArg() != 0 {
		return logging.Usagef("prioritize takes no arguments, got %q", fs.Arg(0))
	}

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	var ranked []prioritize.Ranked
	if err := withOrg(ctx, db, orgSlug(*org), func(tx *sql.Tx) error {
		var err error
		if *noMatches {
			ranked, err = prioritize.Rank(ctx, tx)
		} else {
			ranked, err = prioritize.RankAll(ctx, tx)
		}
		return err
	}); err != nil {
		return err
	}
	total := len(ranked)
	if *top > 0 && len(ranked) > *top {
		ranked = ranked[:*top]
	}

	switch *format {
	case "md":
		return writeOut(*out, prioritize.RenderMarkdown(ranked, total, time.Now()))
	case "json":
		b, err := rankedJSON(ranked)
		if err != nil {
			return err
		}
		return writeOut(*out, b)
	}
	return printRanked(ranked, total, *explain)
}

// rankedJSON is the machine-readable form: every score with the reasons behind it.
func rankedJSON(ranked []prioritize.Ranked) ([]byte, error) {
	type reason struct {
		Signal string `json:"signal"`
		Points int    `json:"points"`
		Detail string `json:"detail"`
	}
	type item struct {
		Rank     int      `json:"rank"`
		Source   string   `json:"source"`
		Score    int      `json:"score"`
		Decision string   `json:"decision"`
		Asset    string   `json:"asset"`
		Kind     string   `json:"kind"`
		Severity string   `json:"severity"`
		Template string   `json:"template"`
		CVE      string   `json:"cve,omitempty"`
		Why      []reason `json:"why"`
	}
	items := make([]item, 0, len(ranked))
	for i, r := range ranked {
		it := item{Rank: i + 1, Source: r.Source, Score: r.Result.Score, Decision: r.Result.Decision, Asset: r.Asset,
			Kind: r.Kind, Severity: r.Finding.Severity, Template: r.Finding.Template, CVE: r.Finding.CVE}
		for _, w := range r.Result.Why {
			it.Why = append(it.Why, reason{w.Signal, w.Points, w.Detail})
		}
		items = append(items, it)
	}
	b, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// printRanked writes the terminal table; total is the count before --top trimmed it.
func printRanked(ranked []prioritize.Ranked, total int, explain bool) error {
	if total == 0 {
		fmt.Println("no findings stored; scan with FALX_DSN set, or run: fal-x assets import --from <run directory>")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "#\tSCORE\tDECISION\tASSET\tSEVERITY\tFINDING")
	for i, r := range ranked {
		fmt.Fprintf(w, "%d\t%d\t%s\t%s\t%s\t%s\n", i+1, r.Result.Score, r.Result.Decision,
			r.Asset, r.Finding.Severity, r.Finding.Template)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if len(ranked) < total {
		fmt.Printf("\nshowing %d of %d findings (--top 0 shows all)\n", len(ranked), total)
	}
	if !explain {
		fmt.Println("\nuse --explain to see how each score was reached")
		return nil
	}
	for i, r := range ranked {
		fmt.Printf("\n#%d  %s  %s  (%s)  score %d, %s\n", i+1, r.Asset, r.Finding.Template,
			r.Finding.Severity, r.Result.Score, r.Result.Decision)
		for _, why := range r.Result.Why {
			fmt.Printf("    %+4d  %-18s %s\n", why.Points, why.Signal, why.Detail)
		}
	}
	return nil
}

// writeOut writes a rendered document to a file, or to standard output when no
// file is named. A file is created 0600: it can name vulnerable assets.
func writeOut(path string, b []byte) error {
	if path == "" {
		_, err := os.Stdout.Write(b)
		return err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return logging.Runtimef("could not write %s: %v", path, err)
	}
	logging.Ok("wrote %s", path)
	return nil
}
