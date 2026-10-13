package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/engine"
	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/recon"
)

// runScan drives the self-driving recon engine against one or more seeds, writing
// everything it finds into the entity graph. It is the scan command.
func runScan(ctx context.Context, args []string) error {
	fs := flagSet("scan")
	dsn := fs.String("dsn", "", "Postgres connection string (default $FALX_DSN)")
	org := fs.String("org", "", "organization slug (default $FALX_ORG, then \"default\")")
	mode := fs.String("mode", "active", "passive (no packets to the target), active, or full")
	depth := fs.Int("depth", 2, "how many hops from a seed the engine may follow (0 = unbounded)")
	budget := fs.Int("budget", 2000, "total source-call budget (0 = unbounded)")
	fanout := fs.Int("max-fanout", 1000, "cap on new entities enqueued per source call (0 = unbounded)")
	dryRun := fs.Bool("dry-run", false, "print what would run and contact nothing")
	quiet := fs.Bool("quiet", false, "log errors only")
	debug := fs.Bool("debug", false, "verbose internal logging")
	asJSON := fs.Bool("json", false, "machine-readable logging")
	if err := parseFlags(fs, "fal-x scan <domain|host|ip|cidr|asn>... [--mode] [--depth N] [--budget N] [--org slug]", args); err != nil {
		return err
	}

	passiveOnly := false
	switch *mode {
	case "passive":
		passiveOnly = true
	case "active", "full":
	default:
		return logging.Usagef("unknown mode %q (expected passive, active or full)", *mode)
	}

	var seeds []graph.Seed
	for _, a := range fs.Args() {
		seeds = append(seeds, seedsFor(a)...)
	}
	if len(seeds) == 0 {
		return logging.Usagef("scan needs at least one target (domain, host, IP, CIDR or ASN)")
	}

	// Logging flags work after the command name too, so "fal-x scan host --quiet"
	// behaves as expected.
	applyLogging(&globals{debug: *debug, quiet: *quiet, json: *asJSON})

	if *dryRun {
		printScanPlan(seeds, *mode, *depth, *budget, *fanout)
		return nil
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

	logging.Info("scan starting: %d seed(s), mode %s", len(seeds), *mode)
	stats, err := recon.Run(ctx, scoped, id, recon.Options{
		Seeds:       seeds,
		Brake:       engine.Brake{MaxDepth: *depth, Budget: *budget, MaxFanout: *fanout},
		PassiveOnly: passiveOnly,
		Full:        *mode == "full",
	})
	if err != nil {
		return logging.Runtimef("%v", err)
	}

	logging.Ok("scan complete: %d entities worked, %d source runs, %d discovered, %d source error(s)",
		stats.Jobs, stats.Collects, stats.Produced, stats.Errors)
	return summarizeGraph(ctx, scoped)
}

// summarizeGraph prints the entity counts by type after a run.
func summarizeGraph(ctx context.Context, db interface {
	InTx(context.Context, func(*sql.Tx) error) error
}) error {
	var counts map[graph.EntityType]int
	if err := db.InTx(ctx, func(tx *sql.Tx) error {
		var err error
		counts, err = graph.CountByType(ctx, tx)
		return err
	}); err != nil {
		return logging.Runtimef("%v", err)
	}
	if len(counts) == 0 {
		return nil
	}
	types := make([]string, 0, len(counts))
	for t := range counts {
		types = append(types, string(t))
	}
	sort.Strings(types)
	fmt.Println("\ngraph:")
	for _, t := range types {
		fmt.Printf("  %-14s %d\n", t, counts[graph.EntityType(t)])
	}
	return nil
}

// seedsFor classifies a raw target into one or more typed seeds. An address is an
// IP, a prefix is a netblock, ASnnnn is an ASN. A name is seeded as both a host (to
// resolve) and a domain (to enumerate subdomains from certificate transparency), so
// one target drives both discovery paths without the operator choosing.
func seedsFor(raw string) []graph.Seed {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return []graph.Seed{{Type: graph.TypeIP, Key: s}}
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return []graph.Seed{{Type: graph.TypeNetblock, Key: s}}
	}
	if up := strings.ToUpper(s); strings.HasPrefix(up, "AS") && allDigits(up[2:]) {
		return []graph.Seed{{Type: graph.TypeASN, Key: s}}
	}
	return []graph.Seed{{Type: graph.TypeHost, Key: s}, {Type: graph.TypeDomain, Key: s}}
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// printScanPlan shows what a scan would do, for --dry-run. It opens no database and
// contacts nothing.
func printScanPlan(seeds []graph.Seed, mode string, depth, budget, fanout int) {
	fmt.Println("scan plan (dry run, nothing will be contacted):")
	fmt.Printf("  mode: %s\n", mode)
	fmt.Printf("  depth: %s   budget: %s   max-fanout: %s\n",
		unbounded(depth), unbounded(budget), unbounded(fanout))
	fmt.Printf("  targets (%d):\n", len(seeds))
	for _, s := range seeds {
		fmt.Printf("    %-8s %s\n", s.Type, s.Key)
	}
	var names []string
	for _, src := range recon.DefaultRegistry().All() {
		c := src.Capability()
		if mode == "passive" && !c.Passive {
			continue
		}
		names = append(names, c.Name)
	}
	sort.Strings(names)
	fmt.Printf("  sources: %s\n", strings.Join(names, ", "))
}

// unbounded renders a brake dimension, showing 0 as "unbounded".
func unbounded(n int) string {
	if n <= 0 {
		return "unbounded"
	}
	return strconv.Itoa(n)
}
