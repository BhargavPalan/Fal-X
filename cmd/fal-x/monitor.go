package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/engine"
	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/monitor"
	"github.com/BhargavPalan/Fal-X/internal/recon"
)

// runMonitor re-scans one or more seeds on a schedule and reports what changed since the
// previous scan, alerting to standard output and an optional webhook.
func runMonitor(ctx context.Context, args []string) error {
	fs := flagSet("monitor")
	dsn := fs.String("dsn", "", "Postgres connection string (default $FALX_DSN)")
	org := fs.String("org", "", "organization slug (default $FALX_ORG, then \"default\")")
	mode := fs.String("mode", "active", "passive (no packets to the target), active, or full")
	depth := fs.Int("depth", 2, "how many hops from a seed the engine may follow (0 = unbounded)")
	budget := fs.Int("budget", 2000, "total source-call budget (0 = unbounded)")
	fanout := fs.Int("max-fanout", 1000, "cap on new entities enqueued per source call (0 = unbounded)")
	interval := fs.Duration("interval", 0, "re-scan every interval, e.g. 6h (0 = run once and exit)")
	webhook := fs.String("webhook", "", "POST change events as JSON to this URL")
	quiet := fs.Bool("quiet", false, "log errors only")
	debug := fs.Bool("debug", false, "verbose internal logging")
	asJSON := fs.Bool("json", false, "machine-readable logging")
	if err := parseFlags(fs, "fal-x monitor <domain|host|ip|cidr|asn>... [--interval 6h] [--webhook url] [--mode] [--org slug]", args); err != nil {
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
		return logging.Usagef("monitor needs at least one target (domain, host, IP, CIDR or ASN)")
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

	opts := recon.Options{
		Seeds:       seeds,
		Brake:       engine.Brake{MaxDepth: *depth, Budget: *budget, MaxFanout: *fanout},
		PassiveOnly: passiveOnly,
		Full:        *mode == "full",
	}
	client := &http.Client{Timeout: 15 * time.Second}

	for {
		// Capture the cutoff from the database clock before the scan, so "changed since the
		// previous run" is exactly what this scan newly discovers, regardless of any skew
		// between the application host clock and the database host clock.
		cutoff, err := scoped.Now(ctx)
		if err != nil {
			return logging.Runtimef("%v", err)
		}
		logging.Info("monitor: scanning %d seed(s), mode %s", len(seeds), *mode)
		if _, err := recon.Run(ctx, scoped, id, opts); err != nil {
			return logging.Runtimef("%v", err)
		}
		events, err := monitor.Cycle(ctx, scoped, cutoff, 500)
		if err != nil {
			return logging.Runtimef("%v", err)
		}
		fmt.Println(monitor.Format(events))
		if *webhook != "" {
			if err := monitor.Webhook(ctx, client, *webhook, events); err != nil {
				logging.Warn("monitor: webhook: %v", err)
			}
		}
		logging.Ok("monitor: cycle complete, %d change(s)", len(events))

		if *interval <= 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(*interval):
		}
	}
}
