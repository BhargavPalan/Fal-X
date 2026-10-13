package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/attackpath"
	"github.com/BhargavPalan/Fal-X/internal/logging"
)

// runPaths ranks the attack paths from a seed to a crown jewel, and the choke points
// that cut the most paths.
func runPaths(ctx context.Context, args []string) error {
	fs := flagSet("paths")
	dsn := fs.String("dsn", "", "Postgres connection string (default $FALX_DSN)")
	org := fs.String("org", "", "organization slug (default $FALX_ORG, then \"default\")")
	top := fs.Int("top", 20, "how many paths to show")
	explain := fs.Bool("explain", false, "print each path hop by hop with its risk derivation")
	chokes := fs.Bool("chokes", false, "show the choke points that lie on the most paths")
	if err := parseFlags(fs, "fal-x paths [--explain] [--chokes] [--top N] [flags]", args); err != nil {
		return err
	}

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	return withOrg(ctx, db, orgSlug(*org), func(tx *sql.Tx) error {
		g, err := attackpath.Load(ctx, tx)
		if err != nil {
			return err
		}
		// `paths blast <asset>` shows the blast radius of one asset instead of ranking.
		if args := fs.Args(); len(args) >= 1 && args[0] == "blast" {
			if len(args) < 2 {
				return logging.Usagef("usage: fal-x paths blast <asset-key>")
			}
			return printBlast(g, args[1])
		}
		paths := attackpath.Analyze(g)
		if len(paths) == 0 {
			logging.Info("no attack paths found: need a seed (entry) and a reachable crown jewel")
			return nil
		}
		if *chokes {
			printChokes(attackpath.Chokes(paths))
			return nil
		}
		shown := min(*top, len(paths))
		fmt.Printf("%d attack path(s); showing %d\n\n", len(paths), shown)
		for i, p := range paths[:shown] {
			fmt.Printf("%2d. [%d %s] %s\n", i+1, p.Risk, p.Decision, pathLine(p))
			if *explain {
				for _, h := range p.Hops {
					arrow := "   entry"
					if h.Rel != "" {
						arrow = "   --" + h.Rel + "-->"
					}
					fmt.Printf("%s %s (%s)\n", arrow, h.Key, h.Type)
				}
				for _, r := range p.Reasons {
					fmt.Printf("     %s\n", r)
				}
				fmt.Println()
			}
		}
		return nil
	})
}

// pathLine renders a path as "entry -> ... -> jewel".
func pathLine(p attackpath.Path) string {
	parts := make([]string, len(p.Hops))
	for i, h := range p.Hops {
		parts[i] = h.Key
	}
	return strings.Join(parts, " -> ")
}

// printBlast prints the blast radius of one asset: everything reachable from it.
func printBlast(g *attackpath.Graph, key string) error {
	id, ok := g.NodeByKey(key)
	if !ok {
		return logging.Runtimef("no asset named %q in the graph", key)
	}
	reach := attackpath.Blast(g, id)
	fmt.Printf("blast radius of %s: %d asset(s) reachable\n", key, len(reach))
	for _, rid := range reach {
		if n := g.Nodes[rid]; n != nil {
			fmt.Printf("  %s (%s)\n", n.Key, n.Type)
		}
	}
	return nil
}

// printChokes prints the ranked choke points.
func printChokes(chokes []attackpath.Choke) {
	if len(chokes) == 0 {
		logging.Info("no choke points: paths do not share intermediate assets")
		return
	}
	fmt.Println("choke points (assets on the most attack paths):")
	for _, c := range chokes {
		fmt.Printf("  %3d paths  %s (%s)\n", c.PathsCut, c.Key, c.Type)
	}
}
