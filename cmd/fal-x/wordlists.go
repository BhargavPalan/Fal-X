package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/BhargavPalan/Fal-X/internal/config"
	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/wordlists"
)

// runWordlists lists or fetches the open-source wordlists the brute-force stages use.
func runWordlists(ctx context.Context, args []string) error {
	const usage = "fal-x wordlists <list|fetch> [--force] [name...]"
	if len(args) == 0 {
		return logging.Usagef("usage: %s", usage)
	}
	sub, rest := args[0], args[1:]
	dir := filepath.Join(config.Home(), "wordlists")

	switch sub {
	case "list":
		wordlists.List(os.Stdout, dir)
		return nil
	case "fetch":
		fs := flagSet("wordlists fetch")
		force := fs.Bool("force", false, "replace files that already exist")
		if err := parseFlags(fs, "fal-x wordlists fetch [--force] [name...]", rest); err != nil {
			return err
		}
		if err := wordlists.Fetch(ctx, wordlists.Options{
			Dir: dir, Only: fs.Args(), Force: *force, Out: os.Stdout,
		}); err != nil {
			return logging.Runtimef("%v", err)
		}
		return nil
	default:
		return logging.Usagef("unknown subcommand %q; usage: %s", sub, usage)
	}
}
