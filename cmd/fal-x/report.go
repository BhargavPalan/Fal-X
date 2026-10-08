package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/config"
	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/report"
)

// runReport renders a finished run as Markdown, JSON or SARIF.
//
// It only reads files the run already wrote, so it contacts nothing and needs no
// scope: producing a report cannot widen what was scanned.
func runReport(_ context.Context, args []string) error {
	fs := flagSet("report")
	runDir := fs.String("run", "", "run directory (default: the newest run under --output)")
	target := fs.String("target", "", "newest run of this target (used when --run is not given)")
	formats := fs.String("format", "md", "md, json or sarif; comma-separated for several")
	out := fs.String("out", "", "write to this file (one format), or into this directory (several)")
	root := fs.String("output", filepath.Join(config.Home(), "output"), "output root to search for runs")
	if err := parseFlags(fs, "fal-x report [--run <dir> | --target <t>] [--format md,json,sarif] [--out <path>]", args); err != nil {
		return err
	}

	var fmts []report.Format
	for _, name := range strings.Split(*formats, ",") {
		f, err := report.ParseFormat(name)
		if err != nil {
			return logging.Usagef("%v", err)
		}
		fmts = append(fmts, f)
	}

	dir := *runDir
	if dir == "" {
		d, err := report.Latest(*root, *target)
		if err != nil {
			return logging.Runtimef("%v", err)
		}
		dir = d
	}

	m, err := report.Load(dir)
	if err != nil {
		return logging.Runtimef("%v", err)
	}

	// One format with no --out goes to stdout so it can be piped. Several formats
	// need somewhere to land, so they are written beside the run.
	if len(fmts) == 1 && *out == "" {
		b, err := report.Render(m, fmts[0])
		if err != nil {
			return logging.Runtimef("%v", err)
		}
		_, err = os.Stdout.Write(b)
		return err
	}

	for _, f := range fmts {
		b, err := report.Render(m, f)
		if err != nil {
			return logging.Runtimef("%v", err)
		}
		path := outputPath(*out, dir, f, len(fmts) > 1)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return logging.Runtimef("could not create %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return logging.Runtimef("could not write %s: %v", path, err)
		}
		logging.Ok("wrote %s", path)
	}
	return nil
}

// outputPath decides where one rendered format is written.
func outputPath(out, runDir string, f report.Format, several bool) string {
	name := fmt.Sprintf("report.%s", f.Extension())
	switch {
	case out == "":
		return filepath.Join(runDir, name)
	case several:
		return filepath.Join(out, name)
	default:
		return out
	}
}
