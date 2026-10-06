package main

import (
	"context"
	"os"

	"github.com/BhargavPalan/Fal-X/internal/installer"
	"github.com/BhargavPalan/Fal-X/internal/logging"
)

// runInstall installs the external reconnaissance tools for the host platform.
//
// The Go toolchain builds each tool for the running OS and architecture, so one
// command serves Linux, macOS and Windows on amd64, arm64 and the rest without
// any per-platform selection here.
func runInstall(ctx context.Context, args []string) error {
	fs := flagSet("install")
	check := fs.Bool("check", false, "report which tools are present and missing, install nothing")
	withOpt := fs.Bool("with-opt", false, "also install the optional-stage tools (amass, puredns)")
	setup := fs.Bool("setup", false, "only create the local config files; install no tools")
	if err := parseFlags(fs, "fal-x install [--check] [--with-opt] [--setup]", args); err != nil {
		return err
	}

	if *setup {
		return installer.Setup(os.Stdout)
	}

	if *check {
		if installer.Check(os.Stdout, *withOpt) > 0 {
			return logging.Runtimef("some tools are missing; install them with: fal-x install")
		}
		return nil
	}

	return installer.Install(ctx, installer.Options{WithOpt: *withOpt, Out: os.Stdout})
}
