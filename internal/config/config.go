// Package config holds the build version and locates the repository root.
package config

import (
	"os"
	"path/filepath"
)

// Version is set at build time with -ldflags "-X ...config.Version=...".
var Version = "0.2.0-dev"

// Home returns the repository root: FALX_HOME when set, otherwise the nearest
// directory above the working directory that holds go.mod, which works from
// cmd/fal-x, from internal/..., and from a test binary running anywhere in the tree.
func Home() string {
	if h := os.Getenv("FALX_HOME"); h != "" {
		return h
	}
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	dir := wd
	for range 6 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return wd
}
