package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHomeHonoursEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FALX_HOME", dir)
	if got := Home(); got != dir {
		t.Errorf("Home() = %q, want %q", got, dir)
	}
}

func TestHomeFindsModuleRoot(t *testing.T) {
	t.Setenv("FALX_HOME", "")
	got := Home()
	if _, err := os.Stat(filepath.Join(got, "go.mod")); err != nil {
		t.Fatalf("Home() = %q, which has no go.mod: %v", got, err)
	}
}
