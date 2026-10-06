package installer

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSelectedRespectsWithOpt checks that optional tools appear only with the
// opt-in flag, so a default install does not pull in the opt-stage binaries.
func TestSelectedRespectsWithOpt(t *testing.T) {
	core := selected(false)
	for _, tool := range core {
		if tool.Optional {
			t.Errorf("optional tool %q in the default set", tool.Name)
		}
	}
	all := selected(true)
	if len(all) <= len(core) {
		t.Fatalf("with-opt (%d) should exceed core (%d)", len(all), len(core))
	}
}

// TestToolsAreWellFormed guards against a malformed row in the table.
func TestToolsAreWellFormed(t *testing.T) {
	for _, tool := range Tools {
		if tool.Pkg == "" || tool.Name == "" {
			t.Errorf("tool %+v is missing a field", tool)
		}
		if !strings.Contains(tool.Pkg, "/") {
			t.Errorf("tool %q package %q is not a module path", tool.Name, tool.Pkg)
		}
	}
}

// TestSetupIsIdempotentAndNeverOverwrites checks that Setup creates scope.txt
// once and then leaves an operator's file untouched on a second run.
func TestSetupIsIdempotentAndNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := Setup(&buf); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	scope := filepath.Join("config", "scope.txt")
	if _, err := os.Stat(scope); err != nil {
		t.Fatalf("scope.txt not created: %v", err)
	}

	// An operator's edit must survive a second run.
	if err := os.WriteFile(scope, []byte("example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := Setup(&buf); err != nil {
		t.Fatalf("second Setup: %v", err)
	}
	got, _ := os.ReadFile(scope)
	if string(got) != "example.com\n" {
		t.Errorf("Setup overwrote an existing scope.txt: %q", got)
	}
	if !strings.Contains(buf.String(), "already exists") {
		t.Errorf("second run should report the file was left alone, got %q", buf.String())
	}
}
