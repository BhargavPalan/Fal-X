package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/run"
)

// newReportRun writes a real run directory with one finding, using only
// synthetic data.
func newReportRun(t *testing.T) string {
	t.Helper()
	r, err := run.Init(t.TempDir(), "example.com", "20261003-123456")
	if err != nil {
		t.Fatal(err)
	}
	r.SetTarget("example.com")
	_ = r.Stage("scan", func() error { return nil })
	if err := r.Finalise(); err != nil {
		t.Fatal(err)
	}
	scan := filepath.Join(r.Dir, "7-scan")
	if err := os.MkdirAll(scan, 0o750); err != nil {
		t.Fatal(err)
	}
	line := "[tmpl-a] [http] [high] http://example.com/a\n"
	if err := os.WriteFile(filepath.Join(scan, "findings.json"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	return r.Dir
}

// captureStdout runs fn and returns what it wrote to standard output.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = wr
	defer func() { os.Stdout = old }()
	fn()
	_ = wr.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := rd.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}

func TestReportCommand(t *testing.T) {
	dir := newReportRun(t)

	t.Run("json to a file", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "r.json")
		if err := runSubcommand(t, "report", []string{"--run", dir, "--format", "json", "--out", out}); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Findings struct {
				Items []struct{ Template string } `json:"items"`
			} `json:"findings"`
		}
		if err := json.Unmarshal(b, &doc); err != nil || len(doc.Findings.Items) != 1 {
			t.Fatalf("report JSON unusable: %v %s", err, b)
		}
	})

	t.Run("several formats into a directory", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "nested", "reports")
		if err := runSubcommand(t, "report", []string{"--run", dir, "--format", "md,json,sarif", "--out", out}); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"report.md", "report.json", "report.sarif"} {
			if _, err := os.Stat(filepath.Join(out, name)); err != nil {
				t.Errorf("%s not written: %v", name, err)
			}
		}
	})

	t.Run("markdown to stdout", func(t *testing.T) {
		var err error
		got := captureStdout(t, func() {
			err = runSubcommand(t, "report", []string{"--run", dir})
		})
		if err != nil || !strings.Contains(got, "# Fal-X report: example.com") {
			t.Fatalf("stdout report wrong (err %v):\n%s", err, got)
		}
	})

	t.Run("exit statuses", func(t *testing.T) {
		bad := runSubcommand(t, "report", []string{"--run", dir, "--format", "pdf"})
		if got := exitCode(bad); got != logging.StatusUsage {
			t.Errorf("unknown format exit = %d, want %d", got, logging.StatusUsage)
		}
		missing := runSubcommand(t, "report", []string{"--run", filepath.Join(t.TempDir(), "nope")})
		if got := exitCode(missing); got != logging.StatusRuntime {
			t.Errorf("missing run exit = %d, want %d", got, logging.StatusRuntime)
		}
		if err := runSubcommand(t, "report", []string{"--help"}); !errors.Is(err, errHelp) {
			t.Errorf("--help returned %v, want errHelp", err)
		}
	})
}

func TestWordlistsCommandUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"bogus"}} {
		err := runSubcommand(t, "wordlists", args)
		if got := exitCode(err); got != logging.StatusUsage {
			t.Errorf("wordlists %v exit = %d, want %d", args, got, logging.StatusUsage)
		}
	}
	if err := runSubcommand(t, "wordlists", []string{"fetch", "nope"}); exitCode(err) == logging.StatusOK {
		t.Error("fetching an unknown wordlist succeeded")
	}
}

func TestVersionJSON(t *testing.T) {
	var err error
	got := captureStdout(t, func() {
		err = runSubcommand(t, "version", []string{"--json"})
	})
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	if err := json.Unmarshal([]byte(got), &v); err != nil {
		t.Fatalf("version --json is not JSON: %v\n%s", err, got)
	}
	for _, k := range []string{"version", "go", "platform"} {
		if v[k] == "" {
			t.Errorf("version --json missing %q: %v", k, v)
		}
	}
}

func TestStubsNameTheirPhase(t *testing.T) {
	err := runSubcommand(t, "intel", nil)
	if exitCode(err) != logging.StatusUsage || !strings.Contains(err.Error(), "phase 2") {
		t.Errorf("intel stub: %v", err)
	}
	if strings.Contains(err.Error(), "docs/") {
		t.Errorf("stub points at a file the repo does not have: %v", err)
	}
}
