package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/logging"
)

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

// TestStubsSayOnlyThatTheyAreNotAvailable pins that a command that is not built says
// so plainly and nothing more. An earlier message told users which internal
// planning stage a feature belonged to, which is the project plan leaking into the
// product. The words checked for below are the ones that gave it away.
func TestStubsSayOnlyThatTheyAreNotAvailable(t *testing.T) {
	for _, name := range []string{"exploit", "session", "serve"} {
		err := runSubcommand(t, name, nil)
		if exitCode(err) != logging.StatusUsage {
			t.Errorf("%s: exit %d, want %d", name, exitCode(err), logging.StatusUsage)
			continue
		}
		msg := err.Error()
		if !strings.Contains(msg, name+" is not available yet") {
			t.Errorf("%s: %q does not say the command is not available", name, msg)
		}
		for _, leak := range []string{"phase", "roadmap", "docs/", "lands in"} {
			if strings.Contains(strings.ToLower(msg), leak) {
				t.Errorf("%s: the message leaks internal planning (%q): %s", name, leak, msg)
			}
		}
	}
}

func TestIntelCommandUsage(t *testing.T) {
	t.Setenv("FALX_DSN", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("PGDSN", "")
	for _, args := range [][]string{nil, {"bogus"}, {"show"}, {"search"}} {
		err := runSubcommand(t, "intel", args)
		if got := exitCode(err); got != logging.StatusUsage {
			t.Errorf("intel %v exit = %d, want %d (%v)", args, got, logging.StatusUsage, err)
		}
	}
	err := runSubcommand(t, "intel", []string{"status"})
	if exitCode(err) != logging.StatusUsage || !strings.Contains(err.Error(), "FALX_DSN") {
		t.Errorf("intel status without a DSN: %v", err)
	}
}

func TestAssetsCommandUsage(t *testing.T) {
	t.Setenv("FALX_DSN", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("PGDSN", "")

	for _, args := range [][]string{nil, {"bogus"}, {"import"}, {"show"}} {
		err := runSubcommand(t, "assets", args)
		if got := exitCode(err); got != logging.StatusUsage {
			t.Errorf("assets %v exit = %d, want %d (%v)", args, got, logging.StatusUsage, err)
		}
	}
	// With the arguments right but no database configured, it asks for one.
	err := runSubcommand(t, "assets", []string{"list"})
	if exitCode(err) != logging.StatusUsage || !strings.Contains(err.Error(), "FALX_DSN") {
		t.Errorf("assets list without a DSN: %v", err)
	}
}

func TestOrgSlugPrecedence(t *testing.T) {
	t.Setenv("FALX_ORG", "")
	if got := orgSlug(""); got != defaultOrg {
		t.Errorf("default org = %q", got)
	}
	t.Setenv("FALX_ORG", "fromenv")
	if got := orgSlug(""); got != "fromenv" {
		t.Errorf("env org = %q", got)
	}
	if got := orgSlug("fromflag"); got != "fromflag" {
		t.Errorf("flag must beat env, got %q", got)
	}
}

// TestFlagsMeanTheSameAnywhere pins that a flag typed after a positional argument
// is still a flag. The flag package stops at the first positional, so
// "intel search fortinet --limit 3" would otherwise search for the literal text
// "fortinet --limit 3" and find nothing.
func TestFlagsMeanTheSameAnywhere(t *testing.T) {
	newFS := func() *flag.FlagSet {
		fs := flagSet("t")
		fs.String("dsn", "", "")
		fs.Int("limit", 50, "")
		fs.Bool("force", false, "")
		return fs
	}
	cases := []struct {
		name string
		in   []string
		want string // flags, then positionals, as flagsFirst orders them
	}{
		{"flag last", []string{"fortinet", "--limit", "3"}, "--limit 3 fortinet"},
		{"flag first", []string{"--limit", "3", "fortinet"}, "--limit 3 fortinet"},
		{"bool flag takes no value", []string{"a", "--force", "b"}, "--force a b"},
		{"attached value", []string{"a", "--limit=7", "b"}, "--limit=7 a b"},
		{"double dash ends flags", []string{"--force", "--", "--limit", "x"}, "--force -- --limit x"},
		{"unknown flag left for Parse to reject", []string{"a", "--nope"}, "--nope a"},
	}
	for _, tc := range cases {
		got := strings.Join(flagsFirst(newFS(), tc.in), " ")
		if got != tc.want {
			t.Errorf("%s: flagsFirst(%v) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}

	fs := newFS()
	if err := parseFlags(fs, "t", []string{"fortinet", "--limit", "3"}); err != nil {
		t.Fatal(err)
	}
	if fs.Lookup("limit").Value.String() != "3" || fs.NArg() != 1 || fs.Arg(0) != "fortinet" {
		t.Errorf("limit=%s args=%v, want 3 and [fortinet]", fs.Lookup("limit").Value, fs.Args())
	}
}

func TestPrioritizeCommandUsage(t *testing.T) {
	t.Setenv("FALX_DSN", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("PGDSN", "")

	if err := runSubcommand(t, "prioritize", []string{"extra"}); exitCode(err) != logging.StatusUsage {
		t.Errorf("an unexpected argument: exit %d (%v)", exitCode(err), err)
	}
	err := runSubcommand(t, "prioritize", nil)
	if exitCode(err) != logging.StatusUsage || !strings.Contains(err.Error(), "FALX_DSN") {
		t.Errorf("prioritize without a DSN: %v", err)
	}
	if err := runSubcommand(t, "prioritize", []string{"--help"}); !errors.Is(err, errHelp) {
		t.Errorf("--help returned %v", err)
	}
}

func TestAssetsCriticalityArguments(t *testing.T) {
	t.Setenv("FALX_DSN", "")
	for _, args := range [][]string{
		{"criticality"},
		{"criticality", "host"},
		{"criticality", "host", "abc"},
		{"criticality", "host", "101"},
		{"criticality", "host", "-1"},
	} {
		err := runSubcommand(t, "assets", args)
		if exitCode(err) != logging.StatusUsage {
			t.Errorf("assets %v exit = %d, want %d (%v)", args, exitCode(err), logging.StatusUsage, err)
		}
	}
}

func TestIntelEnrichNeedsADatabase(t *testing.T) {
	t.Setenv("FALX_DSN", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("PGDSN", "")
	err := runSubcommand(t, "intel", []string{"enrich", "CVE-2023-48795"})
	if exitCode(err) != logging.StatusUsage || !strings.Contains(err.Error(), "FALX_DSN") {
		t.Errorf("intel enrich without a DSN: %v", err)
	}
}

func TestPrioritizeFormatValidation(t *testing.T) {
	t.Setenv("FALX_DSN", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("PGDSN", "")

	err := runSubcommand(t, "prioritize", []string{"--format", "pdf"})
	if exitCode(err) != logging.StatusUsage || !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("an unknown format: %v", err)
	}
	// The table is for the terminal, so a file for it is a usage mistake.
	err = runSubcommand(t, "prioritize", []string{"--out", "x.md"})
	if exitCode(err) != logging.StatusUsage || !strings.Contains(err.Error(), "--format md or json") {
		t.Errorf("--out with the table: %v", err)
	}
	// Both valid formats get as far as asking for a database.
	for _, f := range []string{"md", "json"} {
		err := runSubcommand(t, "prioritize", []string{"--format", f})
		if exitCode(err) != logging.StatusUsage || !strings.Contains(err.Error(), "FALX_DSN") {
			t.Errorf("--format %s without a DSN: %v", f, err)
		}
	}
}

// TestScanLoggingFlagsAreHonoured pins that --quiet, --debug and --json work after
// the subcommand name as well as before it. They were parsed into the options and
// never applied, so "fal-x scan example.com --quiet" ran at full volume.
func TestScanLoggingFlagsAreHonoured(t *testing.T) {
	logOnce := func(t *testing.T, flag string) string {
		t.Helper()
		var buf bytes.Buffer
		logging.SetOutputs(&buf, &buf)
		logging.SetLevel(logging.LevelInfo)
		logging.SetJSON(false)
		logging.SetTimestamps(true)
		t.Cleanup(func() {
			logging.SetOutputs(os.Stdout, os.Stderr)
			logging.SetLevel(logging.LevelInfo)
			logging.SetJSON(false)
		})

		// A dry run contacts nothing and prints the plan, so it is safe to run.
		captureStdout(t, func() {
			_ = runSubcommand(t, "scan", []string{"example.com", "--dry-run", flag})
		})
		logging.Info("an info line")
		logging.Debug("a debug line")
		logging.Error("an error line")
		return buf.String()
	}

	if got := logOnce(t, "--quiet"); strings.Contains(got, "an info line") || !strings.Contains(got, "an error line") {
		t.Errorf("--quiet should hide info and keep errors:\n%s", got)
	}
	if got := logOnce(t, "--debug"); !strings.Contains(got, "a debug line") {
		t.Errorf("--debug should show debug lines:\n%s", got)
	}
	got := logOnce(t, "--json")
	if !strings.Contains(got, `"msg":"an info line"`) {
		t.Errorf("--json should switch the log to JSON:\n%s", got)
	}
}
