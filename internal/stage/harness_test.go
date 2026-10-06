package stage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/cli"
	"github.com/BhargavPalan/Fal-X/internal/net"
	"github.com/BhargavPalan/Fal-X/internal/run"
	"github.com/BhargavPalan/Fal-X/internal/scope"
	"github.com/BhargavPalan/Fal-X/internal/tools"
	"github.com/BhargavPalan/Fal-X/internal/util"
)

// fixtureRunner answers tool invocations from a recorded table and remembers
// what it was asked.
//
// Stages are tested against this rather than against real tools, so the suite
// needs no network and no binaries. It also lets a test assert the exact flags a
// stage passes, which is how the safety-relevant invocations are checked.
type fixtureRunner struct {
	mu sync.Mutex
	// responses maps "name arg arg" to stdout.
	responses map[string]string
	// missing names a tool as not installed.
	missing map[string]bool
	// calls records every invocation in order.
	calls []tools.Invocation
}

func newFixture() *fixtureRunner {
	return &fixtureRunner{
		responses: map[string]string{},
		missing:   map[string]bool{},
	}
}

// on registers stdout for an exact invocation.
func (f *fixtureRunner) on(name string, args []string, stdout string) *fixtureRunner {
	f.responses[name+" "+strings.Join(args, " ")] = stdout
	return f
}

// without marks a tool as not installed.
func (f *fixtureRunner) without(name string) *fixtureRunner {
	f.missing[name] = true
	return f
}

func (f *fixtureRunner) Run(_ context.Context, name string, args ...string) (tools.Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, tools.Invocation{Name: name, Args: append([]string(nil), args...)})
	table, recorded := f.responses[name+" "+strings.Join(args, " ")]
	absent := f.missing[name]
	f.mu.Unlock()

	if absent {
		return tools.Result{}, &tools.ExitError{Tool: name, Code: 127, Stderr: "not found"}
	}
	if recorded {
		return tools.Result{Stdout: table}, nil
	}
	return tools.Result{}, &tools.ExitError{
		Tool:   name,
		Code:   1,
		Stderr: "no recorded response for: " + name + " " + strings.Join(args, " "),
	}
}

func (f *fixtureRunner) Available(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.missing[name]
}

func (f *fixtureRunner) Missing(names ...string) []string {
	var out []string
	for _, n := range names {
		if !f.Available(n) {
			out = append(out, n)
		}
	}
	return out
}

// invocations returns the recorded calls, rendered for assertions.
func (f *fixtureRunner) invocations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		out = append(out, c.Line())
	}
	return out
}

// calledTool reports whether a tool was invoked at all.
func (f *fixtureRunner) calledTool(name string) bool {
	for _, line := range f.invocations() {
		if strings.HasPrefix(line, name+" ") || line == name {
			return true
		}
	}
	return false
}

// harness is a stage under test.
type harness struct {
	t     *testing.T
	env   *Env
	fx    *fixtureRunner
	dir   string
	paths Paths
}

// newHarness builds a stage environment with a scope allowing example.com and
// its subdomains, plus the RFC-5737 documentation range.
func newHarness(t *testing.T, allow, deny string) *harness {
	t.Helper()

	dir := t.TempDir()

	allowPath := filepath.Join(dir, "scope.txt")
	denyPath := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(allowPath, []byte(allow), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(denyPath, []byte(deny), 0o600); err != nil {
		t.Fatal(err)
	}

	sc := scope.New(false, false)
	if err := sc.Load(allowPath, denyPath); err != nil {
		t.Fatalf("scope load: %v", err)
	}

	paths := NewPaths(filepath.Join(dir, "run"))
	if err := paths.Ensure(); err != nil {
		t.Fatalf("paths: %v", err)
	}

	r, err := run.Init(paths.Dir, "example.com", "20261003-123456")
	if err != nil {
		t.Fatalf("run init: %v", err)
	}
	r.SetTarget("example.com")

	opts, err := cli.Parse(
		"-d", "example.com",
		"--scope", allowPath,
		"--exclude", denyPath,
		"--threads", "10",
		"--jobs", "4",
		"--ports", "80,443,8443",
	)
	if err != nil {
		t.Fatalf("cli parse: %v", err)
	}

	fx := newFixture()

	return &harness{
		t:   t,
		dir: dir,
		fx:  fx,
		env: &Env{
			Run:   r,
			Gate:  net.New(sc),
			Tools: fx,
			Opts:  opts,
			Paths: paths,
		},
		paths: paths,
	}
}

// seed writes a stage input file.
func (h *harness) seed(path, content string) {
	h.t.Helper()
	if err := util.WriteLines(path, strings.Split(strings.TrimSuffix(content, "\n"), "\n")); err != nil {
		h.t.Fatal(err)
	}
}

// read returns the lines of a stage output file.
func (h *harness) read(path string) []string {
	h.t.Helper()
	lines, ok := util.ReadLines(path)
	if !ok {
		return nil
	}
	return lines
}

// mustExist asserts that a file is present, even when it is empty.
func (h *harness) mustExist(path, why string) {
	h.t.Helper()
	if _, err := os.Stat(path); err != nil {
		h.t.Errorf("%s was not created: %v (%s)", filepath.Base(path), err, why)
	}
}

// runStage executes a stage and returns its error.
func (h *harness) runStage(name string, fn func(context.Context, *Env) error) error {
	h.t.Helper()
	return h.env.Run.Stage(name, func() error { return fn(context.Background(), h.env) })
}

// standardScope is the fixture most tests use.
const (
	standardAllow = "example.com\n*.wild.test\n192.0.2.0/24\n2001:db8::1\n"
	standardDeny  = "admin.example.com\n*.dev.test\n192.0.2.8\n"
)
