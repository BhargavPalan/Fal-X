package tools

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRunner answers from a recorded table and records every invocation.
type fakeRunner struct {
	mu    sync.Mutex
	table map[string]string
	calls []Invocation
}

func newFake(responses map[string]string) *fakeRunner {
	return &fakeRunner{table: responses}
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, Invocation{Name: name, Args: append([]string(nil), args...)})

	key := name + " " + strings.Join(args, " ")
	out, ok := f.table[key]
	if !ok {
		return Result{ExitCode: 1}, errors.New("fake runner: no response for " + key)
	}
	return Result{Stdout: out}, nil
}

func (f *fakeRunner) Available(string) bool { return true }

func (f *fakeRunner) called() []Invocation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Invocation(nil), f.calls...)
}

// TestRunnerRejectsUnquotedArguments is the reason this layer exists.
// Arguments are a string slice and are never re-parsed, so a value with a space,
// a quote, or a shell metacharacter reaches the child as one argument.
func TestRunnerRejectsUnquotedArguments(t *testing.T) {
	dir := t.TempDir()

	// A script that echoes each argument on its own line, so the test can see
	// exactly what the child received.
	script := filepath.Join(dir, "echoargs")
	body := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("the test script needs a POSIX shell")
	}

	r := New()
	args := []string{
		"plain",
		"has space",
		`has"quote`,
		"has'apostrophe",
		"semi;colon",
		"pipe|char",
		"dollar$sign",
		"back`tick",
		"glob*",
		"",
	}

	res, err := r.Run(context.Background(), script, args...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	got := strings.Split(strings.TrimSuffix(res.Stdout, "\n"), "\n")
	if len(got) != len(args) {
		t.Fatalf("child received %d arguments, want %d: %q", len(got), len(args), got)
	}
	for i := range args {
		if got[i] != args[i] {
			t.Errorf("argument %d = %q, want %q", i, got[i], args[i])
		}
	}
}

// TestRunPropagatesExitStatus pins that a non-zero exit is an error carrying the
// code, rather than a string that a stage has to parse.
func TestRunPropagatesExitStatus(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test script needs a POSIX shell")
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "fail")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 7\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	_, err := New().Run(context.Background(), script)
	if err == nil {
		t.Fatal("Run returned nil for a failing command")
	}

	var ec *ExitError
	if !errors.As(err, &ec) {
		t.Fatalf("Run returned %T, want an *ExitError", err)
	}
	if ec.ExitCode() != 7 {
		t.Errorf("ExitCode = %d, want 7", ec.ExitCode())
	}
}

// TestRunMissingToolIsDistinguishable pins that a tool that is not installed is
// not reported the same way as one that ran and failed. A stage reports the
// first as "missing" and the second as "failed", and the run manifest
// distinguishes them.
func TestRunMissingToolIsDistinguishable(t *testing.T) {
	_, err := New().Run(context.Background(), "falx-definitely-not-installed")
	if err == nil {
		t.Fatal("Run returned nil for a missing tool")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Run returned %v, want it to wrap ErrNotFound", err)
	}
}

// TestRunHonoursContext pins that a cancelled context stops the tool, so an
// interrupted run does not leave a child process behind.
func TestRunHonoursContext(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test script needs a POSIX shell")
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "sleep")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := New().Run(ctx, script); err == nil {
		t.Fatal("Run returned nil for a cancelled context")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Run took %v, want it to abort near the context deadline", elapsed)
	}

	// The tool's own child must be gone too. exec.CommandContext kills only the
	// direct child, so a wrapper script would otherwise leave "sleep 30" running
	// and holding the output pipe open.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !processAlive("sleep") {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Error("the tool's grandchild process survived cancellation")
}

// processAlive reports whether any process with the given name is running.
func processAlive(name string) bool {
	// pgrep is used rather than a platform API because this is a Unix-only
	// concern; the whole check is skipped where it does not exist.
	out, err := exec.CommandContext(context.Background(), "pgrep", "-x", name).Output()
	return err == nil && len(bytes.TrimSpace(out)) > 0
}

// TestOutputIsCapped pins that a runaway tool cannot exhaust memory.
//
// Several of these tools will happily emit millions of lines from a single
// target, and a pipeline stage that buffers all of it is how a scan dies on the
// host with the least free memory.
func TestOutputIsCapped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test script needs a POSIX shell")
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "flood")
	// A bounded producer: it emits 200 KiB and then exits on its own. An
	// unbounded one would be killed only by the timeout, which is the default
	// 30 minutes, and the test would sit there for all of it.
	if err := os.WriteFile(script,
		[]byte("#!/bin/sh\nhead -c 204800 /dev/zero | tr '\\0' 'a'\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	r := New()
	r.MaxOutputBytes = 64 * 1024

	if _, err := r.Run(context.Background(), script); !errors.Is(err, ErrOutputTooLarge) {
		t.Errorf("Run returned %v, want ErrOutputTooLarge", err)
	}

	// A run within the cap is unaffected.
	r.MaxOutputBytes = 1 << 20
	res, err := r.Run(context.Background(), script)
	if err != nil {
		t.Fatalf("Run within the cap: %v", err)
	}
	if len(res.Stdout) != 204800 {
		t.Errorf("captured %d bytes, want 204800", len(res.Stdout))
	}
}

// TestAvailableReportsMissingTools pins the availability check.
func TestAvailableReportsMissingTools(t *testing.T) {
	r := New()

	if r.Available("falx-definitely-not-installed") {
		t.Error("Available reported a missing tool as present")
	}
	if len(r.Missing("falx-definitely-not-installed", "also-not-installed")) != 2 {
		t.Error("Missing did not report both absent tools")
	}
}

// TestStageCallersUseTheRecordedInvocation pins that a stage passes its flags as
// discrete arguments.
//
// The Fake runner records what was asked for, which is how a test asserts that
// a stage disables interactive templates, restricts the protocol, or bounds its
// rate without any of those tools being installed.
func TestStageCallersUseTheRecordedInvocation(t *testing.T) {
	f := newFake(map[string]string{
		"httpx -l hosts.txt -silent -json": `{"url":"https://example.com"}`,
	})

	res, err := f.Run(context.Background(), "httpx", "-l", "hosts.txt", "-silent", "-json")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Stdout == "" {
		t.Error("recorded stdout was not returned")
	}

	calls := f.called()
	if len(calls) != 1 {
		t.Fatalf("recorded %d calls, want 1", len(calls))
	}
	if got := calls[0].Line(); got != "httpx -l hosts.txt -silent -json" {
		t.Errorf("invocation = %q", got)
	}
}

// TestFakeRunnerReportsUnrecordedInvocations makes a test typo loud. A stage that
// invokes a tool with different flags than the fixture recorded should fail with
// a clear message rather than an empty result that looks like "found nothing".
func TestFakeRunnerReportsUnrecordedInvocations(t *testing.T) {
	f := newFake(map[string]string{"tool -a": "x"})

	_, err := f.Run(context.Background(), "tool", "-b")
	if err == nil {
		t.Fatal("Run returned nil for an unrecorded invocation")
	}
	if !strings.Contains(err.Error(), "no response for") {
		t.Errorf("error %q does not name the unrecorded invocation", err)
	}
}

// TestInvocationLineRoundTripsArgumentsWithSpaces pins that the recorded form is
// unambiguous, since assertions are written against it.
func TestInvocationLineRoundTripsArgumentsWithSpaces(t *testing.T) {
	inv := Invocation{Name: "httpx", Args: []string{"-header", "X-A: b c"}}
	line := inv.Line()
	if !strings.Contains(line, "X-A: b c") {
		t.Errorf("Line = %q, want it to preserve the space inside the argument", line)
	}
}
