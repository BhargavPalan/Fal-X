// Package tools is the boundary between Fal-X and the external reconnaissance
// binaries.
//
// Every external command is launched from here, with arguments as a string
// slice. Nothing in this package builds a command line as a string and hands it
// to a shell, so a host name, a path, or a header value containing a space, a
// quote, or a metacharacter cannot be re-split or interpreted.
package tools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Errors this package returns.
//
// ErrNotFound is distinct from a non-zero exit so a stage can report a missing
// tool differently from a tool that ran and failed. The run manifest keeps those
// apart, because "nuclei is not installed" and "nuclei found nothing" are very
// different things to read in a report.
var (
	// ErrNotFound means the binary is not on PATH.
	ErrNotFound = errors.New("tool not found")
	// ErrOutputTooLarge means a tool produced more output than the cap.
	ErrOutputTooLarge = errors.New("tool output exceeded the size cap")
)

// ExitError is a tool that ran and exited non-zero.
type ExitError struct {
	Tool     string
	Code     int
	Stderr   string
	Duration time.Duration
}

func (e *ExitError) Error() string {
	msg := fmt.Sprintf("%s exited %d", e.Tool, e.Code)
	if s := strings.TrimSpace(e.Stderr); s != "" {
		// Bounded: a tool can emit megabytes of stderr, and this string ends up
		// in a log line and possibly a report.
		msg += ": " + truncate(s, 400)
	}
	return msg
}

// ExitCode returns the tool's exit status.
func (e *ExitError) ExitCode() int { return e.Code }

// Result is one completed tool invocation.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

// Runner executes an external tool.
//
// It is an interface so a stage can be tested against recorded output without
// the tool being installed. Every stage takes a Runner, never the concrete type.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (Result, error)
	Available(name string) bool
	Missing(names ...string) []string
}

// DefaultMaxOutputBytes caps a single tool's standard output.
//
// Several of these tools will emit millions of lines from one target, and a
// stage that buffers all of it is how a run dies on the host with the least free
// memory.
const DefaultMaxOutputBytes = 256 << 20 // 256 MiB

// DefaultTimeout bounds a single invocation.
const DefaultTimeout = 30 * time.Minute

// Exec runs tools as real processes.
type Exec struct {
	// MaxOutputBytes caps captured standard output.
	MaxOutputBytes int64
	// Timeout bounds one invocation.
	Timeout time.Duration
	// Env is the environment for the child. A nil Env means inherit.
	Env []string
	// Dir is the working directory for the child.
	Dir string
}

// New returns an Exec runner with the default limits.
func New() *Exec {
	return &Exec{MaxOutputBytes: DefaultMaxOutputBytes, Timeout: DefaultTimeout}
}

// Run executes name with args and returns its output.
//
// There is no shell anywhere in this path. Arguments reach the child exactly as
// given, which is what makes a value containing a space safe.
func (e *Exec) Run(ctx context.Context, name string, args ...string) (Result, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %s", ErrNotFound, name)
	}

	if e.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = e.Env
	cmd.Dir = e.Dir

	// Kill the whole process group on cancellation, and bound how long Wait
	// blocks on inherited pipe handles afterwards. Without the second bound, a
	// grandchild holding the output pipe keeps an interrupted run hanging.
	configureProcessGroup(cmd)
	cmd.WaitDelay = 10 * time.Second

	var stdout, stderr cappedBuffer
	stdout.limit = e.MaxOutputBytes
	stderr.limit = 64 << 10
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	runErr := cmd.Run()
	elapsed := time.Since(start)

	if stdout.exceeded {
		return Result{}, fmt.Errorf("%w: %s produced more than %d bytes",
			ErrOutputTooLarge, name, e.MaxOutputBytes)
	}

	// A cancelled context is a caller decision, not a tool failure, and must not
	// be reported as one.
	if ctxErr := ctx.Err(); errors.Is(ctxErr, context.Canceled) {
		return Result{}, fmt.Errorf("%s: %w", name, ctxErr)
	} else if errors.Is(ctxErr, context.DeadlineExceeded) {
		return Result{}, fmt.Errorf("%s: %w", name, ctxErr)
	}

	if runErr != nil {
		code := -1
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			code = ee.ExitCode()
		}
		return Result{
			Stdout:   stdout.String(),
			Stderr:   stderr.String(),
			ExitCode: code,
			Duration: elapsed,
		}, &ExitError{Tool: name, Code: code, Stderr: stderr.String(), Duration: elapsed}
	}

	return Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: 0,
		Duration: elapsed,
	}, nil
}

// Available reports whether a tool is on PATH.
func (e *Exec) Available(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Missing returns the subset of names that is not installed, in the order given.
func (e *Exec) Missing(names ...string) []string {
	var out []string
	for _, n := range names {
		if !e.Available(n) {
			out = append(out, n)
		}
	}
	return out
}

// cappedBuffer collects writes and records when it has seen more than its limit.
type cappedBuffer struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	limit    int64
	exceeded bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.limit > 0 && int64(c.buf.Len())+int64(len(p)) > c.limit {
		c.exceeded = true
		// Discard the overflow rather than growing without bound.
		return len(p), nil
	}
	return c.buf.Write(p)
}

func (c *cappedBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// truncate shortens s to n characters.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
