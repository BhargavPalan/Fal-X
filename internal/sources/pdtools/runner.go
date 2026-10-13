// Package pdtools adapts external recon tools (the ProjectDiscovery suite and a few
// others) as engine sources. Each adapter shells out to one tool, parses its
// structured output, and emits into the graph like any native source; it declares
// itself unavailable when the tool is not on PATH, so a run without the tool simply
// skips it rather than failing.
//
// A tool is run with its arguments passed as a separate slice, never through a shell,
// so a value taken from a scanned host cannot be interpreted as a command. Entity keys
// are canonical (a hostname or a bare IP) before they reach an argument, and an
// argument that would look like a flag is refused.
package pdtools

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// maxToolOutput bounds a tool's captured stdout so a runaway tool cannot exhaust
// memory.
const maxToolOutput = 128 << 20

// Runner runs an external tool and returns its stdout. It is an interface so an
// adapter can be tested with a fake that returns recorded output and records the argv.
type Runner interface {
	Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error)
}

// execRunner runs a real process with a bounded timeout and output.
type execRunner struct {
	timeout time.Duration
}

// defaultRunner is the shared real runner.
var defaultRunner Runner = execRunner{timeout: 5 * time.Minute}

// Run executes name with args (never through a shell) and returns stdout bounded by
// maxToolOutput.
func (r execRunner) Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	if r.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &out, n: maxToolOutput}
	cmd.Stderr = io.Discard
	err := cmd.Run()
	// A tool that exits non-zero but produced output (nuclei finds nothing, httpx
	// probes a dead host) is not a hard error; the parsed output decides.
	if err != nil && out.Len() == 0 {
		return nil, fmt.Errorf("pdtools: run %s: %w", name, err)
	}
	return out.Bytes(), nil
}

// limitedWriter discards everything past n bytes, so stdout cannot grow without
// bound.
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil // cap reached: discard but report success so the child keeps running
	}
	keep := p
	if len(keep) > l.n {
		keep = keep[:l.n]
	}
	n, err := l.w.Write(keep)
	l.n -= n
	if err != nil {
		return n, err
	}
	if n < len(keep) {
		return n, io.ErrShortWrite // a genuine short write is an error, per io.Writer
	}
	// Everything up to the cap was stored; report the full length so io.Copy keeps
	// draining the child's stdout. Bytes past the cap are discarded by design, not
	// short-written.
	return len(p), nil
}

// available reports whether a tool is on PATH.
func available(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// safeArg reports whether s is safe to pass as a positional tool argument: non-empty
// and not something a tool would read as a flag. Entity keys are already canonical, so
// this only guards against a malformed value slipping through.
func safeArg(s string) bool {
	return s != "" && !strings.HasPrefix(s, "-")
}

// trimName lowercases a DNS name and drops a trailing root dot.
func trimName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// validHost reports whether s is a plausible DNS hostname: dotted, with labels of
// only letters, digits and hyphens.
func validHost(s string) bool {
	if len(s) == 0 || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for label := range strings.SplitSeq(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			switch {
			case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9', ch == '-':
			default:
				return false
			}
		}
	}
	return true
}
