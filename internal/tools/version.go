package tools

import (
	"context"
	"regexp"
	"sync"
	"time"
)

// ansi matches terminal colour sequences, which several of these tools emit even
// when their output is not a terminal.
var ansi = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// semver finds the first version number in text, with an optional "v" and an
// optional pre-release suffix such as -dev.
var semver = regexp.MustCompile(`v?([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?)`)

// ParseVersion extracts a version from a tool's version output, normalised with a
// leading "v", or "" when the output holds none.
//
// Tools disagree about how they report a version (a log line, a bare string, a "v"
// or not, colour codes), so this takes the first thing shaped like a version. That
// is the engine version for the tools checked, which print it first.
func ParseVersion(out string) string {
	m := semver.FindStringSubmatch(ansi.ReplaceAllString(out, ""))
	if m == nil {
		return ""
	}
	return "v" + m[1]
}

// versionFlag is how each tool is asked for its version. Most use -version.
var versionFlag = map[string]string{
	"gau":  "--version",
	"ffuf": "-V",
}

// versionTimeout bounds one probe, so a tool that hangs cannot stall a run.
const versionTimeout = 10 * time.Second

// Version asks an installed tool for its version, or returns "" if it is absent,
// does not answer, or answers with nothing recognisable. It never fails a run:
// provenance is worth having, not worth stopping for.
func (e *Exec) Version(ctx context.Context, name string) string {
	if !e.Available(name) {
		return ""
	}
	flag := versionFlag[name]
	if flag == "" {
		flag = "-version"
	}
	ctx, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()

	// A non-zero exit still prints a version for some tools, so the output is read
	// whether or not the run reported an error.
	res, _ := e.Run(ctx, name, flag)
	return ParseVersion(res.Stdout + "\n" + res.Stderr)
}

// Versions probes several tools at once and returns the versions it found,
// keyed by tool name. A tool with no answer is left out.
func (e *Exec) Versions(ctx context.Context, names []string) map[string]string {
	out := make(map[string]string, len(names))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, n := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if v := e.Version(ctx, n); v != "" {
				mu.Lock()
				out[n] = v
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out
}
