package tools

import (
	"context"
	"errors"
	"strings"
	"sync"
)

// Invocation is one recorded tool call.
type Invocation struct {
	Name string
	Args []string
	// Code is the tool's exit status, or -1 when it did not run.
	Code int
	// Duration is how long it took.
	Duration string
}

// Line renders the invocation as a single string.
//
// This is the form assertions and log lines read. An argument containing a
// space stays intact as one argument in the Args slice; Line is for humans.
func (i Invocation) Line() string { return i.Name + " " + strings.Join(i.Args, " ") }

// Recording wraps a Runner and remembers what it was asked to run.
//
// The manifest records which external tools a run used and what they returned,
// because a finding is only reproducible if you know which scanner produced it
// and with which flags. A tool that was missing is recorded too: "nuclei is not
// installed" and "nuclei found nothing" are very different things to read in a
// report.
type Recording struct {
	Inner Runner

	mu    sync.Mutex
	calls []Invocation
}

// NewRecording wraps r so that every invocation is recorded.
func NewRecording(r Runner) *Recording { return &Recording{Inner: r} }

// Run records the invocation and delegates.
func (r *Recording) Run(ctx context.Context, name string, args ...string) (Result, error) {
	inv := Invocation{Name: name, Args: append([]string(nil), args...), Code: -1}

	res, err := r.Inner.Run(ctx, name, args...)
	if err != nil {
		var ee *ExitError
		if errors.As(err, &ee) {
			inv.Code = ee.Code
		}
	} else {
		inv.Code = 0
	}

	r.mu.Lock()
	r.calls = append(r.calls, inv)
	r.mu.Unlock()

	return res, err
}

// Available delegates.
func (r *Recording) Available(name string) bool { return r.Inner.Available(name) }

// Missing delegates.
func (r *Recording) Missing(names ...string) []string { return r.Inner.Missing(names...) }

// Invocations returns the recorded calls in order.
func (r *Recording) Invocations() []Invocation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Invocation(nil), r.calls...)
}

// Lines renders the recorded calls for display.
func (r *Recording) Lines() []string {
	inv := r.Invocations()
	out := make([]string, 0, len(inv))
	for _, i := range inv {
		out = append(out, i.Line())
	}
	return out
}

// Called reports whether a tool was invoked at all, as opposed to being absent.
func (r *Recording) Called(name string) bool {
	for _, i := range r.Invocations() {
		if i.Name == name {
			return true
		}
	}
	return false
}
