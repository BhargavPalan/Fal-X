package logging

import (
	"errors"
	"fmt"
	"testing"
)

// TestExitForPinsTheStatusContract.
//
// Wrappers and CI branch on these numbers, so a change here is a change to the
// public interface of the tool. 0 is success, 1 is a runtime failure, 2 is a
// usage or validation error, 3 is an authorization or scope refusal, and 130
// is a signal-terminated run.
func TestExitFor(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, StatusOK},

		// A bare error is a runtime failure, because it is the default and
		// anything unclassified must not be mistaken for a usage error.
		{"plain", errors.New("boom"), StatusRuntime},
		{"wrapped", fmt.Errorf("stage http: %w", errors.New("timeout")), StatusRuntime},
		{"runtime", Runtimef("stage failed"), StatusRuntime},

		// Usage errors, including one buried under wraps. A usage error that
		// loses its type through wrapping would exit 1 instead of 2, which
		// would make a caller's flag mistake look like a scan failure.
		{"usage", Usagef("bad flag"), StatusUsage},
		{"usage wrapped", fmt.Errorf("scan: %w", Usagef("bad flag")), StatusUsage},

		// A scope refusal must stay distinguishable from a usage error, since
		// it means authorization rather than a typo.
		{"scope", Scopef("no allowlist"), StatusScope},
		{"scope wrapped", fmt.Errorf("preflight: %w", Scopef("no allowlist")), StatusScope},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExitFor(tc.err); got != tc.want {
				t.Errorf("ExitFor(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

// TestScopeOutranksRuntime pins that a scope refusal nested inside a runtime
// error keeps its own status. The refusal is the useful signal: it tells the
// operator they need authorization, not that the tool broke.
func TestScopeOutranksRuntime(t *testing.T) {
	inner := fmt.Errorf("resolving stage: %w", Scopef("192.0.2.5 is out of scope"))
	if got := ExitFor(inner); got != StatusScope {
		t.Errorf("ExitFor = %d, want %d", got, StatusScope)
	}
}

// TestStatusesAreDistinct guards the contract itself. Two categories sharing a
// number would make the mapping ambiguous even though each case passed above.
func TestStatusesAreDistinct(t *testing.T) {
	seen := map[int]string{}
	for name, status := range map[string]int{
		"runtime":     StatusRuntime,
		"usage":       StatusUsage,
		"scope":       StatusScope,
		"interrupted": StatusInterrupted,
	} {
		if other, dup := seen[status]; dup {
			t.Errorf("%s and %s share status %d", other, name, status)
		}
		seen[status] = name
	}

	if StatusOK != 0 {
		t.Errorf("StatusOK = %d, want 0", StatusOK)
	}
	if StatusInterrupted != 130 {
		t.Errorf("StatusInterrupted = %d, want 130", StatusInterrupted)
	}
}

// TestErrorMessagesUnwrap confirms each wrapper exposes its cause, so callers
// can use errors.Is against the sentinel types rather than string matching.
func TestErrorMessagesUnwrap(t *testing.T) {
	var usage ErrUsage
	if err := Usagef("x"); !errors.As(err, &usage) {
		t.Error("Usagef does not produce an ErrUsage")
	}

	var scopeErr ErrScope
	if err := Scopef("x"); !errors.As(err, &scopeErr) {
		t.Error("Scopef does not produce an ErrScope")
	}

	var runtime ErrRuntime
	if err := Runtimef("x"); !errors.As(err, &runtime) {
		t.Error("Runtimef does not produce an ErrRuntime")
	}
}

// TestFatalErrUsesExitStatus confirms the single exit point maps errors to the
// right status rather than always exiting 1.
func TestFatalErrUsesExitStatus(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, 0},
		{"runtime", errors.New("x"), StatusRuntime},
		{"usage", Usagef("x"), StatusUsage},
		{"scope", Scopef("x"), StatusScope},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got = -1
			prev := exitFn
			SetExitFunc(func(code int) { got = code })
			t.Cleanup(func() { SetExitFunc(prev) })

			FatalErr(tc.err)

			want := tc.want
			if tc.err == nil {
				// Nothing to report, so nothing must exit.
				if got != -1 {
					t.Errorf("FatalErr(nil) exited with %d, want no exit", got)
				}
				return
			}
			if got != want {
				t.Errorf("FatalErr exited with %d, want %d", got, want)
			}
		})
	}
}

// TestErrorMessagesSurviveEmptyCause covers the nil-Err path, which exists
// because a bare ErrScope{} is a valid way to say "unauthorized".
func TestErrorMessagesSurviveEmptyCause(t *testing.T) {
	if got := (ErrUsage{}).Error(); got != "invalid usage" {
		t.Errorf("ErrUsage{}.Error() = %q", got)
	}
	if got := (ErrScope{}).Error(); got != "authorization required" {
		t.Errorf("ErrScope{}.Error() = %q", got)
	}
	if got := (ErrRuntime{}).Error(); got != "runtime failure" {
		t.Errorf("ErrRuntime{}.Error() = %q", got)
	}
}
