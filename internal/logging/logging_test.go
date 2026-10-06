package logging

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// capture redirects the logger for the duration of a test and returns what was
// written.
//
// Every setter in this package mutates process-wide state, so the tests must
// put it back or they will pass in isolation and fail as a suite.
func capture(t *testing.T, level Level, asJSON bool) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer
	prevOut, prevErr := std.out, std.errOut
	prevJSON, prevTimestamps, prevColor := std.json, std.stamps, std.color
	prevLevel := CurrentLevel()
	prevExtra := std.extra

	std.extra = nil
	SetOutputs(&buf, &buf)
	SetLevel(level)
	SetJSON(asJSON)

	t.Cleanup(func() {
		std.mu.Lock()
		std.out, std.errOut = prevOut, prevErr
		std.json, std.stamps, std.color = prevJSON, prevTimestamps, prevColor
		std.extra = prevExtra
		std.mu.Unlock()
		SetLevel(prevLevel)
	})

	return &buf
}

// TestLevelFiltering pins that a message below the threshold is dropped.
//
// The threshold has to be the other way round from what it looks like: a higher
// level means more severe, so setting Error must suppress Debug.
func TestLevelFiltering(t *testing.T) {
	cases := []struct {
		level Level
		want  []string
		drop  []string
	}{
		{LevelDebug, []string{"debugmsg", "infomsg", "warnmsg", "errmsg"}, nil},
		{LevelInfo, []string{"infomsg", "warnmsg", "errmsg"}, []string{"debugmsg"}},
		{LevelWarn, []string{"warnmsg", "errmsg"}, []string{"debugmsg", "infomsg"}},
		{LevelError, []string{"errmsg"}, []string{"debugmsg", "infomsg", "warnmsg"}},
		// Quiet is not an alias for error. It is a distinct level that drops
		// errors too, which is what a machine-readable run wants.
		{LevelQuiet, nil, []string{"debugmsg", "infomsg", "warnmsg", "errmsg"}},
	}

	for _, tc := range cases {
		t.Run(tc.level.String(), func(t *testing.T) {
			buf := capture(t, tc.level, false)
			SetTimestamps(false)
			SetColor(false)

			Debug("debugmsg")
			Info("infomsg")
			Warn("warnmsg")
			Error("errmsg")

			got := buf.String()
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("message %q was suppressed at %v but should appear", want, tc.level)
				}
			}
			for _, drop := range tc.drop {
				if strings.Contains(got, drop) {
					t.Errorf("message %q appeared at %v but should be suppressed", drop, tc.level)
				}
			}
		})
	}
}

// TestJSONOutputProducesOneObjectPerLine pins that JSON mode is machine
// readable. The run manifest and any CI parsing depend on one complete object
// per line, so a message containing a newline must not split into two.
func TestJSONOutputProducesOneObjectPerLine(t *testing.T) {
	buf := capture(t, LevelDebug, true)
	SetTimestamps(false)

	Error("something failed: %s", "a detail with \"quotes\" and a\nnewline")

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("JSON output produced %d lines, want 1: %q", len(lines), buf.String())
	}
	for _, want := range []string{`"msg"`, `"level"`, "something failed", `quotes`} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("JSON line missing %q: %s", want, lines[0])
		}
	}
}

// TestPlainOutputHasNoJSONNoise pins the opposite: normal mode must not emit
// braces, because a human reads it.
func TestPlainOutputHasNoJSONNoise(t *testing.T) {
	buf := capture(t, LevelDebug, false)
	SetTimestamps(false)
	SetColor(false)

	Info("hello %s", "world")

	got := strings.TrimSpace(buf.String())
	if strings.Contains(got, "{") || strings.Contains(got, `"msg"`) {
		t.Errorf("plain output contains JSON: %q", got)
	}
	if !strings.Contains(got, "hello world") {
		t.Errorf("plain output = %q, want the formatted message", got)
	}
}

// TestColourCanBeDisabled pins that the escape codes are suppressible, which is
// what keeps a redirected log readable.
func TestColourCanBeDisabled(t *testing.T) {
	withColor := capture(t, LevelDebug, false)
	SetTimestamps(false)
	SetColor(true)
	Ok("colourful")
	colored := withColor.String()

	if !strings.Contains(colored, "\033[") {
		t.Skip("this terminal setting did not emit colour codes")
	}

	plain := capture(t, LevelDebug, false)
	SetTimestamps(false)
	SetColor(false)
	Ok("colourful")
	if strings.Contains(plain.String(), "\033[") {
		t.Errorf("colour was not suppressed: %q", plain.String())
	}
}

// TestLevelQuietIsNotAnAliasForError pins the distinction between the two.
//
// Quiet exists so a machine-readable run can be silenced without losing the
// ability to see an error. Collapsing it into error would leave a failed stage
// indistinguishable from ordinary output.
func TestLevelQuietIsNotAnAliasForError(t *testing.T) {
	if LevelQuiet == LevelError {
		t.Fatal("LevelQuiet and LevelError are the same level")
	}

	buf := capture(t, LevelQuiet, false)
	SetTimestamps(false)
	SetColor(false)
	Error("this should not appear")
	if strings.TrimSpace(buf.String()) != "" {
		t.Errorf("quiet level emitted %q, want nothing", buf.String())
	}
}

// TestParseLevel pins the level parser used by configuration.
func TestParseLevel(t *testing.T) {
	cases := map[string]Level{
		"debug":    LevelDebug,
		"DEBUG":    LevelDebug,
		"info":     LevelInfo,
		"warn":     LevelWarn,
		"warning":  LevelWarn,
		"error":    LevelError,
		"quiet":    LevelQuiet,
		"":         LevelInfo,
		"  info  ": LevelInfo,
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}

	// An unrecognised level falls back rather than silencing the logger, which
	// would hide a typo that turns into a run that reports nothing.
	if got := ParseLevel("verbose"); got != LevelInfo {
		t.Errorf("ParseLevel(\"verbose\") = %v, want the %v default", got, LevelInfo)
	}
}

// TestRefusalOf pins the classification the exit-status contract depends on.
//
// An unclassified error has to be a runtime failure rather than a usage error.
// Reporting a tool failure as a caller mistake would send an operator looking at
// their command line instead of at the tool.
func TestRefusalOf(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want Refusal
	}{
		{"nil", nil, RefuseNone},
		{"plain", errors.New("boom"), RefuseNone},
		{"runtime", Runtimef("stage failed"), RefuseNone},
		{"usage", Usagef("bad flag"), RefuseUsage},
		{"usage wrapped", fmt.Errorf("scan: %w", Usagef("bad flag")), RefuseUsage},
		{"scope", Scopef("no allowlist"), RefuseScope},
		{"scope wrapped", fmt.Errorf("preflight: %w", Scopef("no allowlist")), RefuseScope},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RefusalOf(tc.err); got != tc.want {
				t.Errorf("RefusalOf(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestRefusalString pins that the three categories stay distinguishable in a
// message, which is all a human has to go on.
func TestRefusalString(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range []Refusal{RefuseNone, RefuseUsage, RefuseScope} {
		s := r.String()
		if s == "" {
			t.Errorf("Refusal %d has no string form", r)
		}
		if seen[s] {
			t.Errorf("Refusal string %q is used twice", s)
		}
		seen[s] = true
	}
}

// TestTeeCopiesToBothWriters pins that a caller can mirror the log without
// taking it over.
func TestTeeCopiesToBothWriters(t *testing.T) {
	var primary, mirror bytes.Buffer
	prevOut, prevErr := std.out, std.errOut
	prevExtra := std.extra
	prevLevel := CurrentLevel()

	std.extra = nil
	SetOutputs(&primary, &primary)
	SetLevel(LevelDebug)
	SetTimestamps(false)
	SetColor(false)

	t.Cleanup(func() {
		std.mu.Lock()
		std.out, std.errOut = prevOut, prevErr
		std.extra = prevExtra
		std.mu.Unlock()
		SetLevel(prevLevel)
	})

	Info("mirrored")
	if !strings.Contains(primary.String(), "mirrored") {
		t.Fatalf("primary writer got %q", primary.String())
	}

	Tee(&mirror)
	Info("second")
	if !strings.Contains(mirror.String(), "second") {
		t.Errorf("mirror writer got %q, want the later message", mirror.String())
	}
	if !strings.Contains(primary.String(), "second") {
		t.Errorf("primary writer lost the message after Tee: %q", primary.String())
	}
}

// TestFatalVariantsUseTheRightStatus pins each helper's status.
func TestFatalVariantsUseTheRightStatus(t *testing.T) {
	cases := []struct {
		name string
		fn   func()
		want int
	}{
		{"Fatal", func() { Fatal("boom") }, StatusRuntime},
		{"FatalUsage", func() { FatalUsage("bad flag") }, StatusUsage},
		{"FatalScope", func() { FatalScope("no allowlist") }, StatusScope},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capture(t, LevelDebug, false)

			got := -1
			prev := exitFn
			SetExitFunc(func(code int) { got = code })
			t.Cleanup(func() { SetExitFunc(prev) })

			tc.fn()
			if got != tc.want {
				t.Errorf("exited %d, want %d", got, tc.want)
			}
		})
	}
}

// TestDefaultWritersAreSet guards against a build where no writer is wired,
// which would make the tool silent rather than obviously broken.
func TestDefaultWritersAreSet(t *testing.T) {
	lg := Default()
	if lg == nil {
		t.Fatal("Default() returned nil")
	}
	lg.mu.Lock()
	defer lg.mu.Unlock()
	if lg.out == nil {
		t.Error("stdout writer is nil")
	}
	if lg.errOut == nil {
		t.Error("stderr writer is nil")
	}
}

// TestHaveAndMissing pins the tool-presence helpers, which decide whether a
// stage reports itself as skipped.
func TestHaveAndMissing(t *testing.T) {
	// These two exist on any system running the tests.
	if !Have("go") && !Have("sh") {
		t.Skip("neither go nor sh is on PATH")
	}
	missing := Missing("go", "falx-definitely-not-installed", "sh",
		"also-definitely-not-installed")
	if len(missing) != 2 {
		t.Errorf("Missing returned %v, want the two absent tools", missing)
	}
	if HaveAll("falx-definitely-not-installed") {
		t.Error("HaveAll accepted an absent tool")
	}
}
