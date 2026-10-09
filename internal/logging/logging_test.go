package logging

import (
	"bytes"
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
	prevLevel := std.level

	SetOutputs(&buf, &buf)
	SetLevel(level)
	SetJSON(asJSON)

	t.Cleanup(func() {
		std.mu.Lock()
		std.out, std.errOut = prevOut, prevErr
		std.json, std.stamps, std.color = prevJSON, prevTimestamps, prevColor
		std.level = prevLevel
		std.mu.Unlock()
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
