package util

import (
	"testing"
	"time"
)

// TestElapsedFormat pins the human duration rendering used in stage output.
//
// Zero padded and not localized, because stages.json is parsed by tooling.
func TestElapsedFormat(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "0s"},
		{5 * time.Second, "5s"},
		{59 * time.Second, "59s"},
		{60 * time.Second, "1m00s"},
		{125 * time.Second, "2m05s"},
		{3599 * time.Second, "59m59s"},
		{3600 * time.Second, "1h00m00s"},
		{3661 * time.Second, "1h01m01s"},
		{86399 * time.Second, "23h59m59s"},
		{90000 * time.Second, "25h00m00s"},
	}

	for _, tc := range cases {
		if got := FormatElapsed(tc.in); got != tc.want {
			t.Errorf("FormatElapsed(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestElapsedFormatClampsNegative pins that a negative duration, which a clock
// adjustment can produce, does not render as something like "-3s".
func TestElapsedFormatClampsNegative(t *testing.T) {
	if got := FormatElapsed(-5 * time.Second); got != "0s" {
		t.Errorf("FormatElapsed(-5s) = %q, want 0s", got)
	}
}

// TestISOStamp pins the timestamp format.
//
// Second precision with a Z suffix, no offset and no fractional part, because
// it is sorted lexicographically and embedded in directory names.
func TestISOStamp(t *testing.T) {
	ts := time.Date(2026, 10, 3, 12, 34, 56, 0, time.UTC)
	if got := ISOStamp(ts); got != "2026-10-03T12:34:56Z" {
		t.Errorf("ISOStamp = %q", got)
	}

	// Sorting is what makes a run directory list chronological.
	a := ISOStamp(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	b := ISOStamp(time.Date(2026, 1, 2, 3, 4, 6, 0, time.UTC))
	if a >= b {
		t.Errorf("ISO stamps do not sort chronologically: %q >= %q", a, b)
	}
}

// TestRunStamp pins the directory label format, which has to sort
// lexicographically because run directories are listed by name.
func TestRunStamp(t *testing.T) {
	ts := time.Date(2026, 10, 3, 12, 34, 56, 0, time.UTC)
	if got := RunStamp(ts); got != "20261003-123456" {
		t.Errorf("RunStamp = %q, want 20261003-123456", got)
	}
	if got := RunStamp(ts); len(got) != len("20060102-150405") {
		t.Errorf("RunStamp = %q, want the width of 20060102-150405", got)
	}
}
