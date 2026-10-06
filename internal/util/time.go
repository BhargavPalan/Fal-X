package util

import (
	"fmt"
	"time"
)

// FormatElapsed renders d for stage output.
//
// Second precision and zero padded, because the value is parsed by tooling and
// must not vary with locale.
//
// A negative duration, which a clock adjustment can produce, clamps to zero
// rather than rendering as "-3s".
func FormatElapsed(d time.Duration) string {
	s := int64(d.Seconds())
	if s < 0 {
		s = 0
	}

	switch {
	case s < 60:
		return fmt.Sprintf("%ds", s)
	case s < 3600:
		return fmt.Sprintf("%dm%02ds", s/60, s%60)
	default:
		return fmt.Sprintf("%dh%02dm%02ds", s/3600, (s%3600)/60, s%60)
	}
}

// ISOStamp renders t as a second-precision RFC 3339 UTC timestamp.
//
// The Z suffix and the absence of an offset are deliberate: it sorts
// lexicographically and is safe in a directory name.
func ISOStamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// RunStamp renders t as the run directory label, for example 20261003-123456.
// It has to sort lexicographically, because run directories are listed by name.
func RunStamp(t time.Time) string {
	return t.UTC().Format("20060102-150405")
}
