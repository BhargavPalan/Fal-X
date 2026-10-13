package store

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// dbText is the one sanitiser every stored value passes through (graph.AddFact and
// the match writers all route through store.SafeText). These tests pin its
// guarantees directly: a value chosen by a scanned host can never carry a NUL, be
// invalid UTF-8, exceed its column budget, or be silently shortened. Before this was
// handled, one such value rolled back a whole import and lost every other asset in
// it.

// Truncation must be visible. A title quietly shortened into something that looks
// ordinary would hide evidence in a tool whose whole purpose is evidence. The marker
// must also fit inside the budget, at every budget the store uses.
func TestTruncationIsAnnounced(t *testing.T) {
	budgets := map[string]int{"orgSlug": maxOrgSlug, "text": maxText, "mid": 500}
	huge := []string{
		strings.Repeat("L", 500000),
		strings.Repeat("日", 5000),
		strings.Repeat("🔐", 3000),
		strings.Repeat("a", 10000),
	}
	for name, limit := range budgets {
		for _, in := range huge {
			got := dbText(in, limit)
			if len(got) > limit {
				t.Errorf("%s: dbText returned %d bytes, over the %d budget (input %d bytes)",
					name, len(got), limit, len(in))
			}
			if !utf8.ValidString(got) {
				t.Errorf("%s: dbText produced invalid UTF-8", name)
			}
			if !strings.Contains(got, "bytes]") {
				t.Errorf("%s: an over-long value was shortened without saying so: %q", name, got)
			}
		}
	}
}

// A value inside the budget must come back untouched, or every normal import would
// accumulate truncation markers.
func TestValuesWithinBudgetAreUnchanged(t *testing.T) {
	for _, s := range []string{
		"", "nginx", "http://example.com/path?q=1", "Apache/2.4.41 (Ubuntu)",
		strings.Repeat("a", 100), "日本語のタイトル", "emoji 🔐 title",
	} {
		if got := dbText(s, maxText); got != s {
			t.Errorf("dbText(%q) = %q, want it unchanged", s, got)
		}
	}
}

// Postgres forbids U+0000 outright, so it must be gone from anything stored.
func TestNulAndInvalidUTF8AreRemoved(t *testing.T) {
	if got := dbText("a\x00b", maxText); strings.ContainsRune(got, 0) {
		t.Errorf("dbText kept a NUL: %q", got)
	}
	if got := dbText("a\xffb", maxText); strings.Contains(got, "\xff") {
		t.Errorf("dbText kept an invalid byte: %q", got)
	}
}

// Truncation must not split a multi-byte rune, which would produce invalid UTF-8 and
// be rejected by Postgres all the same.
func TestTruncationKeepsValidUTF8(t *testing.T) {
	for _, s := range []string{
		strings.Repeat("日", 5000),
		strings.Repeat("🔐", 3000),
		strings.Repeat("é", 8000),
	} {
		got := dbText(s, maxText)
		if !utf8.ValidString(got) {
			t.Errorf("dbText produced invalid UTF-8 (len %d) for %q", len(got), s[:8])
		}
	}
}

// The marker must fit at every small budget too, not just the large ones.
func TestDBTextNeverExceedsAnyBudget(t *testing.T) {
	long := strings.Repeat("é", 5000)
	for limit := 0; limit <= 120; limit++ {
		got := dbText(long, limit)
		if len(got) > limit {
			t.Fatalf("limit %d: got %d bytes", limit, len(got))
		}
		if !utf8.ValidString(got) {
			t.Fatalf("limit %d: invalid UTF-8", limit)
		}
	}
}
