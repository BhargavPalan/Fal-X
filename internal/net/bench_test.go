package net

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/scope"
)

// benchGate builds a gate over a realistic allowlist plus a generated URL list.
//
// The mix matters. A list of only in-scope entries would measure the cheapest
// path through the gate and make the number meaningless.
func benchGate(b testing.TB, hosts int) (*Gate, string) {
	b.Helper()

	dir := b.TempDir()
	allow := filepath.Join(dir, "scope.txt")
	deny := filepath.Join(dir, "deny.txt")

	if err := os.WriteFile(allow, []byte("example.com\n*.wild.test\n192.0.2.0/24\n"), 0o600); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(deny, []byte("admin.example.com\n"), 0o600); err != nil {
		b.Fatal(err)
	}

	sc := scope.New(false, false)
	if err := sc.Load(allow, deny); err != nil {
		b.Fatal(err)
	}

	// A strings.Builder, because concatenating in a loop is quadratic and would
	// dominate the profile with fixture construction.
	var body strings.Builder
	body.Grow(hosts * 56)
	for i := 0; i < hosts; i++ {
		switch {
		case i%97 == 0:
			fmt.Fprintf(&body, "https://admin.example.com/%d\n", i)
		case i%53 == 0:
			fmt.Fprintf(&body, "https://attacker.test/%d\n", i)
		case i%7 == 0:
			fmt.Fprintf(&body, "https://a%d.wild.test/path\n", i)
		case i%3 == 0:
			fmt.Fprintf(&body, "http://192.0.2.%d/x\n", i%250+1)
		default:
			fmt.Fprintf(&body, "https://host%d.example.com/path?q=%d\n", i, i)
		}
	}

	list := filepath.Join(dir, "urls.txt")
	if err := os.WriteFile(list, []byte(body.String()), 0o600); err != nil {
		b.Fatal(err)
	}

	return New(sc), list
}

// BenchmarkFilterURLsSmall measures the bulk filter on a modest list, which is
// what most single-estate runs produce.
func BenchmarkFilterURLsSmall(b *testing.B) {
	g, list := benchGate(b, 2000)
	out := filepath.Join(b.TempDir(), "out.txt")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := FilterURLs(g, list, out); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkFilterURLsLarge measures the bulk filter at a scale where a per-entry
// gate loop would dominate, which is the case the bulk path exists for.
func BenchmarkFilterURLsLarge(b *testing.B) {
	g, list := benchGate(b, 50000)
	out := filepath.Join(b.TempDir(), "out.txt")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := FilterURLs(g, list, out); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkFilterURLsThroughput reports entries per second, which is the number
// that decides whether a large crawl is usable at all.
func BenchmarkFilterURLsThroughput(b *testing.B) {
	const n = 50000
	g, list := benchGate(b, n)
	out := filepath.Join(b.TempDir(), "out.txt")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := FilterURLs(g, list, out); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N)*n/b.Elapsed().Seconds(), "entries/s")
}

// TestFilterURLsThroughputFloor is a test rather than a benchmark, so a
// regression fails CI instead of only showing up in a local run.
//
// The floor is deliberately loose. It is there to catch an accidental
// order-of-magnitude slowdown, not to normalise variance between machines.
func TestFilterURLsThroughputFloor(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the throughput floor in short mode")
	}

	const n = 20000
	g, list := benchGate(t, n)
	out := filepath.Join(t.TempDir(), "out.txt")

	start := time.Now()
	if err := FilterURLs(g, list, out); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	rate := float64(n) / elapsed.Seconds()
	t.Logf("filtered %d entries in %v (%.0f entries/s)", n, elapsed, rate)

	// A per-entry gate loop over this many entries was the historical
	// bottleneck, taking hours. Anything under tens of thousands per second means
	// the bulk path has stopped being one.
	if rate < 20000 {
		t.Errorf("filtering ran at %.0f entries/s, want at least 20000", rate)
	}
}
