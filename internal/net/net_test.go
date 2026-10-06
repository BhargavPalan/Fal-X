package net

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/scope"
	"github.com/BhargavPalan/Fal-X/internal/util"
)

// newScope builds a Scope from inline allow and deny text.
func newScope(t *testing.T, allow, deny string) *scope.Scope {
	t.Helper()

	dir := t.TempDir()
	allowPath := filepath.Join(dir, "scope.txt")
	denyPath := filepath.Join(dir, "deny.txt")

	if err := os.WriteFile(allowPath, []byte(allow), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(denyPath, []byte(deny), 0o600); err != nil {
		t.Fatal(err)
	}

	s := scope.New(false, false)
	if err := s.Load(allowPath, denyPath); err != nil {
		t.Fatalf("scope load: %v", err)
	}
	return s
}

// both runs one target through the single-target gate and the bulk filter and
// reports whether they agreed, plus the verdict.
//
// The bulk filter calls the single gate, so divergence is not possible by
// construction. The assertion remains because an optimisation that reintroduces
// a separate fast path is precisely the change this test would catch.
func both(t *testing.T, g *Gate, target string) (allow bool, agreed bool) {
	t.Helper()

	single := g.Scope().Gate(target, "")

	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	out := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(in, []byte(target+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := FilterURLs(g, in, out); err != nil {
		t.Fatalf("FilterURLs(%q): %v", target, err)
	}

	batch := util.Count(out) > 0
	return batch, single == batch
}

// parityMatrix is the fixture shared by the single and bulk paths.
const (
	fixtureAllow = "example.com\n*.wild.test\n192.0.2.0/24\n2001:db8::1\n"
	fixtureDeny  = "admin.example.com\n*.dev.test\n192.0.2.8\n"
)

// TestFilterURLsAgreesWithGate is the parity gate for the authorization
// decision. Every case must be judged identically by both paths, and the
// expected verdict pins that the shared answer is the correct one.
func TestFilterURLsAgreesWithGate(t *testing.T) {
	cases := []struct {
		want  bool
		entry string
		why   string
	}{
		// Domains.
		{true, "https://example.com/", "apex"},
		{true, "https://api.example.com/v1/users", "subdomain"},
		{true, "https://a.b.c.d.example.com/deep/path", "deep subdomain"},
		{true, "http://example.com:8080/x", "explicit port"},
		{true, "https://x.wild.test/", "wildcard match"},
		{true, "https://a.b.wild.test/", "wildcard subdomain"},

		// The spoof cases. Each of these contains the allowlisted string as a
		// substring and is the whole reason matching is label-aware.
		{false, "https://example.com.attacker.test/", "suffix spoof"},
		{false, "https://notexample.com/", "prefix extension"},
		{false, "https://evil-example.com/", "hyphen prefix"},
		{false, "https://admin.example.com/panel", "denylisted apex"},
		{false, "https://a.dev.test/x", "denylisted wildcard"},
		{false, "https://wild.test/", "wildcard apex itself"},

		// Parser-confusion shapes.
		{false, "https://example.com@attacker.test/x", "userinfo spoof"},
		{true, "https://user@example.com/x", "real userinfo"},

		// IPv4.
		{true, "http://192.0.2.5/", "address in range"},
		{true, "http://192.0.2.5:8443/x", "address with port"},
		{false, "http://192.0.2.8/", "denylisted address"},
		{false, "http://192.0.4.5/", "address out of range"},

		// IPv6.
		{true, "http://[2001:db8::1]:8080/", "allowed IPv6 with port"},
		{false, "http://[2001:db8::2]/", "IPv6 out of scope"},

		// Bare hostnames, which is what a subdomain stage emits.
		{true, "example.com", "bare apex"},
		{false, "attacker.test", "bare out-of-scope"},
	}

	for _, tc := range cases {
		t.Run(tc.why+" "+tc.entry, func(t *testing.T) {
			g := New(newScope(t, fixtureAllow, fixtureDeny))

			batch, agreed := both(t, g, tc.entry)
			if !agreed {
				t.Fatalf("DIVERGENCE: the single gate and the bulk filter disagree on %q", tc.entry)
			}
			if batch != tc.want {
				t.Errorf("verdict for %q = %v, want %v", tc.entry, batch, tc.want)
			}
		})
	}
}

// TestFilterURLsList pins whole-list behaviour, including the exact kept set.
func TestFilterURLsList(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "urls.txt")
	out := filepath.Join(dir, "out.txt")

	entries := []string{
		"https://example.com/",
		"https://api.example.com/login",
		"https://admin.example.com/secret",
		"https://a.dev.test/staging",
		"https://x.wild.test/app",
		"https://attacker.test/evil",
		"https://example.com.attacker.test/evil",
		"http://192.0.2.5:8080/admin",
		"http://192.0.2.8/denied",
		"http://[2001:db8::1]/",
		"https://example.com@attacker.test/evil",
		"https://user@example.com/ok",
	}
	if err := util.WriteLines(in, entries); err != nil {
		t.Fatal(err)
	}

	g := New(newScope(t, fixtureAllow, fixtureDeny))
	if err := FilterURLs(g, in, out); err != nil {
		t.Fatalf("FilterURLs: %v", err)
	}

	got, _ := util.ReadLines(out)
	sort.Strings(got)

	want := []string{
		"http://192.0.2.5:8080/admin",
		"http://[2001:db8::1]/",
		"https://api.example.com/login",
		"https://example.com/",
		"https://user@example.com/ok",
		"https://x.wild.test/app",
	}
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("kept %d entries (%q), want %d (%q)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestFilterURLsDeduplicates pins that repeated URLs collapse, so a crawler
// that revisits a page does not inflate the result set.
func TestFilterURLsDeduplicates(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "dup.txt")
	out := filepath.Join(dir, "out.txt")

	if err := util.WriteLines(in, []string{
		"https://example.com/a", "https://example.com/a", "https://example.com/b",
	}); err != nil {
		t.Fatal(err)
	}

	g := New(newScope(t, fixtureAllow, fixtureDeny))
	if err := FilterURLs(g, in, out); err != nil {
		t.Fatal(err)
	}
	if got := util.Count(out); got != 2 {
		t.Errorf("kept %d entries, want 2 after deduplication", got)
	}
}

// TestFilterURLsAlwaysProducesOutput pins the distinction stages.json depends
// on: a present empty file means the stage ran and matched nothing, while a
// missing file means it never got that far.
func TestFilterURLsAlwaysProducesOutput(t *testing.T) {
	dir := t.TempDir()

	for _, tc := range []struct {
		name    string
		present bool
	}{
		{"empty input", true},
		{"absent input", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := filepath.Join(dir, tc.name+".in")
			out := filepath.Join(dir, tc.name+".out")
			if tc.present {
				if err := util.WriteLines(in, nil); err != nil {
					t.Fatal(err)
				}
			}

			g := New(newScope(t, fixtureAllow, fixtureDeny))
			if err := FilterURLs(g, in, out); err != nil {
				t.Fatalf("FilterURLs: %v", err)
			}

			if _, err := os.Stat(out); err != nil {
				t.Errorf("output file was not created: %v", err)
			}
			if got := util.Count(out); got != 0 {
				t.Errorf("output holds %d entries, want 0", got)
			}
		})
	}
}

// TestFilterURLsFullyDeniedList pins that a list with nothing in scope yields a
// present, empty output rather than an error.
func TestFilterURLsFullyDeniedList(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "all.in")
	out := filepath.Join(dir, "all.out")

	if err := util.WriteLines(in, []string{
		"https://attacker.test/", "https://evil.test/",
	}); err != nil {
		t.Fatal(err)
	}

	g := New(newScope(t, fixtureAllow, fixtureDeny))
	if err := FilterURLs(g, in, out); err != nil {
		t.Fatal(err)
	}
	if got := util.Count(out); got != 0 {
		t.Errorf("fully denied list yielded %d entries, want 0", got)
	}
}

// TestFilterURLsDropsPrivateRanges pins that the private-range block applies on
// the bulk path too, and that allowing private space does not widen the
// allowlist. Those are separate properties and the second is the one that gets
// forgotten.
func TestFilterURLsDropsPrivateRanges(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "lab.in")
	out := filepath.Join(dir, "lab.out")

	if err := util.WriteLines(in, []string{
		"http://10.1.2.3/", "https://lab.test/", "http://192.168.1.1/",
	}); err != nil {
		t.Fatal(err)
	}

	t.Run("denied by default", func(t *testing.T) {
		s := scope.New(false, false)
		if err := s.Load(writeScope(t, "10.0.0.0/8\nlab.test\n"), ""); err != nil {
			t.Fatal(err)
		}
		g := New(s)
		if err := FilterURLs(g, in, out); err != nil {
			t.Fatal(err)
		}

		got, _ := util.ReadLines(out)
		if len(got) != 1 || got[0] != "https://lab.test/" {
			t.Errorf("kept %q, want only https://lab.test/", got)
		}
	})

	t.Run("allow-private does not widen the allowlist", func(t *testing.T) {
		s := scope.New(true, false)
		if err := s.Load(writeScope(t, "10.0.0.0/8\nlab.test\n"), ""); err != nil {
			t.Fatal(err)
		}
		g := New(s)
		out2 := filepath.Join(dir, "lab2.out")
		if err := FilterURLs(g, in, out2); err != nil {
			t.Fatal(err)
		}

		got, _ := util.ReadLines(out2)
		if len(got) != 2 {
			t.Errorf("kept %d entries (%q), want 2", len(got), got)
		}
		for _, e := range got {
			if strings.Contains(e, "192.168") {
				t.Errorf("192.168.1.1 was kept; --allow-private must not widen the allowlist")
			}
		}
		if !contains(got, "http://10.1.2.3/") {
			t.Errorf("10.1.2.3 was not kept despite being allowlisted with --allow-private")
		}
	})
}

// TestFilterURLsHonoursAllowAny pins that the bulk path permits everything
// except what the denylist names.
func TestFilterURLsHonoursAllowAny(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "any.in")
	out := filepath.Join(dir, "any.out")

	if err := util.WriteLines(in, []string{
		"https://unrelated.test/a", "https://admin.example.com/b",
	}); err != nil {
		t.Fatal(err)
	}

	s := scope.New(false, true)
	if err := s.Load(writeScope(t, "example.com\n"), writeScope(t, "admin.example.com\n")); err != nil {
		t.Fatal(err)
	}
	g := New(s)

	if err := FilterURLs(g, in, out); err != nil {
		t.Fatal(err)
	}

	got, _ := util.ReadLines(out)
	if len(got) != 1 || got[0] != "https://unrelated.test/a" {
		t.Errorf("kept %q, want only https://unrelated.test/a; the denylist must still win under --allow-any", got)
	}
}

// TestRequireAllowedCounts pins that every decision is counted, so a run
// manifest can report how much was suppressed rather than looking complete.
func TestRequireAllowedCounts(t *testing.T) {
	g := New(newScope(t, fixtureAllow, fixtureDeny))

	for _, entry := range []string{"https://example.com/", "https://api.example.com/x"} {
		if err := g.RequireAllowed(entry, ""); err != nil {
			t.Errorf("RequireAllowed(%q) = %v, want nil", entry, err)
		}
	}
	for _, entry := range []string{"https://attacker.test/", "https://admin.example.com/"} {
		if err := g.RequireAllowed(entry, ""); err == nil {
			t.Errorf("RequireAllowed(%q) = nil, want a refusal", entry)
		}
	}

	allowed, denied := g.Counts()
	if allowed != 2 {
		t.Errorf("allowed count = %d, want 2", allowed)
	}
	if denied != 2 {
		t.Errorf("denied count = %d, want 2", denied)
	}
}

// TestRequireAllowedReturnsScopeError pins that a refusal is distinguishable
// from a transport failure. The exit-status contract maps them differently: a
// refusal means the operator needs authorization, a failure means the tool
// broke.
func TestRequireAllowedReturnsScopeError(t *testing.T) {
	g := New(newScope(t, fixtureAllow, fixtureDeny))

	err := g.RequireAllowed("https://attacker.test/", "")
	if err == nil {
		t.Fatal("RequireAllowed returned nil for an out-of-scope target")
	}
	if !errors.Is(err, ErrScopeRefused) {
		t.Errorf("RequireAllowed returned %v, want it to wrap ErrScopeRefused", err)
	}
}

// TestDryRunGatesNothing pins that --dry-run is the same code path with the
// network closed, not a separate implementation that skips the gate.
func TestDryRunGatesNothing(t *testing.T) {
	// A deliberately tiny allowlist. In dry run the gate is never consulted, so
	// even an out-of-scope target is permitted, and the caller is responsible
	// for not issuing the request.
	g := New(newScope(t, fixtureAllow, fixtureDeny))
	g.SetDryRun(true)

	if err := g.RequireAllowed("https://attacker.test/", ""); err != nil {
		t.Errorf("dry run refused %q; the gate should be bypassed, not evaluated", "https://attacker.test/")
	}

	if _, denied := g.Counts(); denied != 0 {
		t.Error("dry run counted a denial; the gate was evaluated")
	}
}

// TestDeniedTargetIsNeverContacted is the end-to-end property: an out-of-scope
// URL does not reach the server.
//
// Loopback needs allowPrivate, which is exactly what that switch is for.
func TestDeniedTargetIsNeverContacted(t *testing.T) {
	var contacted bool
	srv := newCountingServer(t, &contacted)

	s := scope.New(true, false)
	// The allowlist names 127.0.0.1 and deliberately not "localhost", which
	// resolves to the same server.
	if err := s.Load(writeScope(t, "127.0.0.1\n"), ""); err != nil {
		t.Fatal(err)
	}
	g := New(s)
	g.SetHTTPClient(newLocalClient())

	if err := g.RequireAllowed("http://localhost:"+srv.port()+"/", ""); err == nil {
		t.Fatal("an out-of-scope host was permitted")
	}

	if _, err := g.Get("http://localhost:" + srv.port() + "/"); err == nil {
		t.Error("Get returned nil for an out-of-scope URL")
	}
	if contacted {
		t.Error("the out-of-scope server was contacted")
	}
}

// TestOutOfScopeRedirectIsNotFollowed is the redirect property that a
// client-level redirect follow would break.
//
// A redirect is attacker-controlled input. Authorizing only the first URL means
// the second request reaches whatever host the first one chose to name, with no
// gate in front of it. Both servers here are loopback; the allowlist names only
// 127.0.0.1, so the hop to "localhost" is out of scope while resolving to the
// very same address.
func TestOutOfScopeRedirectIsNotFollowed(t *testing.T) {
	var secondHits atomic.Int64
	second := newCountingServer(t, nil)
	second.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	secondHits.Store(0)

	target := "http://localhost:" + second.port() + "/"

	var firstHits atomic.Int64
	first := redirectingServer(t, target, &firstHits)

	s := scope.New(true, false)
	if err := s.Load(writeScope(t, "127.0.0.1\n"), ""); err != nil {
		t.Fatal(err)
	}
	g := New(s)
	g.SetHTTPClient(newLocalClient())

	// The first URL names 127.0.0.1, which is allowlisted.
	_, err := g.Get("http://127.0.0.1:" + first.port() + "/")
	if err == nil {
		t.Fatal("Get followed an out-of-scope redirect instead of refusing it")
	}
	if !errors.Is(err, ErrScopeRefused) {
		t.Errorf("Get returned %v, want it to wrap ErrScopeRefused", err)
	}

	if firstHits.Load() == 0 {
		t.Error("the in-scope first hop was never requested, so nothing was proven")
	}
	if secondHits.Load() != 0 {
		t.Errorf("the out-of-scope redirect target was contacted %d times", secondHits.Load())
	}
	if got := g.RedirectsBlocked(); got != 1 {
		t.Errorf("RedirectsBlocked = %d, want 1", got)
	}
}

// TestRedirectSchemeIsRestricted pins that a Location naming a non-HTTP scheme
// is not followed.
func TestRedirectSchemeIsRestricted(t *testing.T) {
	cases := []struct {
		location string
		why      string
	}{
		{"file:///etc/passwd", "file scheme"},
		{"gopher://example.com/", "gopher scheme"},
		{"ftp://example.com/", "ftp scheme"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			if _, err := resolveRedirect("https://example.com/", tc.location); err == nil {
				t.Errorf("resolveRedirect accepted %q", tc.location)
			}
		})
	}

	// An ordinary absolute and relative redirect must still resolve.
	abs, err := resolveRedirect("https://example.com/a/b", "https://other.test/c")
	if err != nil || abs != "https://other.test/c" {
		t.Errorf("absolute redirect resolved to (%q, %v)", abs, err)
	}
	rel, err := resolveRedirect("https://example.com/a/b", "/c")
	if err != nil || rel != "https://example.com/c" {
		t.Errorf("relative redirect resolved to (%q, %v)", rel, err)
	}
}

func writeScope(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
