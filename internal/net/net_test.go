package net

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/scope"
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

// parityMatrix is the fixture shared by the single and bulk paths.
const (
	fixtureAllow = "example.com\n*.wild.test\n192.0.2.0/24\n2001:db8::1\n"
	fixtureDeny  = "admin.example.com\n*.dev.test\n192.0.2.8\n"
)

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

	if _, err := g.GetContext(context.Background(), "http://localhost:"+srv.port()+"/"); err == nil {
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
	_, err := g.GetContext(context.Background(), "http://127.0.0.1:"+first.port()+"/")
	if err == nil {
		t.Fatal("GetContext followed an out-of-scope redirect instead of refusing it")
	}
	if !errors.Is(err, ErrScopeRefused) {
		t.Errorf("GetContext returned %v, want it to wrap ErrScopeRefused", err)
	}

	if firstHits.Load() == 0 {
		t.Error("the in-scope first hop was never requested, so nothing was proven")
	}
	if secondHits.Load() != 0 {
		t.Errorf("the out-of-scope redirect target was contacted %d times", secondHits.Load())
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
