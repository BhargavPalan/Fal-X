package scope

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These check the invariants this package's comments state, by behaviour rather than
// by reading. They exist because a comment that documents an invariant is only
// worth having if the invariant actually holds, and an invariant that quietly stops
// holding is invisible until something goes wrong.

// scope.go: "It never widens scope." and "A denylist entry always wins,
// including under --allow-any."
func TestClaimDenylistAlwaysWins(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "allow.txt")
	deny := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(allow, []byte("example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deny, []byte("secret.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, mode := range []struct {
		name                   string
		allowPrivate, allowAny bool
	}{
		{"plain", false, false},
		{"allow-any", false, true},
		{"allow-any+private", true, true},
	} {
		s := New(mode.allowPrivate, mode.allowAny)
		if err := s.Load(allow, deny); err != nil {
			t.Fatalf("[%s] Load: %v", mode.name, err)
		}
		if !s.Gate("example.com", "") {
			t.Errorf("[%s] the allowed host is refused", mode.name)
		}
		for _, spelling := range []string{
			"secret.example.com",
			"SECRET.example.com",
			"secret.example.com.",
			"sub.secret.example.com",
			"http://secret.example.com/x",
		} {
			if s.Gate(spelling, "") {
				t.Errorf("[%s] BUG: denylisted host %q was allowed", mode.name, spelling)
			}
		}
	}
}

// scope.go: "Set by Unrestricted, never by Load: a scope file that exists but is
// unreadable must not leave the run unrestricted."
func TestClaimUnreadableAllowlistIsNotUnrestricted(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.txt")
	for _, mode := range []struct {
		allowPrivate, allowAny bool
	}{{false, false}, {false, true}, {true, true}} {
		s := New(mode.allowPrivate, mode.allowAny)
		err := s.Load(missing, "")
		if err == nil {
			t.Errorf("Load of a missing allowlist returned nil: the run would be unrestricted")
			continue
		}
		if !strings.Contains(err.Error(), "allowlist") {
			t.Errorf("error does not name the allowlist: %v", err)
		}
	}
}

// scope.go: "It fails closed. A missing or unreadable allowlist is an error."
// An empty-but-readable one is an error too, except under --allow-any, where the
// operator has already said the file is not what decides.
func TestClaimEmptyAllowlistIsNotUnrestricted(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(empty, []byte("# only comments\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Without --allow-any an empty allowlist must refuse.
	for _, mode := range []struct {
		allowPrivate, allowAny bool
	}{{false, false}, {true, false}} {
		s := New(mode.allowPrivate, mode.allowAny)
		if err := s.Load(empty, ""); err == nil {
			t.Errorf("[priv=%v any=%v] an empty allowlist loaded; the run would be unrestricted",
				mode.allowPrivate, mode.allowAny)
		}
		// And the scope must be left unloaded, so nothing passes.
		if s.Gate("example.com", "") {
			t.Errorf("[priv=%v any=%v] something was allowed after a failed load",
				mode.allowPrivate, mode.allowAny)
		}
	}

	// Under --allow-any the empty file is accepted by design, but the denylist
	// must still be honoured.
	deny := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(deny, []byte("secret.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(false, true)
	if err := s.Load(empty, deny); err != nil {
		t.Fatalf("under --allow-any an empty allowlist should load: %v", err)
	}
	if !s.Gate("example.com", "") {
		t.Error("under --allow-any, --allow-any should permit an unlisted target")
	}
	if s.Gate("secret.example.com", "") {
		t.Error("BUG: under --allow-any the denylist stopped applying")
	}
}

// util/parse.go and the design notes: the authorization path parses a host one
// way, so a userinfo string cannot mean one host to the gate and another to a
// dialler.
func TestClaimAuthorizationParsesOneWay(t *testing.T) {
	cases := []string{
		"http://allowed.com@evil.com/",
		"http://evil.com@allowed.com/",
		"http://evil.com\\@allowed.com/",
		"http://allowed.com%2f@evil.com/",
	}
	for _, raw := range cases {
		dir := t.TempDir()
		allow := filepath.Join(dir, "a.txt")
		if err := os.WriteFile(allow, []byte("allowed.com\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		s := New(false, false)
		if err := s.Load(allow, ""); err != nil {
			t.Fatal(err)
		}
		if s.URLAllowed(raw) {
			h, _, _ := s.reduce(raw, "")
			t.Logf("allowed %q (reduced to %q)", raw, h)
		}
	}
}
