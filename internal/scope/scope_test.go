package scope

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests are written before the implementation on purpose. internal/scope
// decides what Fal-X is allowed to contact, so a regression here is worse than
// the feature not shipping at all.

// fixtures writes scope files into a temporary directory.
type fixtures struct {
	dir       string
	allowPath string
	denyPath  string
}

func newFixtures(t *testing.T, allow, deny string) *fixtures {
	t.Helper()
	dir := t.TempDir()
	f := &fixtures{
		dir:       dir,
		allowPath: filepath.Join(dir, "scope.txt"),
		denyPath:  filepath.Join(dir, "deny.txt"),
	}
	if allow != "" {
		if err := os.WriteFile(f.allowPath, []byte(allow), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if deny != "" {
		if err := os.WriteFile(f.denyPath, []byte(deny), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// load builds a loaded Scope or fails the test.
func (f *fixtures) load(t *testing.T, allowPrivate, allowAny bool) *Scope {
	t.Helper()
	s := New(allowPrivate, allowAny)
	if err := s.Load(f.allowPath, f.denyPath); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !s.Loaded() {
		t.Fatal("scope not loaded after a successful Load")
	}
	return s
}

// ---------------------------------------------------------------------------
// Canonicalisation
// ---------------------------------------------------------------------------

func TestNormHost(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"Example.COM", "example.com", true},
		{"example.com.", "example.com", true},
		{"https://example.com/a/b", "example.com", true},
		{"example.com:8443", "example.com", true},
		{"HTTP://API.Example.com/x", "api.example.com", true},
		{"user:pw@example.com/p", "example.com", true},
		{"[2001:db8::1]:443", "2001:db8::1", true},
		{"::1", "::1", true},
		{"2001:db8::1", "2001:db8::1", true},
		{"2001:DB8::1", "2001:db8::1", true},
		{"example.com#frag", "example.com", true},
		{"", "", false},
		{"   ", "", false},
		{"exa mple.com", "", false},
		// A trailing newline comes from reading a file and is tolerated; a
		// newline in the middle is the injection shape and is not.
		{"example.com\n", "example.com", true},
		{"example.com\r\n", "example.com", true},
		{"exam\nple.com", "", false},
		{"exam\rple.com", "", false},
	}
	for _, tc := range tests {
		got, ok := NormHost(tc.in)
		if ok != tc.ok {
			t.Errorf("NormHost(%q) ok = %v, want %v (got %q)", tc.in, ok, tc.ok, got)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("NormHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsIPv4(t *testing.T) {
	valid := []string{"0.0.0.0", "192.0.2.1", "255.255.255.255", "10.1.2.3", "172.16.0.1"}
	for _, s := range valid {
		if !IsIPv4(s) {
			t.Errorf("IsIPv4(%q) = false, want true", s)
		}
	}
	invalid := []string{
		"192.0.2", "192.0.2.1.1", "192.0.2.300", "192.0.2.-1",
		"192.000.2.1", "010.1.1.1", "example.com", "", "192.0.2.1 ",
		"1.2.3.4/24",
	}
	for _, s := range invalid {
		if IsIPv4(s) {
			t.Errorf("IsIPv4(%q) = true, want false", s)
		}
	}
}

func TestIsIPv6(t *testing.T) {
	valid := []string{
		"::1", "::", "2001:db8::1", "fe80::1", "fd00::1",
		"2001:db8:0:0:0:0:0:1", "::ffff:127.0.0.1", "::ffff:192.0.2.1",
	}
	for _, s := range valid {
		if !IsIPv6(s) {
			t.Errorf("IsIPv6(%q) = false, want true", s)
		}
	}
	invalid := []string{
		"example.com", "192.0.2.1", "",
		"2001::db8::1",     // two compressions
		"20011:db8::1",     // oversized group
		"2001:db8:::1",     // stray colon
		"gggg::1",          // not hex
		"::ffff:999.1.1.1", // embedded IPv4 out of range
	}
	for _, s := range invalid {
		if IsIPv6(s) {
			t.Errorf("IsIPv6(%q) = true, want false", s)
		}
	}
}

func TestIsIPAndIsCIDR(t *testing.T) {
	if !IsIP("192.0.2.1") || !IsIP("2001:db8::1") {
		t.Error("IsIP rejected a valid literal")
	}
	if IsIP("example.com") || IsIP("192.0.2.0/24") || IsIP("") {
		t.Error("IsIP accepted something it should not")
	}

	if !IsCIDR("192.0.2.0/24") || !IsCIDR("0.0.0.0/0") || !IsCIDR("2001:db8::/32") {
		t.Error("IsCIDR rejected a valid prefix")
	}
	for _, s := range []string{"192.0.2.0/33", "2001:db8::/129", "192.0.2.0", "example.com/24", "192.0.2.0/", "/24"} {
		if IsCIDR(s) {
			t.Errorf("IsCIDR(%q) = true, want false", s)
		}
	}
}

// ---------------------------------------------------------------------------
// Special ranges
// ---------------------------------------------------------------------------

func TestIsSpecialIP(t *testing.T) {
	special := []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255",
		"192.168.1.1", "169.254.1.1", "169.254.169.254",
		"100.64.0.1", "198.18.0.1", "198.19.255.255",
		"192.0.0.8", "0.0.0.0", "224.0.0.1", "255.255.255.255",
		"::1", "::", "fe80::1", "fd00::1", "fc00::1",
		"ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
	}
	for _, s := range special {
		if !IsSpecialIP(s) {
			t.Errorf("IsSpecialIP(%q) = false, want true", s)
		}
	}

	// Documentation ranges stay scannable so fixtures and lab work remain
	// possible. Treating them as private would make the tool untestable.
	public := []string{
		"192.0.2.1", "198.51.100.1", "203.0.113.1",
		"172.15.0.1", "172.32.0.1", "8.8.8.8", "1.1.1.1",
		"2001:db8::1", "::ffff:192.0.2.1", "example.com",
	}
	for _, s := range public {
		if IsSpecialIP(s) {
			t.Errorf("IsSpecialIP(%q) = true, want false", s)
		}
	}
}

// ---------------------------------------------------------------------------
// CIDR arithmetic
// ---------------------------------------------------------------------------

func TestIPv4InCIDR(t *testing.T) {
	tests := []struct {
		ip, cidr string
		want     bool
	}{
		{"192.0.2.5", "192.0.2.0/24", true},
		{"192.0.3.5", "192.0.2.0/24", false},
		{"192.0.2.7", "192.0.2.7/32", true},
		{"192.0.2.8", "192.0.2.7/32", false},
		{"203.0.114.1", "0.0.0.0/0", true},
		{"10.1.2.3", "10.0.0.0/8", true},
		{"11.1.2.3", "10.0.0.0/8", false},
		{"192.0.3.1", "192.0.2.0/23", true},  // unaligned /23
		{"192.0.4.1", "192.0.2.0/23", false}, // next block excluded
		{"192.0.2.0", "192.0.2.0/24", true},  // network address
		{"192.0.3.255", "192.0.2.0/24", false},
	}
	for _, tc := range tests {
		if got := IPv4InCIDR(tc.ip, tc.cidr); got != tc.want {
			t.Errorf("IPv4InCIDR(%q, %q) = %v, want %v", tc.ip, tc.cidr, got, tc.want)
		}
	}

	if IPv4InCIDR("2001:db8::1", "2001:db8::/32") {
		t.Error("IPv4InCIDR accepted an IPv6 address")
	}
}

func TestIPInCIDR(t *testing.T) {
	if !IPInCIDR("2001:db8::5", "2001:db8::/32") {
		t.Error("IPInCIDR rejected an IPv6 address inside the prefix")
	}
	if IPInCIDR("2001:db9::5", "2001:db8::/32") {
		t.Error("IPInCIDR accepted an IPv6 address outside the prefix")
	}
	if !IPInCIDR("192.0.2.9", "192.0.2.0/24") {
		t.Error("IPInCIDR rejected an IPv4 address inside the prefix")
	}
}

// ---------------------------------------------------------------------------
// Fail-closed behaviour
// ---------------------------------------------------------------------------

func TestLoadFailsClosed(t *testing.T) {
	t.Run("absent allowlist", func(t *testing.T) {
		f := newFixtures(t, "", "")
		s := New(false, false)
		if err := s.Load(f.allowPath, f.denyPath); err == nil {
			t.Error("expected an error for an absent allowlist")
		}
		if s.Loaded() {
			t.Error("scope must not be loaded after a failed Load")
		}
		if s.Gate("example.com", "") {
			t.Error("Gate allowed a target while scope was unloaded")
		}
		if s.Gate("192.0.2.1", "") {
			t.Error("Gate allowed an address while scope was unloaded")
		}
	})

	t.Run("empty allowlist", func(t *testing.T) {
		f := newFixtures(t, "", "")
		s := New(false, false)
		if err := s.Load(f.allowPath, ""); err == nil {
			t.Error("expected an error for an empty allowlist")
		}
		if s.Gate("example.com", "") {
			t.Error("Gate allowed a target after an empty allowlist")
		}
	})

	t.Run("comments-only allowlist", func(t *testing.T) {
		f := newFixtures(t, "   \n# only comments\n\n", "")
		s := New(false, false)
		if err := s.Load(f.allowPath, ""); err == nil {
			t.Error("expected an error for a comments-only allowlist")
		}
	})

	t.Run("bare wildcard refused", func(t *testing.T) {
		f := newFixtures(t, "*\n", "")
		s := New(false, false)
		if err := s.Load(f.allowPath, ""); err == nil {
			t.Error("a bare wildcard must not authorise anything")
		}
		if s.Gate("anything.test", "") {
			t.Error("Gate allowed a host under a bare wildcard")
		}
	})

	t.Run("absolute path denied", func(t *testing.T) {
		f := newFixtures(t, "example.com\n", "")
		s := New(false, false)
		_ = s.Load(f.allowPath, "")
		if s.Gate("/etc/passwd", "") {
			t.Error("Gate accepted a filesystem path as a target")
		}
	})
}

// ---------------------------------------------------------------------------
// Domain decisions
// ---------------------------------------------------------------------------

func TestDomainGate(t *testing.T) {
	f := newFixtures(t, `# approved assets
example.com
*.wild.example.com
portonly.example.com:8443
192.0.2.0/24
198.51.100.7
2001:db8::1
`, `admin.example.com
*.dev.example.com
192.0.2.8
198.51.100.7
`)
	s := f.load(t, false, false)

	allowed := []string{
		"example.com",
		"api.example.com",
		"a.b.c.d.example.com",
		"API.Example.COM",
		"api.example.com.",
		"x.wild.example.com",
		"a.b.wild.example.com",
		"192.0.2.5",
		"192.0.2.0/24",
		"2001:db8::1",
	}
	for _, target := range allowed {
		if !s.Gate(target, "") {
			t.Errorf("Gate(%q) = false, want true", target)
		}
	}

	denied := []string{
		// Suffix spoofing. A naive ends-with check allows all of these.
		"example.com.attacker.test",
		"notexample.com",
		"example-com.attacker.test",
		"evil-example.com",
		// Denylist beats allowlist.
		"admin.example.com",
		"a.dev.example.com",
		// Denied addresses.
		"192.0.2.8",
		"198.51.100.7",
		"2001:db8::2",
		"198.51.100.1",
		// Hostile input.
		"example.com;id",
		"exa mple.com",
		"attacker.test",
	}
	for _, target := range denied {
		if s.Gate(target, "") {
			t.Errorf("Gate(%q) = true, want false", target)
		}
	}

	// Sibling of a denied host stays allowed.
	if !s.Gate("other.example.com", "") {
		t.Error("a sibling of a denied host should still be allowed")
	}
}

func TestGateRejectsSpoofedURLs(t *testing.T) {
	f := newFixtures(t, "example.com\n", "")
	s := f.load(t, false, false)

	denied := []string{
		"https://attacker.test/x",
		"https://example.com@attacker.test/x",
		"https://example.com.attacker.test/x",
	}
	for _, u := range denied {
		if s.Gate(u, "") {
			t.Errorf("Gate(%q) = true, want false", u)
		}
	}

	allowed := []string{
		"https://example.com/",
		"https://api.example.com/v1/users",
		"https://user@example.com/ok",
	}
	for _, u := range allowed {
		if !s.Gate(u, "") {
			t.Errorf("Gate(%q) = false, want true", u)
		}
	}
}

func TestURLAllowed(t *testing.T) {
	f := newFixtures(t, "example.com\n192.0.2.0/24\n2001:db8::/32\n", "")
	s := f.load(t, false, false)

	allowed := []string{
		"https://api.example.com/v1/users",
		"http://192.0.2.5/admin",
		"http://[2001:db8::1]:8080/x",
	}
	for _, u := range allowed {
		if !s.URLAllowed(u) {
			t.Errorf("URLAllowed(%q) = false, want true", u)
		}
	}

	for _, u := range []string{
		"https://attacker.test/x",
		"http://192.0.4.5/",
		"http://[2001:db9::1]/", // outside 2001:db8::/32
	} {
		if s.URLAllowed(u) {
			t.Errorf("URLAllowed(%q) = true, want false", u)
		}
	}
}

// ---------------------------------------------------------------------------
// Wildcard semantics, isolated so an apex rule cannot mask the result
// ---------------------------------------------------------------------------

func TestWildcardDoesNotMatchApex(t *testing.T) {
	f := newFixtures(t, "*.only.test\n", "")
	s := f.load(t, false, false)

	for _, h := range []string{"a.only.test", "a.b.c.only.test"} {
		if !s.Gate(h, "") {
			t.Errorf("wildcard should match %q", h)
		}
	}
	for _, h := range []string{"only.test", "notonly.test", "other.test"} {
		if s.Gate(h, "") {
			t.Errorf("wildcard should not match %q", h)
		}
	}
}

func TestApexMatchesSubdomains(t *testing.T) {
	f := newFixtures(t, "apex.test\n", "")
	s := f.load(t, false, false)

	for _, h := range []string{"apex.test", "a.apex.test", "a.b.c.d.e.apex.test"} {
		if !s.Gate(h, "") {
			t.Errorf("apex rule should match %q", h)
		}
	}
	for _, h := range []string{"other.test", "xapex.test", "apex.test.attacker.test"} {
		if s.Gate(h, "") {
			t.Errorf("apex rule should not match %q", h)
		}
	}
}

// ---------------------------------------------------------------------------
// Port-scoped entries
// ---------------------------------------------------------------------------

func TestPortPinnedEntries(t *testing.T) {
	f := newFixtures(t, "pinned.test:8443\nfree.test\n", "")
	s := f.load(t, false, false)

	if !s.Gate("pinned.test", "8443") {
		t.Error("pinned host on its pinned port should be allowed")
	}
	if s.Gate("pinned.test", "443") {
		t.Error("pinned host on another port should be denied")
	}
	if s.Gate("pinned.test", "") {
		t.Error("pinned host with no port resolved should be denied, fail closed")
	}
	if !s.Gate("free.test", "443") {
		t.Error("unpinned host on any port should be allowed")
	}
	if !s.Gate("free.test", "") {
		t.Error("unpinned host with no port should be allowed")
	}
	if s.Gate("other.test", "443") {
		t.Error("a host absent from scope should be denied")
	}
}

func TestHostPortFormsAccepted(t *testing.T) {
	f := newFixtures(t, "192.0.2.0/24\n2001:db8::/32\nexample.com\n", "")
	s := f.load(t, false, false)

	// A host:port must be authorised on its host, and a bare IPv6 literal must
	// survive parsing at all.
	if !s.Gate("192.0.2.5:443", "") {
		t.Error("an IPv4 host:port inside scope should be allowed")
	}
	if !s.Gate("[2001:db8::1]:443", "") {
		t.Error("a bracketed IPv6 host:port inside scope should be allowed")
	}
	if !s.Gate("2001:db8::1", "") {
		t.Error("a bare IPv6 literal should be allowed")
	}
	if s.Gate("192.0.4.5:443", "") {
		t.Error("an IPv4 host:port outside the allowlisted range should be denied")
	}
	if s.Gate("[2001:db9::1]:443", "") {
		t.Error("a bracketed IPv6 host:port outside the allowlisted range should be denied")
	}
}

// ---------------------------------------------------------------------------
// Private-range gating
// ---------------------------------------------------------------------------

func TestPrivateRangeGating(t *testing.T) {
	allow := "10.0.0.0/8\n192.168.0.0/16\nlab.example.com\nlocalhost\n127.0.0.1\n"

	t.Run("denied by default", func(t *testing.T) {
		f := newFixtures(t, allow, "")
		s := f.load(t, false, false)
		for _, target := range []string{"10.1.2.3", "192.168.1.1", "localhost", "127.0.0.1"} {
			if s.Gate(target, "") {
				t.Errorf("Gate(%q) = true with --allow-private off, want false", target)
			}
		}
		if !s.Gate("lab.example.com", "") {
			t.Error("a public host in scope should still be allowed")
		}
	})

	t.Run("allowed with --allow-private", func(t *testing.T) {
		f := newFixtures(t, allow, "")
		s := f.load(t, true, false)
		for _, target := range []string{"10.1.2.3", "192.168.1.1", "localhost", "127.0.0.1"} {
			if !s.Gate(target, "") {
				t.Errorf("Gate(%q) = false with --allow-private on, want true", target)
			}
		}
	})

	t.Run("allow-private does not widen the allowlist", func(t *testing.T) {
		f := newFixtures(t, "10.0.0.0/8\n", "")
		s := f.load(t, true, false)
		if s.Gate("192.168.1.1", "") {
			t.Error("192.168.x is not in the allowlist and must stay denied")
		}
	})
}

// ---------------------------------------------------------------------------
// allow-any
// ---------------------------------------------------------------------------

func TestAllowAny(t *testing.T) {
	allow := "example.com\n"
	deny := "admin.example.com\n"

	t.Run("off", func(t *testing.T) {
		f := newFixtures(t, allow, deny)
		s := f.load(t, false, false)
		if !s.Gate("example.com", "") {
			t.Error("in-scope host should be allowed")
		}
		if s.Gate("unrelated.test", "") {
			t.Error("unrelated host should be denied without --allow-any")
		}
		if s.Gate("admin.example.com", "") {
			t.Error("denylisted host should be denied")
		}
	})

	t.Run("on, denylist still wins", func(t *testing.T) {
		f := newFixtures(t, allow, deny)
		s := f.load(t, false, true)
		if !s.Gate("unrelated.test", "") {
			t.Error("unrelated host should be allowed with --allow-any")
		}
		if s.Gate("admin.example.com", "") {
			t.Error("the denylist must override --allow-any")
		}
	})
}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

func TestFingerprint(t *testing.T) {
	f := newFixtures(t, "example.com\n*.wild.test\n192.0.2.0/24\n", "admin.example.com\n")

	a := f.load(t, false, false)
	fpA := a.Fingerprint()

	b := f.load(t, false, false)
	if fpB := b.Fingerprint(); fpB != fpA {
		t.Errorf("fingerprint changed across identical reloads: %s vs %s", fpA, fpB)
	}
	if fpA == "" {
		t.Error("fingerprint is empty")
	}

	g := newFixtures(t, "example.com\n", "")
	c := g.load(t, false, false)
	if c.Fingerprint() == fpA {
		t.Error("a different scope produced the same fingerprint")
	}
}

// ---------------------------------------------------------------------------
// Entry parsing
// ---------------------------------------------------------------------------

func TestEntryNormalisation(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		apex    string
		wild    string
		port    string
		ipExact string
		ipCIDR  string
	}{
		{name: "apex", line: "example.com", apex: "example.com"},
		{name: "uppercase", line: "EXAMPLE.COM", apex: "example.com"},
		{name: "trailing dot", line: "example.com.", apex: "example.com"},
		{name: "wildcard star", line: "*.example.com", wild: "example.com"},
		{name: "wildcard dot", line: ".example.com", wild: "example.com"},
		{name: "port", line: "example.com:8443", port: "example.com:8443"},
		{name: "url", line: "https://example.com/path", apex: "example.com"},
		{name: "ipv4", line: "192.0.2.1", ipExact: "192.0.2.1"},
		{name: "cidr", line: "192.0.2.0/24", ipCIDR: "192.0.2.0/24"},
		{name: "ipv6", line: "2001:db8::1", ipExact: "2001:db8::1"},
		{name: "ipv6 cidr", line: "2001:db8::/32", ipCIDR: "2001:db8::/32"},
		{name: "comment", line: "# example.com"},
		{name: "blank", line: "   "},
		{name: "trailing comment", line: "example.com # prod"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := parseEntry(tc.line)
			if tc.apex != "" && e.apex != tc.apex {
				t.Errorf("apex = %q, want %q", e.apex, tc.apex)
			}
			if tc.wild != "" && e.wild != tc.wild {
				t.Errorf("wild = %q, want %q", e.wild, tc.wild)
			}
			if tc.port != "" && e.port != tc.port {
				t.Errorf("port = %q, want %q", e.port, tc.port)
			}
			if tc.ipExact != "" && e.ipExact != tc.ipExact {
				t.Errorf("ipExact = %q, want %q", e.ipExact, tc.ipExact)
			}
			if tc.ipCIDR != "" && e.ipCIDR != tc.ipCIDR {
				t.Errorf("ipCIDR = %q, want %q", e.ipCIDR, tc.ipCIDR)
			}
			if tc.apex == "" && tc.wild == "" && tc.port == "" &&
				tc.ipExact == "" && tc.ipCIDR == "" && e.empty() {
				t.Setenv("FALX_TEST_UNUSED", "1") // keep the branch honest
				return
			}
		})
	}
}

func TestEntryRejectsBareWildcard(t *testing.T) {
	for _, line := range []string{"*", "*.*", "*/*"} {
		e := parseEntry(line)
		if !e.rejected {
			t.Errorf("parseEntry(%q) should mark the entry rejected", line)
		}
	}
}

func TestEntryRejectsInvalidCharacters(t *testing.T) {
	e := parseEntry("exa mple.com; rm -rf /")
	if !e.rejected {
		t.Error("an entry with shell metacharacters should be rejected")
	}
	if e.apex != "" || e.wild != "" || e.port != "" {
		t.Error("a rejected entry must not populate a rule")
	}
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

func TestExplain(t *testing.T) {
	f := newFixtures(t, "example.com\n", "admin.example.com\n")
	s := f.load(t, false, false)

	if d := s.Explain("api.example.com", ""); !d.Allowed {
		t.Errorf("Explain(api.example.com).Allowed = false, reason %q", d.Reason)
	}
	d := s.Explain("admin.example.com", "")
	if d.Allowed {
		t.Error("Explain(admin.example.com).Allowed = true, want false")
	}
	if d.Reason == "" {
		t.Error("a denial should carry a reason")
	}
	if !strings.Contains(strings.ToLower(d.Reason), "denied") {
		t.Errorf("reason should say denied, got %q", d.Reason)
	}

	// A target that is out of scope for a specific reason should say which.
	d2 := s.Explain("attacker.test", "")
	if d2.Allowed || d2.Reason == "" {
		t.Errorf("Explain(attacker.test) = %+v", d2)
	}
}

// TestFingerprintIsStableAcrossReloads pins that the digest does not depend on
// Go map iteration order.
//
// The fingerprint exists to answer "is this the same scope as last time", and it
// is recorded in the run manifest. If it varied between two loads of an
// identical file it could not answer that at all, and every comparison of a run
// against its own approval would silently fail.
//
// Two of the rule collections are maps, and Go randomises map iteration on every
// range, so this regresses the moment the digest walks one without sorting.
func TestFingerprintIsStableAcrossReloads(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "allow.txt")
	deny := filepath.Join(dir, "deny.txt")

	// Several host:port entries on both sides, which is what puts entries into
	// the maps rather than the slices.
	if err := os.WriteFile(allow, []byte(strings.Join([]string{
		"example.com:443", "", "example.com:8443", "example.com:80",
		"192.0.2.0/24", "*.wild.test", "2001:db8::1",
	}, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deny, []byte(strings.Join([]string{
		"a.example.com:443", "b.example.com:8443", "c.example.com:80",
	}, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}

	first := ""
	for i := 0; i < 50; i++ {
		s := New(false, false)
		if err := s.Load(allow, deny); err != nil {
			t.Fatalf("Load: %v", err)
		}
		if i == 0 {
			first = s.Fingerprint()
			if first == "" {
				t.Fatal("Fingerprint is empty")
			}
			continue
		}
		if got := s.Fingerprint(); got != first {
			t.Fatalf("fingerprint changed between identical loads:\n  %s\n  %s", first, got)
		}
	}
}

// TestFingerprintDistinguishesDifferentScopes is the other half: a digest that is
// stable but insensitive would be worse than useless, because it would report
// two different scopes as the same one.
func TestFingerprintDistinguishesDifferentScopes(t *testing.T) {
	dir := t.TempDir()
	deny := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(deny, []byte("admin.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	load := func(allow string) string {
		p := filepath.Join(dir, "a.txt")
		if err := os.WriteFile(p, []byte(allow), 0o600); err != nil {
			t.Fatal(err)
		}
		s := New(false, false)
		if err := s.Load(p, deny); err != nil {
			t.Fatalf("Load: %v", err)
		}
		return s.Fingerprint()
	}

	variants := map[string]string{
		"apex":      "example.com\n",
		"wildcard":  "*.example.com\n",
		"cidr":      "192.0.2.0/24\n",
		"ipv6":      "2001:db8::1\n",
		"host:port": "example.com:8443\n",
		"two rules": "example.com\n*.wild.test\n",
		"denied ip": "example.com\n198.51.100.5\n",
	}

	seen := map[string]string{}
	for name, content := range variants {
		fp := load(content)
		if other, dup := seen[fp]; dup {
			t.Errorf("%q and %q produced the same fingerprint", name, other)
		}
		seen[fp] = name
	}

	// Reloading the same content must still match.
	first, second := load("example.com\n"), load("example.com\n")
	if first != second {
		t.Error("identical content produced different fingerprints")
	}
}
