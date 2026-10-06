package scope

import (
	"os"
	"path/filepath"
	"testing"
)

// benchScope builds a scope that resembles a real allowlist: several apex
// domains, wildcards, address ranges and host:port pins.
func benchScope(b *testing.B) *Scope {
	b.Helper()

	dir := b.TempDir()
	allow := filepath.Join(dir, "allow.txt")
	deny := filepath.Join(dir, "deny.txt")

	allowLines := []string{
		"example.com",
		"*.wild.test",
		"corp.example.org",
		"*.internal.example.org",
		"192.0.2.0/24",
		"198.51.100.0/24",
		"2001:db8::/32",
		"example.com:8443",
		"203.0.113.0/24",
	}
	denyLines := []string{
		"admin.example.com",
		"*.dev.wild.test",
		"192.0.2.8",
		"old.example.org",
		"example.com:9000",
	}

	if err := os.WriteFile(allow, []byte(joinLines(allowLines)), 0o600); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(deny, []byte(joinLines(denyLines)), 0o600); err != nil {
		b.Fatal(err)
	}

	s := New(false, false)
	if err := s.Load(allow, deny); err != nil {
		b.Fatalf("Load: %v", err)
	}
	return s
}

func joinLines(in []string) string {
	out := ""
	for _, l := range in {
		out += l + "\n"
	}
	return out
}

// benchTargets is a mix of hits, near-misses and denials, because a benchmark
// of only allowed targets measures the cheapest path through the gate.
var benchTargets = []struct {
	target string
	port   string
}{
	{"example.com", ""},
	{"api.example.com", ""},
	{"a.b.c.example.com", ""},
	{"deep.nested.internal.example.org", ""},
	{"x.wild.test", ""},
	{"x.y.wild.test", ""},
	{"192.0.2.5", ""},
	{"198.51.100.200", "443"},
	{"2001:db8::10", ""},
	{"example.com", "8443"},
	{"admin.example.com", ""},
	{"a.dev.wild.test", ""},
	{"192.0.2.8", ""},
	{"example.com", "9000"},
	{"notexample.com", ""},
	{"example.com.attacker.test", ""},
	{"unrelated.test", ""},
	{"[2001:db8::10]:443", ""},
}

// BenchmarkGate measures the per-target decision, which runs once for every
// host and every discovered URL.
func BenchmarkGate(b *testing.B) {
	s := benchScope(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, t := range benchTargets {
			s.Gate(t.target, t.port)
		}
	}
}

// BenchmarkGateSingle measures one lookup, which is the granularity a caller
// actually sees.
func BenchmarkGateSingle(b *testing.B) {
	s := benchScope(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Gate("api.example.com", "")
	}
}

// BenchmarkGateURL measures the URL form, which parses more.
func BenchmarkGateURL(b *testing.B) {
	s := benchScope(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Gate("https://api.example.com/v1/users", "")
	}
}

// BenchmarkExplain measures the diagnostic path behind --why-denied.
func BenchmarkExplain(b *testing.B) {
	s := benchScope(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Explain("api.example.com", "")
	}
}

// BenchmarkRules measures the dry-run plan, which builds and sorts every rule.
func BenchmarkRules(b *testing.B) {
	s := benchScope(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Rules()
	}
}

// BenchmarkLoad measures loading a scope file, which happens once per run.
func BenchmarkLoad(b *testing.B) {
	dir := b.TempDir()
	allow := filepath.Join(dir, "allow.txt")
	deny := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(allow, []byte(joinLines([]string{
		"example.com", "*.wild.test", "192.0.2.0/24", "198.51.100.0/24",
		"2001:db8::/32", "example.com:8443", "203.0.113.0/24",
		"corp.example.org", "*.internal.example.org",
	})), 0o600); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(deny, []byte(joinLines([]string{
		"admin.example.com", "*.dev.wild.test", "192.0.2.8",
	})), 0o600); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := New(false, false)
		if err := s.Load(allow, deny); err != nil {
			b.Fatal(err)
		}
	}
}
