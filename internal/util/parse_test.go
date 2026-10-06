package util

import (
	"strings"
	"testing"
)

// A bare address must survive verbatim. Port scanners emit them, and a caller
// that assumed a hostname here would silently drop them.
func TestURLHost(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"https://example.com/a/b?c=1", "example.com", true},
		{"http://example.com", "example.com", true},
		{"https://api.example.com:8443/health", "api.example.com", true},
		{"https://user:pw@example.com/x", "example.com", true},

		// Bracketed IPv6 keeps its colons. Stripping at the first colon here
		// is the B01 bug this whole function exists to prevent.
		{"http://[::1]:8080/x", "::1", true},
		{"http://[2001:db8::1]/", "2001:db8::1", true},

		{"https://example.com/#frag", "example.com", true},
		{"example.com/path", "example.com", true},
		{"https://example.com?a=b", "example.com", true},

		// No host can be determined.
		{"", "", false},
		{"https://", "", false},
		{"https:///path", "", false},

		// A userinfo-only authority has no host.
		{"https://user@example.com@", "", false},
	}

	for _, tc := range cases {
		got, ok := URLHost(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("URLHost(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestURLHostReturnsBareIP pins that a bare address survives intact, since port
// scanners emit them and no stage parses a URL before handing it on.
//
// The assertion is on the exact value, not merely non-emptiness. A weaker check
// let a bug through that split a bare IPv6 literal at its first colon and
// returned "2001" for "2001:db8::1".
func TestURLHostReturnsBareIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"192.0.2.5", "192.0.2.5"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"::1", "::1"},
		{"::", "::"},
	}
	for _, tc := range cases {
		got, ok := URLHost(tc.in)
		if !ok {
			t.Errorf("URLHost(%q) reported no host", tc.in)
			continue
		}
		if got != tc.want {
			t.Errorf("URLHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestURLPort pins that a port is read only from where one really is.
func TestURLPort(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://api.example.com:8443/h", "8443"},
		{"https://example.com/", ""},
		{"http://[::1]:8080/x", "8080"},
		{"https://[::1]/x", ""},

		// A colon in the path is not a port. Getting this wrong turns
		// "example.com/a:b" into a request on port "b".
		{"https://example.com/a:b", ""},

		// Non-numeric ports are dropped rather than passed through.
		{"https://example.com:notaport/", ""},
		{"", ""},
	}

	for _, tc := range cases {
		if got := URLPort(tc.in); got != tc.want {
			t.Errorf("URLPort(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestHostPortSplit is the B01/B02 regression test.
//
// Naive `cut -d: -f1` turns "::1" into an empty host and "[::1]:443" into "[".
// Every form naabu, nmap and httpx emit has to survive the round trip.
func TestHostPortSplit(t *testing.T) {
	cases := []struct {
		in       string
		host     string
		port     string
		testName string
	}{
		{"[::1]:443", "::1", "443", "bracketed IPv6 with port"},
		{"::1", "::1", "", "bare IPv6, no port"},
		{"2001:db8::1", "2001:db8::1", "", "bare IPv6, full form"},
		{"[2001:db8::1]", "2001:db8::1", "", "bracketed IPv6, no port"},
		{"[2001:db8::1]:8443", "2001:db8::1", "8443", "bracketed IPv6 full form with port"},
		{"example.com:8443", "example.com", "8443", "hostname:port"},
		{"example.com", "example.com", "", "hostname only"},
		{"192.0.2.5:443", "192.0.2.5", "443", "IPv4:port"},
		{"https://example.com:443/p?q=1", "example.com", "443", "URL form"},
		{"http://[2001:db8::1]:8443/", "2001:db8::1", "8443", "IPv6 URL form"},
		{"https://user@example.com/", "example.com", "", "strips userinfo"},
		{"example.com:notaport", "example.com", "", "non-numeric port rejected"},
		{"", "", "", "empty input"},

		// nuclei prints its findings with the whole URL wrapped in brackets.
		// Reducing the scheme first left a stray bracket glued to the host name,
		// so "example.com]" reached the scope gate and matched nothing. The
		// finding was then dropped from the report even though its host was
		// in scope.
		{"[https://example.com]", "example.com", "", "bracket-wrapped URL"},
		{"[https://example.com:8443]", "example.com", "8443", "bracket-wrapped URL with port"},
	}

	for _, tc := range cases {
		host, port := HostPortSplit(tc.in)
		if host != tc.host || port != tc.port {
			t.Errorf("HostPortSplit(%q) = (%q, %q), want (%q, %q) [%s]",
				tc.in, host, port, tc.host, tc.port, tc.testName)
		}
	}
}

// TestHostPortSplitRoundTrips pins that a host and port produced by
// HostPortSplit can be re-joined and split again unchanged.
func TestHostPortSplitRoundTrips(t *testing.T) {
	for _, in := range []string{
		"example.com:8443", "192.0.2.5:443", "[2001:db8::1]:8443", "[::1]:443",
	} {
		host, port := HostPortSplit(in)
		if host == "" {
			t.Errorf("HostPortSplit(%q) produced an empty host", in)
			continue
		}
		// Rejoining an IPv6 host needs the bracket form, which is what
		// JoinHostPort must therefore produce.
		joined := JoinHostPort(host, port)
		gotHost, gotPort := HostPortSplit(joined)
		if gotHost != host || gotPort != port {
			t.Errorf("round trip of %q via %q gave (%q, %q)", in, joined, gotHost, gotPort)
		}
	}
}

// TestJoinHostPort pins the bracket rule, since getting it wrong produces a
// URL that no client can parse.
func TestJoinHostPort(t *testing.T) {
	cases := []struct {
		host, port, want string
	}{
		{"example.com", "8443", "example.com:8443"},
		{"example.com", "", "example.com"},
		{"192.0.2.5", "443", "192.0.2.5:443"},
		{"::1", "443", "[::1]:443"},
		{"2001:db8::1", "8443", "[2001:db8::1]:8443"},
		{"2001:db8::1", "", "[2001:db8::1]"},
	}
	for _, tc := range cases {
		if got := JoinHostPort(tc.host, tc.port); got != tc.want {
			t.Errorf("JoinHostPort(%q, %q) = %q, want %q", tc.host, tc.port, got, tc.want)
		}
	}
}

// TestSplitScheme pins that a missing scheme yields "" rather than the input.
func TestSplitScheme(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://example.com", "https"},
		{"http://example.com", "http"},
		{"ftp://example.com", "ftp"},
		{"example.com", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := SplitScheme(tc.in); got != tc.want {
			t.Errorf("SplitScheme(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestValidDomain pins the hostname grammar.
//
// The interesting part is the length and label rules. Too permissive a pattern
// is how "example.com.attacker.test" and "notexample.com" get treated as
// in-scope, which is why the scope gate does not use this function alone.
func TestValidDomain(t *testing.T) {
	valid := []string{
		"example.com", "api.example.com", "a.b.c.d.example.com",
		"xn--bcher-kva.example.com", "host1.example.com",
		"example-site.com", "EXAMPLE.COM",
		// A single label is legal in DNS and appears in host files.
		"localhost",
		// 63 characters is the maximum label length, so it must be accepted.
		// The 64-character case below is the one that has to fail.
		label63() + ".com",
	}
	for _, h := range valid {
		if !ValidDomain(h) {
			t.Errorf("ValidDomain(%q) = false, want true", h)
		}
	}

	invalid := []string{
		"", ".", "..", "example..com", ".example.com", "example.com.",
		"-example.com", "example-.com", "exa mple.com",
		"exam\nple.com", "exam\rple.com", "exa\tmple.com",
		"https://example.com", "example.com/path", "user@example.com",
		"example.com:8443", "[2001:db8::1]", "2001:db8::1", "192.0.2.5",
		label64() + ".com", "exam!ple.com", "exam$ple.com",
	}
	for _, h := range invalid {
		if ValidDomain(h) {
			t.Errorf("ValidDomain(%q) = true, want false", h)
		}
	}
}

// label63 returns a label of exactly 63 characters, the DNS maximum.
func label63() string {
	return strings.Repeat("a", 63)
}

// label64 returns a label of 64 characters, one over the maximum.
func label64() string {
	return strings.Repeat("a", 64)
}

// TestIsIPv4 pins strictness. netip.ParseAddr accepts forms a scanner must not,
// and a leading-zero address is ambiguous between octal and decimal.
func TestIsIPv4(t *testing.T) {
	for _, s := range []string{"0.0.0.0", "192.0.2.5", "255.255.255.255", "1.2.3.4"} {
		if !IsIPv4(s) {
			t.Errorf("IsIPv4(%q) = false, want true", s)
		}
	}
	for _, s := range []string{
		"", "256.0.0.1", "1.2.3", "1.2.3.4.5", "01.2.3.4", "1.2.3.4 ",
		" 1.2.3.4", "example.com", "::1", "2001:db8::1", "-1.2.3.4",
		"1.2.3.-4", "1.2.3.4/24",
	} {
		if IsIPv4(s) {
			t.Errorf("IsIPv4(%q) = true, want false", s)
		}
	}
}

// TestIsIPv6 pins that a mapped IPv4 address counts as IPv6, because
// "::ffff:192.0.2.5" is what a dual-stack socket reports.
func TestIsIPv6(t *testing.T) {
	for _, s := range []string{"::1", "2001:db8::1", "fe80::1", "::ffff:192.0.2.5"} {
		if !IsIPv6(s) {
			t.Errorf("IsIPv6(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "192.0.2.5", "example.com", "[::1]", "2001:db8:::1"} {
		if IsIPv6(s) {
			t.Errorf("IsIPv6(%q) = true, want false", s)
		}
	}
}

// TestValidPort pins the range and the no-leading-zero rule. "0" is excluded
// because it is not a connectable port, and "0080" is excluded because two
// spellings of one port would create two cache keys for one target.
func TestValidPort(t *testing.T) {
	for _, s := range []string{"1", "80", "443", "8443", "65535"} {
		if !ValidPort(s) {
			t.Errorf("ValidPort(%q) = false, want true", s)
		}
	}
	for _, s := range []string{
		"", "0", "00", "01", "080", "65536", "99999", "-1", "80a", " 80", "80 ",
		"443\n", "1e3", "0x1f", "4.4", "+80",
	} {
		if ValidPort(s) {
			t.Errorf("ValidPort(%q) = true, want false", s)
		}
	}
}

// TestIsPortOrRange pins the port-spec grammar, since --pflag accepts both a
// comma list and a range and naabu must be given one well-formed argument.
func TestIsPortOrRange(t *testing.T) {
	valid := []string{"80", "80,443", "1-1024", "80,443,8000-8100"}
	for _, s := range valid {
		if !IsPortOrRange(s) {
			t.Errorf("IsPortOrRange(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "80,", ",80", "80,,443", "a", "80-", "-80", "80-70", "0", "65536"} {
		if IsPortOrRange(s) {
			t.Errorf("IsPortOrRange(%q) = true, want false", s)
		}
	}
}
