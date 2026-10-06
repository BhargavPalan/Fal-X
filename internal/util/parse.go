// Package util holds the dependency-free helpers: file IO, hashing, host and
// URL parsing, timestamps, JSON escaping, and a non-executing credential
// parser.
//
// It performs no network access. Network authorization lives exclusively in
// internal/net, and the authorization decision itself in internal/scope, so
// that there is exactly one of each.
package util

import (
	"net/netip"
	"strings"
)

// SplitScheme returns the scheme of raw, or "" when it carries none.
func SplitScheme(raw string) string {
	if i := strings.Index(raw, "://"); i >= 0 {
		return raw[:i]
	}
	return ""
}

// ReduceAuthority strips the scheme, path, query, fragment and userinfo from
// raw, leaving host[:port].
//
// A slash is only stripped as a path delimiter. A CIDR contains a slash too, so
// a caller that wants to reduce a prefix must test for it first. A reduced
// prefix therefore comes back still carrying its slash, which is what lets a
// caller tell the two apart.
func ReduceAuthority(raw string) string {
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
		if j := strings.IndexAny(raw, "/?#"); j >= 0 {
			raw = raw[:j]
		}
	} else if _, err := netip.ParsePrefix(raw); err != nil {
		// Not a prefix, so a slash here can only be a path.
		if j := strings.IndexAny(raw, "/?#"); j >= 0 {
			raw = raw[:j]
		}
	}

	// Userinfo: keep whatever follows the last '@'.
	if i := strings.LastIndexByte(raw, '@'); i >= 0 {
		raw = raw[i+1:]
	}
	return raw
}

// URLHost extracts a bare host from raw.
//
// It handles a scheme, userinfo, the bracketed IPv6 form, ports, paths,
// queries, fragments and scheme-less input. It reports false when no host can
// be determined, rather than returning an empty string, so a caller cannot
// mistake "no host" for "the host is empty".
func URLHost(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}

	auth := ReduceAuthority(raw)
	if auth == "" {
		return "", false
	}

	// A bracketed IPv6 literal keeps its colons; stripping at the first colon
	// would reduce "[::1]:8080" to an empty host.
	if strings.HasPrefix(auth, "[") {
		end := strings.IndexByte(auth, ']')
		if end < 0 {
			return "", false
		}
		inner := auth[1:end]
		if inner == "" {
			return "", false
		}
		return inner, true
	}

	// Otherwise a colon introduces a port, which means the host is the part
	// before it.
	//
	// More than one colon means this is a bare IPv6 literal with no port at
	// all, so it is returned whole. Splitting at the first colon would reduce
	// "2001:db8::1" to "2001", which is a different address.
	if strings.Count(auth, ":") > 1 {
		return auth, true
	}
	if i := strings.IndexByte(auth, ':'); i >= 0 {
		auth = auth[:i]
	}
	if auth == "" {
		return "", false
	}
	return auth, true
}

// URLPort returns the explicit port in raw, or "" when it carries none.
//
// A colon inside a path or query is not a port, and a non-numeric port is
// dropped rather than passed to a caller that would then dial it.
func URLPort(raw string) string {
	auth := ReduceAuthority(raw)
	if auth == "" {
		return ""
	}

	var candidate string
	switch {
	case strings.HasPrefix(auth, "["):
		end := strings.IndexByte(auth, ']')
		if end < 0 {
			return ""
		}
		rest := auth[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return "" // bracketed IPv6 with no port
		}
		candidate = rest[1:]

	case strings.Contains(auth, ":"):
		// A bare IPv6 literal has colons but no port. More than one colon is
		// the signal, since a host:port has exactly one.
		if strings.Count(auth, ":") > 1 {
			return ""
		}
		candidate = auth[strings.IndexByte(auth, ':')+1:]

	default:
		return ""
	}

	if !ValidPort(candidate) {
		return ""
	}
	return candidate
}

// HostPortSplit normalises the ambiguous host:port form that naabu, nmap and
// httpx emit.
//
// A bare IPv6 literal has no port and must survive intact, which is the reason
// this exists rather than a naive cut on the first colon.
func HostPortSplit(raw string) (host, port string) {
	auth := raw

	// A bracket wrapper around the whole token is a shape nuclei prints around
	// its findings. It has to be noted before scheme reduction, because
	// reduction of "[https://example.com]" leaves "example.com]" and the stray
	// bracket then reads as part of the host name.
	bracketed := strings.HasPrefix(auth, "[")

	if strings.Contains(auth, "://") {
		auth = ReduceAuthority(auth)
		if bracketed && strings.HasSuffix(auth, "]") {
			auth = strings.TrimSuffix(auth, "]")
		}
	}

	if strings.HasPrefix(auth, "[") {
		end := strings.IndexByte(auth, ']')
		if end < 0 {
			return strings.TrimPrefix(auth, "["), ""
		}
		host = auth[1:end]
		rest := auth[end+1:]
		if strings.HasPrefix(rest, ":") {
			if p := rest[1:]; ValidPort(p) {
				port = p
			}
		}
		return host, port
	}

	if strings.Count(auth, ":") > 1 {
		// Bare IPv6 literal: no port.
		return auth, ""
	}

	if i := strings.IndexByte(auth, ':'); i >= 0 {
		host = auth[:i]
		if p := auth[i+1:]; ValidPort(p) {
			port = p
		}
		return host, port
	}

	return auth, ""
}

// JoinHostPort rebuilds the host:port form, bracketing an IPv6 literal.
//
// Reverses HostPortSplit. Without the brackets the result would be ambiguous
// and would not survive another split.
func JoinHostPort(host, port string) string {
	if IsIPv6(host) {
		if port == "" {
			return "[" + host + "]"
		}
		return "[" + host + "]:" + port
	}
	if port == "" {
		return host
	}
	return host + ":" + port
}

// IsIPv4 reports whether s is a dotted-quad IPv4 literal.
func IsIPv4(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	return a.Is4()
}

// IsIPv6 reports whether s is an IPv6 literal.
//
// A mapped address such as "::ffff:192.0.2.5" counts as IPv6, because that is
// what a dual-stack socket reports.
func IsIPv6(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	return a.Is4In6() || a.Is6()
}

// ValidPort reports whether s is a port number worth dialling.
//
// Leading zeros are rejected so that one port cannot be spelled two ways and
// create two cache entries for one target.
func ValidPort(s string) bool {
	if s == "" || len(s) > 5 {
		return false
	}
	if len(s) > 1 && s[0] == '0' {
		return false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n >= 1 && n <= 65535
}

// IsPortOrRange reports whether s is a well-formed port specification: a comma
// list of ports and ranges, such as "80,443,8000-8100".
func IsPortOrRange(s string) bool {
	if s == "" {
		return false
	}
	for _, part := range strings.Split(s, ",") {
		if part == "" {
			return false
		}
		if lo, hi, isRange := strings.Cut(part, "-"); isRange {
			if !ValidPort(lo) || !ValidPort(hi) {
				return false
			}
			if lo > hi {
				return false
			}
			continue
		}
		if !ValidPort(part) {
			return false
		}
	}
	return true
}

// ValidDomain reports whether s is a syntactically valid hostname.
//
// This is deliberately a syntax check only. It is not an authorization
// decision: a valid name such as "example.com.attacker.test" matches nothing on
// its own, and treating a syntactically valid host as in-scope is exactly the
// mistake the scope gate exists to prevent.
func ValidDomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}

	lower := strings.ToLower(s)

	// A trailing root dot is legal in a fully qualified name but never appears
	// in an allowlist entry, so it is rejected here and callers normalise it.
	if strings.HasSuffix(lower, ".") {
		return false
	}

	labels := strings.Split(lower, ".")
	for _, label := range labels {
		if !validLabel(label) {
			return false
		}
	}

	// The last label must not be all digits. That is the DNS rule which keeps a
	// dotted-quad address from being read as a hostname, so that "192.0.2.5"
	// is classified as an address by every caller rather than half of them.
	return !allDigits(labels[len(labels)-1])
}

// allDigits reports whether s is non-empty and entirely digits.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// validLabel reports whether one dot-separated label is well formed.
func validLabel(l string) bool {
	if l == "" || len(l) > 63 {
		return false
	}
	// A label may not start or end with a hyphen.
	if l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '-',
			c == '_':
			// An underscore appears in service names such as _dmarc, and in
			// host files produced by some scanners.
		default:
			return false
		}
	}
	return true
}
