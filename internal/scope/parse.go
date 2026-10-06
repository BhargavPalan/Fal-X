package scope

import (
	"net/netip"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/util"
)

// NormHost reduces any target form to a canonical bare hostname.
//
// It returns false when nothing usable remains. A bare IP literal bypasses the
// URL parser: splitting a URL on the colon separator to remove a port would
// reduce ::1 to an empty string.
func NormHost(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}

	// A bare literal or prefix has no URL components to strip.
	if !strings.ContainsAny(s, ":/?#@") {
		if a, err := netip.ParseAddr(s); err == nil {
			return a.String(), true
		}
	}

	h, _ := hostPortFromURL(s)
	if h == "" {
		return "", false
	}
	h = strings.ToLower(h)
	for strings.HasSuffix(h, ".") && len(h) > 1 {
		h = h[:len(h)-1]
	}
	if h == "" || strings.ContainsAny(h, " \t\r\n") {
		return "", false
	}
	return h, true
}

// IsIPv4 reports whether s is a dotted-quad address.
//
// The implementation lives in internal/util so that there is one parser for
// every caller. A second copy here would be free to drift from the one the HTTP
// and port stages use, which is the failure mode this package exists to
// prevent.
func IsIPv4(s string) bool {
	return util.IsIPv4(s)
}

// IsIPv6 reports whether s is an IPv6 literal, including the IPv4-mapped form
// that a dual-stack socket reports.
func IsIPv6(s string) bool {
	return util.IsIPv6(s)
}

// tryIP parses s as an address, skipping the parse for the common case.
//
// netip.ParseAddr allocates while attempting a dotted-quad parse, so calling it
// on every hostname costs an allocation per candidate for a parse that cannot
// succeed. A hostname cannot contain a colon, and an IPv4 literal contains
// nothing but digits and dots, so those two cheap tests settle it.
func tryIP(s string) (netip.Addr, bool) {
	if strings.IndexByte(s, ':') < 0 && !looksLikeIPv4(s) {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a, true
}

// looksLikeIPv4 reports whether s could be a dotted-quad literal.
//
// Every byte must be a digit or a dot. A hostname always contains something
// else, so this is a reliable negative filter rather than a heuristic.
func looksLikeIPv4(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

// tryPrefix parses s as a prefix. Every prefix contains a slash, so testing for
// one avoids the allocation netip.ParsePrefix makes before failing.
func tryPrefix(s string) (netip.Prefix, bool) {
	if strings.IndexByte(s, '/') < 0 {
		return netip.Prefix{}, false
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

// IsIP reports whether s is either address family.
func IsIP(s string) bool {
	_, ok := tryIP(s)
	return ok
}

// IsCIDR reports whether s is a valid prefix in either family.
func IsCIDR(s string) bool {
	_, ok := tryPrefix(s)
	return ok
}

// IsSpecialAddr reports whether a is loopback, private, link-local,
// carrier-NAT, multicast, benchmarking, reserved, or a cloud metadata address.
//
// Documentation ranges are deliberately not special. Blocking them would make
// the tool impossible to exercise offline, and they are legitimate allowlist
// entries for lab work.
func IsSpecialAddr(a netip.Addr) bool {
	if a.Is4In6() {
		a = a.Unmap()
	}

	if a.Is4() {
		b := a.As4()
		switch {
		case a.IsLoopback(), a.IsPrivate(), a.IsLinkLocalUnicast(), a.IsMulticast():
			return true
		}
		switch {
		case b[0] == 0: // 0.0.0.0/8, this network
			return true
		case b[0] == 100 && b[1] >= 64 && b[1] <= 127: // 100.64.0.0/10, carrier NAT
			return true
		case b[0] == 192 && b[1] == 0 && b[2] == 0: // 192.0.0.0/24, protocol assignments
			return true
		case b[0] == 198 && (b[1] == 18 || b[1] == 19): // 198.18.0.0/15, benchmarking
			return true
		case b[0] >= 224: // multicast and reserved
			return true
		}
		return false
	}

	if a.Is6() {
		if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsMulticast() {
			return true
		}
		// Unspecified, and the discard-only prefix.
		if a == netip.IPv6Unspecified() {
			return true
		}
		if s := a.String(); strings.HasPrefix(s, "100:") {
			return true
		}
	}
	return false
}

// IsSpecialIP is the string form of IsSpecialAddr.
func IsSpecialIP(s string) bool {
	a, ok := tryIP(s)
	return ok && IsSpecialAddr(a)
}

// IPv4ToInt converts a dotted-quad to its unsigned 32-bit value.
func IPv4ToInt(s string) (uint32, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return 0, false
	}
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), true
}

// IPv4InCIDR reports whether ip falls inside cidr.
func IPv4InCIDR(ip, cidr string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() {
		return false
	}
	p, err := netip.ParsePrefix(cidr)
	if err != nil || !p.Addr().Is4() {
		return false
	}
	return p.Contains(a)
}

// IPInCIDR reports whether ip falls inside cidr, in either family.
func IPInCIDR(ip, cidr string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	return p.Contains(a)
}

// hostPortFromURL reduces a URL to a bare host and its explicit port.
//
// Handles a scheme, userinfo, an IPv6 literal in bracket form, a port, a path,
// a query, and a fragment. It is the only accepted way to get a host out of a
// URL: hand-rolled stripping misses one of those cases.
//
// The implementation lives in internal/util. This version once cut at the first
// slash unconditionally, which silently reduced the CIDR "192.0.2.0/24" to the
// address "192.0.2.0" and turned every allowlisted range into an exact match.
func hostPortFromURL(raw string) (host, port string) {
	h, ok := util.URLHost(raw)
	if !ok {
		return "", ""
	}
	return h, util.URLPort(raw)
}
