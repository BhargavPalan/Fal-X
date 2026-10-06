package scope

import (
	"fmt"
	"net/netip"
	"strings"
)

// Decision is the outcome of one authorization check, with the reason.
type Decision struct {
	Target  string `json:"target"`
	Host    string `json:"host"`
	Port    string `json:"port,omitempty"`
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// deniedByList applies the denylist on its own, with no allowlist in play.
//
// It exists for the unrestricted case: without an allowlist there is nothing to
// check against, but --exclude names specific hosts and that instruction should
// hold regardless of whether a scope file was also supplied.
func (s *Scope) deniedByList(target, port string) (string, bool) {
	if target == "" {
		return "denied: empty target", true
	}
	host, resolvedPort, kind := s.reduce(target, port)
	if host == "" {
		return "denied: could not determine a host from the target", true
	}
	return s.denied(kind, host, resolvedPort)
}

// Gate reports whether Fal-X may contact target, optionally on a specific
// port.
//
// target may be a hostname, an IP address, a CIDR, a host:port pair, or a full
// URL. This is the single place the decision is made.
func (s *Scope) Gate(target, port string) bool {
	return s.Explain(target, port).Allowed
}

// Explain returns the decision together with the reason, for --why-denied and
// for the run manifest.
func (s *Scope) Explain(target, port string) Decision {
	d := Decision{Target: target}

	s.mu.RLock()
	loaded := s.loaded
	s.mu.RUnlock()

	// With no allowlist configured there is nothing to check against, and the
	// run proceeds the way nmap or httpx would. The denylist still applies,
	// because --exclude is an explicit instruction rather than a default.
	if s.permissive {
		if reason, denied := s.deniedByList(target, port); denied {
			d.Reason = reason
			return d
		}
		d.Allowed = true
		d.Reason = "allowed: no scope allowlist configured, so every target is reachable; " +
			"pass --scope <file> to hold a run to one"
		return d
	}

	if !loaded {
		d.Reason = "denied: no usable allowlist is loaded"
		return d
	}
	if target == "" {
		d.Reason = "denied: empty target"
		return d
	}

	host, resolvedPort, kind := s.reduce(target, port)
	d.Host, d.Port = host, resolvedPort

	if host == "" {
		d.Reason = "denied: could not determine a host from the target"
		return d
	}

	if reason, denied := s.denied(kind, host, resolvedPort); denied {
		d.Reason = reason
		return d
	}

	switch kind {
	case kindIP:
		if !s.ipAllowed(host) {
			d.Reason = fmt.Sprintf("denied: %s is not in the allowlist", host)
			return d
		}
	case kindCIDR:
		// A range is usable only when its network address is authorised.
		// Accepting a partial range would let a later scan walk outside the
		// approved range.
		network := netip.MustParsePrefix(host).Masked().Addr().String()
		if !s.ipAllowed(network) {
			d.Reason = fmt.Sprintf("denied: network %s is not in the allowlist", network)
			return d
		}
	default:
		if reason, ok := s.domainReason(host, resolvedPort); !ok {
			d.Reason = reason
			return d
		}
	}

	if reason, blocked := s.specialBlocked(host); blocked {
		d.Reason = reason
		return d
	}

	d.Allowed = true
	d.Reason = "allowed"
	return d
}

// targetKind distinguishes the three shapes Gate accepts.
type targetKind int

const (
	kindDomain targetKind = iota
	kindIP
	kindCIDR
)

// reduce turns any accepted target form into a bare host plus a port.
func (s *Scope) reduce(target, port string) (host, resolvedPort string, kind targetKind) {
	t := strings.TrimSpace(target)

	// URLs and anything carrying a path, query, or fragment is reduced with
	// the URL parser rather than by hand.
	if strings.Contains(t, "://") || strings.ContainsAny(t, "/?#@") {
		h, p := hostPortFromURL(t)
		if h == "" {
			return "", port, kindDomain
		}
		if port == "" {
			port = p
		}
		t = h
	}

	// A bare IPv6 literal contains colons but no port, so it must be tested
	// before the host:port split, or every IPv6 address reduces to nothing.
	if a, ok := tryIP(t); ok {
		return a.String(), port, kindIP
	}
	if p, ok := tryPrefix(t); ok {
		return p.String(), port, kindCIDR
	}

	// Bracketed IPv6, with or without a port. This has to be checked before
	// the colon count below, because a bracketed literal with a port contains
	// several colons and would otherwise be mistaken for a bare literal.
	if strings.HasPrefix(t, "[") {
		end := strings.Index(t, "]")
		if end > 0 {
			inner := t[1:end]
			rest := t[end+1:]
			if port == "" && strings.HasPrefix(rest, ":") {
				port = validPort(rest[1:])
			}
			if a, ok := tryIP(inner); ok {
				return a.String(), port, kindIP
			}
			return strings.ToLower(inner), port, kindDomain
		}
	}

	// host:port. More than one colon means a bare IPv6 literal.
	if strings.Count(t, ":") == 1 {
		h, p := splitHostPortForScope(t)
		if p != "" {
			if port == "" {
				port = p
			}
			t = h
		}
	}

	if a, ok := tryIP(t); ok {
		return a.String(), port, kindIP
	}

	// Strip the DNS root dot, which a fully qualified name carries and which
	// no allowlist entry will ever contain.
	t = strings.ToLower(t)
	for strings.HasSuffix(t, ".") && len(t) > 1 {
		t = t[:len(t)-1]
	}

	return t, port, kindDomain
}

// denied applies the denylist, which always wins.
func (s *Scope) denied(kind targetKind, host, port string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	switch kind {
	case kindDomain:
		for _, d := range s.denyApex {
			if matchApex(host, d) {
				return fmt.Sprintf("denied: %s is on the denylist", host), true
			}
		}
		for _, d := range s.denyWild {
			if matchSubdomain(host, d) {
				return fmt.Sprintf("denied: %s matches the denylist wildcard %s", host, d), true
			}
		}
		if port != "" {
			if _, ok := s.denyPorts[host+":"+port]; ok {
				return fmt.Sprintf("denied: %s:%s is on the denylist", host, port), true
			}
		}
	default:
		if a, ok := tryIP(host); ok {
			for _, d := range s.denyIP {
				if d == a {
					return fmt.Sprintf("denied: %s is on the denylist", host), true
				}
			}
			for _, p := range s.denyPrefix {
				if p.Contains(a) {
					return fmt.Sprintf("denied: %s is inside denied range %s", host, p), true
				}
			}
		}
		if port != "" {
			if _, ok := s.denyPorts[host+":"+port]; ok {
				return fmt.Sprintf("denied: %s:%s is on the denylist", host, port), true
			}
		}
	}
	return "", false
}

// domainReason reports why a domain is not allowed, and whether it is allowed.
func (s *Scope) domainReason(host, port string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !validDomain(host) {
		return fmt.Sprintf("denied: %q is not a valid hostname", host), false
	}
	// An address reaching the domain matcher was never a domain rule match.
	if _, ok := tryIP(host); ok {
		return "denied: an IP address cannot match a domain rule", false
	}

	// An exact host:port rule, when a port is known, decides on its own.
	if port != "" {
		if _, ok := s.allowPorts[host+":"+port]; ok {
			return "", true
		}
	}
	if port != "" {
		if _, pinned := s.allowPorts[host+":"+port]; pinned {
			// The rule exists for a different port.
			for p := range s.allowPorts {
				if strings.HasPrefix(p, host+":") {
					return fmt.Sprintf("denied: %s is scoped to port %s, not %s",
						host, strings.TrimPrefix(p, host+":"), port), false
				}
			}
		}
	}

	for _, a := range s.allowApex {
		if matchApex(host, a) {
			return "", true
		}
	}
	for _, w := range s.allowWild {
		if matchSubdomain(host, w) {
			return "", true
		}
	}

	if s.allowAny {
		return "", true
	}
	return "denied: " + host + " is not in the allowlist", false
}

// ipAllowed reports whether an address matches the allowlist.
func (s *Scope) ipAllowed(host string) bool {
	a, ok := tryIP(host)
	if !ok {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, x := range s.allowIP {
		if x == a {
			return true
		}
	}
	for _, p := range s.allowPrefix {
		if p.Contains(a) {
			return true
		}
	}
	return s.allowAny
}

// specialBlocked denies special ranges unless allowPrivate is set.
func (s *Scope) specialBlocked(host string) (string, bool) {
	if s.allowPrivate {
		return "", false
	}
	a, ok := tryIP(host)
	if !ok {
		// Hostname special cases.
		if host == "localhost" || strings.HasSuffix(host, ".localhost") {
			return fmt.Sprintf("denied: %s is a loopback name; pass --allow-private for lab work", host), true
		}
		return "", false
	}
	if !IsSpecialAddr(a) {
		return "", false
	}
	return fmt.Sprintf("denied: %s is a special or reserved range; pass --allow-private for lab work", host), true
}

// matchApex reports whether host is the apex itself or a subdomain of it.
//
// The delimiter check is what stops example.com.attacker.test from matching the
// rule example.com, which a plain suffix test would allow.
func matchApex(host, apex string) bool {
	if host == apex {
		return true
	}
	if len(host) <= len(apex) {
		return false
	}
	if !strings.HasSuffix(host, apex) {
		return false
	}
	return host[len(host)-len(apex)-1] == '.'
}

// matchSubdomain reports whether host is a subdomain of apex, excluding the
// apex itself.
func matchSubdomain(host, apex string) bool {
	if len(host) <= len(apex) {
		return false
	}
	if !strings.HasSuffix(host, apex) {
		return false
	}
	return host[len(host)-len(apex)-1] == '.'
}

// HostAllowed reports whether a bare hostname is in scope.
func (s *Scope) HostAllowed(host string) bool {
	return s.domainAllowed(host, "")
}

func (s *Scope) domainAllowed(host, port string) bool {
	return s.Explain(host, port).Allowed
}

// URLAllowed reports whether the host inside a URL is in scope.
func (s *Scope) URLAllowed(rawURL string) bool {
	host, port := hostPortFromURL(rawURL)
	if host == "" {
		return false
	}
	return s.Gate(host, port)
}

// SummaryLine renders the loaded scope for --dry-run output.
func (s *Scope) SummaryLine() string {
	sum := s.Summary()
	if !sum.Loaded {
		return "FAILED CLOSED (allowlist unusable)"
	}
	return fmt.Sprintf("apex=%d wildcard=%d host:port=%d ip=%d cidr=%d deny=%d private=%v any=%v",
		sum.Apex, sum.Wildcard, sum.HostPort, sum.IPExact, sum.CIDR,
		sum.DenyTotal, sum.AllowPrivate, sum.AllowAny)
}
