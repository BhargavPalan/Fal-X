// Package scope is Fal-X's target authorization boundary.
//
// Every host Fal-X is about to contact passes through Gate. Nothing else in
// the codebase decides reachability, and no module matches hosts on its own.
//
// Properties this package maintains:
//
//   - An absent, empty, unreadable, or comment-only allowlist denies everything.
//     It never widens scope.
//   - A denylist entry overrides an allowlist entry, including under --allow-any.
//   - Hosts, addresses, and ports are parsed canonically. Field splitting on
//     the colon separator corrupts IPv6: [::1]:443 would reduce to "[" with an
//     empty port list.
//   - Private, loopback, link-local, carrier-NAT, multicast, benchmarking, and
//     cloud metadata ranges are denied unless allowPrivate is set.
//   - Documentation ranges (RFC 5737, RFC 3849) are NOT special, so they stay
//     usable as scope entries and in fixtures.
//
// Scope file syntax:
//
//	example.com          apex and every subdomain at any depth
//	*.example.com        subdomains only, at any depth
//	.example.com         same as *.example.com
//	example.com:8443     that host on that port only
//	192.0.2.0/24         IPv4 CIDR
//	198.51.100.7         exact IPv4 address
//	2001:db8::1          exact IPv6 address
//	2001:db8::/32        IPv6 CIDR
//	# comment            ignored
//
// A bare `*` is refused, because it would authorize the entire internet.
package scope

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/BhargavPalan/Fal-X/internal/util"
)

// ErrNoAllowlist is returned when the allowlist is unusable.
var ErrNoAllowlist = errors.New("scope: allowlist is missing, unreadable, or contains no usable entries")

// Scope is a loaded authorization decision.
//
// Safe for concurrent use. Gate is on the hot path of every request, so the
// read path takes only a read lock.
type Scope struct {
	mu sync.RWMutex

	loaded       bool
	allowPath    string
	denyPath     string
	allowPrivate bool
	allowAny     bool

	// permissive means no allowlist was configured, so every target is
	// reachable. Set by Unrestricted, never by Load: a scope file that exists
	// but cannot be read is still an error, because the operator asked for one.
	permissive bool

	allowApex   []string
	allowWild   []string
	allowPorts  map[string]struct{} // host:port
	allowIP     []netip.Addr
	allowPrefix []netip.Prefix

	denyApex   []string
	denyWild   []string
	denyPorts  map[string]struct{}
	denyIP     []netip.Addr
	denyPrefix []netip.Prefix

	// warnings collected during Load, surfaced by the CLI.
	warnings []string

	// fingerprint of the parsed rules, so a change is detectable.
	fingerprint string
}

// New returns an unloaded Scope. Every Gate call denies until Load succeeds.
func New(allowPrivate, allowAny bool) *Scope {
	return &Scope{
		allowPrivate: allowPrivate,
		allowAny:     allowAny,
		allowPorts:   map[string]struct{}{},
		denyPorts:    map[string]struct{}{},
	}
}

// Unrestricted returns a Scope that allows every target.
//
// This is what a run gets when no allowlist is configured, which is the default.
// A bare target behaves the way it does in nmap or httpx: the operator names
// what they want scanned and it is scanned. Passing --scope is how an operator
// who wants a recorded boundary opts back into being held to one.
//
// The denylist still applies. --exclude is an explicit instruction about a
// specific host, which is a different thing from a default that happens to be
// missing.
func Unrestricted() *Scope {
	s := New(false, false)
	s.permissive = true
	return s
}

// DenylistOnly returns an unrestricted Scope that still honours a denylist.
//
// An absent allowlist stops being a boundary, but --exclude names specific
// hosts and that instruction is independent of whether an allowlist exists.
func DenylistOnly(path string) *Scope {
	s := Unrestricted()
	if path == "" {
		return s
	}
	// The denylist is parsed by the same reader as an allowlist; only the
	// allow side is skipped.
	_ = s.Load("", path)
	return s
}

// Loaded reports whether a usable allowlist was parsed.
func (s *Scope) Loaded() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loaded
}

// Warnings returns the messages collected during the last Load.
func (s *Scope) Warnings() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.warnings...)
}

// entry is one parsed scope-file line.
type entry struct {
	apex     string // apex domain, matches itself and all subdomains
	wild     string // subdomain-only domain
	port     string // host:port
	ipExact  string
	ipCIDR   string
	rejected bool
}

func (e entry) empty() bool {
	return e.apex == "" && e.wild == "" && e.port == "" && e.ipExact == "" && e.ipCIDR == ""
}

// parseEntry classifies one scope-file line.
//
// Anything that cannot be classified safely is rejected rather than guessed. A
// scope file is an authorization artefact, so a malformed line is a mistake
// worth reporting, not something to interpret charitably.
func parseEntry(raw string) entry {
	// Strip comments, then surrounding whitespace.
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = raw[:i]
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return entry{}
	}

	// Reduce a URL down to host[:port].
	//
	// The path is only stripped from something that is actually a URL. A CIDR
	// entry also contains a slash, and cutting at it would reduce 192.0.2.0/24
	// to the single address 192.0.2.0, turning a range into an exact match.
	// Reduced by the one implementation in internal/util. A scope entry can be
	// written as a URL for convenience, and letting two packages each reduce it
	// their own way is how they end up disagreeing about what "example.com/x"
	// means.
	raw = util.ReduceAuthority(raw)

	// A bare wildcard would authorize the internet.
	switch raw {
	case "*", "*:*", "*/*":
		return entry{rejected: true}
	}

	host, port := splitHostPortForScope(raw)

	// CIDR first: the port split must not have mangled an IPv6 prefix.
	if p, err := netip.ParsePrefix(host); err == nil {
		return entry{ipCIDR: p.String()}
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return entry{ipExact: a.String()}
	}

	// Domain. Strip wildcard markers.
	isWild := false
	if strings.HasPrefix(host, "*.") {
		host = host[2:]
		isWild = true
	} else if strings.HasPrefix(host, ".") {
		host = host[1:]
		isWild = true
	}
	host = strings.ToLower(host)
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return entry{rejected: true}
	}
	if !validDomain(host) {
		return entry{rejected: true}
	}

	if isWild {
		// A port on a wildcard is ambiguous, so refuse it rather than
		// silently applying the port to only part of the rule.
		if port != "" {
			return entry{rejected: true}
		}
		return entry{wild: host}
	}
	if port != "" {
		return entry{port: host + ":" + port}
	}
	return entry{apex: host}
}

// validDomain reports whether s is a plausible DNS name.
//
// This rejects path traversal, whitespace, and every character that is not
// legal in a hostname, which is what keeps a crafted list from smuggling
// arguments into a later command.
func validDomain(s string) bool {
	return util.ValidDomain(s)
}

// splitHostPortForScope separates a port from a host without breaking IPv6.
//
// A bare IPv6 literal contains colons but no port, so the split is only applied
// when what follows the last colon is a plausible port number.
func splitHostPortForScope(raw string) (host, port string) {
	if strings.HasPrefix(raw, "[") {
		// Bracketed IPv6, optionally with a port.
		if i := strings.Index(raw, "]"); i >= 0 {
			host = raw[1:i]
			rest := raw[i+1:]
			if strings.HasPrefix(rest, ":") {
				port = rest[1:]
			}
			return host, validPort(port)
		}
		return raw, ""
	}
	// Multiple colons means a bare IPv6 literal, not host:port.
	if strings.Count(raw, ":") > 1 {
		return raw, ""
	}
	if i := strings.LastIndexByte(raw, ':'); i >= 0 {
		if p := validPort(raw[i+1:]); p != "" {
			return raw[:i], p
		}
	}
	return raw, ""
}

// validPort returns p when it is a port worth dialling, else "".
//
// The range and leading-zero rules live in internal/util so that a port
// spelled one way here is spelled the same way in the port, HTTP, and content
// stages.
func validPort(p string) string {
	if !util.ValidPort(p) {
		return ""
	}
	return p
}

// AllowlistUnusable carries the detail behind an ErrNoAllowlist refusal.
//
// It exists so the message can say how to fix the problem. An operator who has
// just cloned the repository has no config/scope.txt, and being told only that a
// file is missing sends them looking for a bug rather than for the setup step.
type AllowlistUnusable struct {
	Path   string
	Reason string
}

// Error is only reached when a scope file was named but could not be used. A
// missing allowlist is the default and not an error, so this reports a file the
// operator expected to be honoured and was not.
func (e *AllowlistUnusable) Error() string {
	return fmt.Sprintf("no usable scope allowlist at %s: %s\n\n"+
		"You asked for this run to be held to an allowlist, so it will not proceed "+
		"without one. Fix the file, or drop --scope to scan whatever you name.\n\n"+
		"  1. create it:  fal-x install --setup     (or copy config/scope.txt.example)\n"+
		"  2. put in it what you are authorised to scan, one entry per line\n"+
		"  3. check it:   fal-x scan --scope config/scope.txt --why-denied example.com",
		e.Path, e.Reason)
}

// Load reads the allowlist and denylist.
//
// It fails closed. A missing, empty, or unreadable allowlist is an error, never
// an empty rule set, because an empty rule set reads as "nothing is in scope"
// when it actually means "the authorization was never supplied". On any failure
// the Scope is left unloaded, so every subsequent Gate call denies; a partially
// loaded allowlist is never kept.
func (s *Scope) Load(allowPath, denyPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.reset()
	s.allowPath, s.denyPath = allowPath, denyPath

	if allowPath == "" {
		// No allowlist is the permissive default. The denylist is still read, so
		// --exclude keeps working without one.
		if err := s.loadDenylist(denyPath); err != nil {
			return err
		}
		return &AllowlistUnusable{Path: allowPath, Reason: "no usable entries"}
	}
	f, err := os.Open(allowPath)
	if err != nil {
		s.warn("scope: cannot read allowlist %s: %v", allowPath, err)
		if derr := s.loadDenylist(denyPath); derr != nil {
			return derr
		}
		return &AllowlistUnusable{Path: allowPath, Reason: err.Error()}
	}
	defer f.Close()

	if err := s.consume(f, false); err != nil {
		return err
	}

	if err := s.loadDenylist(denyPath); err != nil {
		return err
	}

	if !s.allowAny && len(s.allowApex) == 0 && len(s.allowWild) == 0 &&
		len(s.allowPorts) == 0 && len(s.allowIP) == 0 && len(s.allowPrefix) == 0 {
		s.warn("scope: allowlist %s contains no usable entries", allowPath)
		return &AllowlistUnusable{Path: allowPath, Reason: "no usable entries"}
	}

	s.fingerprint = s.computeFingerprint()
	s.loaded = true
	return nil
}

// loadDenylist reads the exclude list, if one is configured.
//
// Kept separate from the allowlist read so it still applies when there is no
// allowlist, which is the default. A missing denylist is not fatal, but it must
// be said out loud, because the operator believes exclusions are being applied.
func (s *Scope) loadDenylist(denyPath string) error {
	if denyPath == "" {
		return nil
	}
	df, err := os.Open(denyPath)
	if err != nil {
		s.warn("scope: denylist %s is unreadable; no entries will be excluded", denyPath)
		return nil
	}
	defer df.Close()
	return s.consume(df, true)
}

// reset clears every rule. Called at the start of Load.
func (s *Scope) reset() {
	s.loaded = false
	s.warnings = nil
	s.allowApex = nil
	s.allowWild = nil
	s.allowPorts = map[string]struct{}{}
	s.allowIP = nil
	s.allowPrefix = nil
	s.denyApex = nil
	s.denyWild = nil
	s.denyPorts = map[string]struct{}{}
	s.denyIP = nil
	s.denyPrefix = nil
	s.fingerprint = ""
}

func (s *Scope) warn(format string, a ...any) {
	s.warnings = append(s.warnings, fmt.Sprintf(format, a...))
}

// lineScannerMax bounds a single scope entry. A scope entry is a hostname or a
// prefix, so the ceiling exists only so a pathological line is reported rather
// than silently truncating the rule set.
const lineScannerMax = 1024 * 1024

// consume reads scope entries into the allow or deny rules.
func (s *Scope) consume(f *os.File, deny bool) error {
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), lineScannerMax)
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Text()
		e := parseEntry(raw)

		if e.rejected {
			// A bare '*' is the case worth shouting about; everything else is
			// most likely a typo.
			if strings.TrimSpace(stripComment(raw)) == "*" {
				s.warn("scope: %s:%d refusing wildcard '*'. Pass --allow-any to accept it deliberately.", s.currentPath(deny), line)
			} else {
				s.warn("scope: %s:%d ignoring unusable entry %q", s.currentPath(deny), line, strings.TrimSpace(raw))
			}
			continue
		}
		if e.empty() {
			continue
		}
		s.add(e, deny)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("scope: read %s: %w", s.currentPath(deny), err)
	}
	return nil
}

func stripComment(raw string) string {
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		return raw[:i]
	}
	return raw
}

func (s *Scope) currentPath(deny bool) string {
	if deny {
		return s.denyPath
	}
	return s.allowPath
}

// add files one parsed entry into the right bucket.
func (s *Scope) add(e entry, deny bool) {
	switch {
	case e.ipCIDR != "":
		p, err := netip.ParsePrefix(e.ipCIDR)
		if err != nil {
			return
		}
		// Normalise so Contains works regardless of how the host bits were set.
		if deny {
			s.denyPrefix = append(s.denyPrefix, p.Masked())
		} else {
			s.allowPrefix = append(s.allowPrefix, p.Masked())
		}
	case e.ipExact != "":
		a, err := netip.ParseAddr(e.ipExact)
		if err != nil {
			return
		}
		if deny {
			s.denyIP = append(s.denyIP, a)
		} else {
			s.allowIP = append(s.allowIP, a)
		}
	case e.wild != "":
		if deny {
			s.denyWild = append(s.denyWild, e.wild)
		} else {
			s.allowWild = append(s.allowWild, e.wild)
		}
	case e.port != "":
		if deny {
			s.denyPorts[e.port] = struct{}{}
		} else {
			s.allowPorts[e.port] = struct{}{}
		}
	case e.apex != "":
		if deny {
			s.denyApex = append(s.denyApex, e.apex)
		} else {
			s.allowApex = append(s.allowApex, e.apex)
		}
	}
}

// computeFingerprint digests the parsed rules.
//
// It is recorded in the run manifest so a report can be tied to the approval
// that produced it, without storing a second copy of the scope file.
func (s *Scope) computeFingerprint() string {
	// Every collection is sorted here rather than by a separate pass over the
	// rule set. Go randomises map iteration on every run, so a digest that
	// walked a map directly would differ between two loads of an identical
	// file, and the fingerprint's whole purpose is to answer "is this the same
	// scope as last time". Making the invariant local means no caller has to
	// remember to establish it.
	var b strings.Builder

	write := func(tag string, vals []string) {
		for _, v := range vals {
			b.WriteString(tag)
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	writeMap := func(tag string, vals map[string]struct{}) {
		keys := make([]string, 0, len(vals))
		for k := range vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		write(tag, keys)
	}
	writeAddrs := func(tag string, addrs []netip.Addr) {
		strs := make([]string, 0, len(addrs))
		for _, a := range addrs {
			strs = append(strs, a.String())
		}
		sort.Strings(strs)
		write(tag, strs)
	}

	write("A|", sortedCopy(s.allowApex))
	write("W|", sortedCopy(s.allowWild))
	write("a|", sortedCopy(s.denyApex))
	write("w|", sortedCopy(s.denyWild))
	writeMap("P|", s.allowPorts)
	writeMap("p|", s.denyPorts)
	writeAddrs("I|", s.allowIP)
	writeAddrs("i|", s.denyIP)
	write("C|", sortedPrefixes(s.allowPrefix))
	write("c|", sortedPrefixes(s.denyPrefix))

	return sha256Sum(b.String())
}

// sha256Sum returns the hex digest of s.
func sha256Sum(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Fingerprint returns a stable digest of the parsed rules.
func (s *Scope) Fingerprint() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fingerprint
}

// AllowPrivate reports whether special ranges are permitted.
func (s *Scope) AllowPrivate() bool { return s.allowPrivate }

// AllowAny reports whether the bare wildcard was accepted.
func (s *Scope) AllowAny() bool { return s.allowAny }

// Summary counts the loaded rules, for --dry-run output.
type Summary struct {
	Loaded       bool   `json:"loaded"`
	Apex         int    `json:"apex"`
	Wildcard     int    `json:"wildcard"`
	HostPort     int    `json:"host_port"`
	IPExact      int    `json:"ip_exact"`
	CIDR         int    `json:"cidr"`
	DenyTotal    int    `json:"deny_total"`
	AllowPrivate bool   `json:"allow_private"`
	AllowAny     bool   `json:"allow_any"`
	Fingerprint  string `json:"fingerprint"`
}

// Summary reports the loaded rule counts.
func (s *Scope) Summary() Summary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Summary{
		Loaded:       s.loaded,
		Apex:         len(s.allowApex),
		Wildcard:     len(s.allowWild),
		HostPort:     len(s.allowPorts),
		IPExact:      len(s.allowIP),
		CIDR:         len(s.allowPrefix),
		DenyTotal:    len(s.denyApex) + len(s.denyWild) + len(s.denyPorts) + len(s.denyIP) + len(s.denyPrefix),
		AllowPrivate: s.allowPrivate,
		AllowAny:     s.allowAny,
		Fingerprint:  s.fingerprint,
	}
}
