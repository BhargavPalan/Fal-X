package scope

import (
	"net/netip"
	"sort"
)

// Rules is the effective rule set, exposed for the dry-run plan.
//
// It exists so an operator can see exactly what Fal-X believes it is
// authorized to do before it does any of it. Entries are sorted so the plan is
// stable between runs and a rule cannot hide behind map ordering.
type Rules struct {
	Loaded bool

	AllowApex     []string
	AllowWildcard []string
	AllowHostPort []string
	AllowIP       []string
	AllowCIDR     []string

	DenyApex     []string
	DenyWildcard []string
	DenyHostPort []string
	DenyIP       []string
	DenyCIDR     []string
}

// Rules returns the effective rule set, with the entries sorted.
//
// A copy is returned so a caller cannot mutate the gate's state, and so the
// lock is not held while the caller formats it.
func (s *Scope) Rules() Rules {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r := Rules{
		Loaded:        s.loaded,
		AllowApex:     sortedCopy(s.allowApex),
		AllowWildcard: sortedCopy(s.allowWild),
		AllowHostPort: sortedKeys(s.allowPorts),
		AllowIP:       sortedAddrs(s.allowIP),
		AllowCIDR:     sortedPrefixes(s.allowPrefix),

		DenyApex:     sortedCopy(s.denyApex),
		DenyWildcard: sortedCopy(s.denyWild),
		DenyHostPort: sortedKeys(s.denyPorts),
		DenyIP:       sortedAddrs(s.denyIP),
		DenyCIDR:     sortedPrefixes(s.denyPrefix),
	}
	return r
}

// sortedAddrs returns the sorted string form of a set of addresses.
func sortedAddrs(in []netip.Addr) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, a := range in {
		out = append(out, a.String())
	}
	sort.Strings(out)
	return out
}

// sortedPrefixes returns the sorted string form of a set of prefixes.
func sortedPrefixes(in []netip.Prefix) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, p.String())
	}
	sort.Strings(out)
	return out
}

// sortedCopy returns a sorted copy of a rule slice.
func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}

// sortedKeys returns the sorted keys of a port or prefix map.
func sortedKeys[V any](m map[string]V) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
