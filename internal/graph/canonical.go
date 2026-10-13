package graph

import (
	"net/netip"
	"net/url"
	"strings"
)

// Canonicalize returns the identity key and a display form for a raw value of a
// given type. The key is what dedup and the UNIQUE(org_id, type, key) constraint
// use, so two sources naming the same thing resolve to one entity. The display
// form keeps the value as observed.
//
// It is conservative on purpose: a wrong normalisation merges two distinct things
// into one node and poisons the graph, so it only applies transforms that cannot
// change identity (case for hostnames, canonical IP form, default-port stripping).
func Canonicalize(t EntityType, raw string) (key, display string) {
	display = strings.TrimSpace(raw)
	switch t {
	case TypeHost, TypeDomain:
		k := strings.ToLower(display)
		k = strings.TrimSuffix(k, ".")
		return k, display
	case TypeEmail, TypeUsername:
		return strings.ToLower(display), display
	case TypeIP:
		if a, err := netip.ParseAddr(strings.TrimSpace(display)); err == nil {
			return a.String(), display
		}
		return strings.ToLower(display), display
	case TypeNetblock:
		if p, err := netip.ParsePrefix(strings.TrimSpace(display)); err == nil {
			return p.Masked().String(), display
		}
		return strings.ToLower(display), display
	case TypeASN:
		k := strings.ToUpper(strings.TrimSpace(display))
		k = strings.TrimPrefix(k, "AS")
		return "AS" + k, display
	case TypeCertificate:
		return strings.ToLower(strings.ReplaceAll(display, ":", "")), display
	case TypeURL:
		return canonicalURL(display), display
	case TypeService:
		return strings.ToLower(display), display
	default:
		return display, display
	}
}

// canonicalURL lowercases the scheme and host, drops a default port, keeps the
// path, and drops the query string's values while keeping its parameter names, so
// two URLs that differ only by a tracking value are one identity.
func canonicalURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.TrimSpace(raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	u.Host = host
	if port != "" {
		u.Host = host + ":" + port
	}
	if q := u.Query(); len(q) > 0 {
		names := make(url.Values, len(q))
		for name := range q {
			names.Set(name, "")
		}
		u.RawQuery = names.Encode()
	}
	u.Fragment = ""
	return u.String()
}

// typePair is one allowed (source, destination) pairing for an edge.
type typePair struct {
	src, dst EntityType
}

// relationships lists the entity-type pairs each edge may connect. An edge whose
// endpoints are not a listed pair is a programming error, caught by
// ValidRelationship before it reaches the database.
var relationships = map[EdgeType][]typePair{
	RelSubdomainOf:  {{TypeHost, TypeDomain}, {TypeDomain, TypeDomain}},
	RelResolvesTo:   {{TypeHost, TypeIP}, {TypeDomain, TypeIP}},
	RelInNetblock:   {{TypeIP, TypeNetblock}},
	RelAnnouncedBy:  {{TypeNetblock, TypeASN}, {TypeIP, TypeASN}},
	RelPresentsCert: {{TypeService, TypeCertificate}, {TypeHost, TypeCertificate}},
	RelSanOf:        {{TypeCertificate, TypeHost}, {TypeCertificate, TypeDomain}},
	RelMxFor:        {{TypeHost, TypeDomain}},
	RelNsFor:        {{TypeHost, TypeDomain}},
	RelHosts:        {{TypeIP, TypeService}},
	RelRunsTech:     {{TypeService, TypeTechnology}, {TypeURL, TypeTechnology}, {TypeHost, TypeTechnology}},
	RelServesURL:    {{TypeService, TypeURL}, {TypeHost, TypeURL}},
	RelHasEndpoint:  {{TypeURL, TypeEndpoint}},
	RelHasParam:     {{TypeEndpoint, TypeParameter}, {TypeURL, TypeParameter}},
	RelOwns:         {{TypeOrg, TypeDomain}, {TypeOrg, TypeNetblock}, {TypeOrg, TypeASN}},
	RelEmploys:      {{TypeOrg, TypePerson}},
	RelHasEmail:     {{TypePerson, TypeEmail}},
	RelTakeoverOf:   {{TypeHost, TypeCloudResource}, {TypeHost, TypeBucket}},
	RelOriginOf:     {{TypeIP, TypeHost}},
	RelLeaks:        {{TypeRepository, TypeCredential}, {TypeRepository, TypeLeak}, {TypeURL, TypeCredential}, {TypeURL, TypeLeak}},
	RelFoundIn:      {{TypeURL, TypeDocument}, {TypeHost, TypeDocument}},
}

// ValidRelationship reports whether an edge of this type may connect these types.
// RelSiblingOf is correlation-derived and may connect any two entities, so it is
// always allowed.
func ValidRelationship(rel EdgeType, src, dst EntityType) bool {
	if rel == RelSiblingOf {
		return true
	}
	for _, p := range relationships[rel] {
		if p.src == src && p.dst == dst {
			return true
		}
	}
	return false
}

// Inferred reports whether an edge type is a hypothesis rather than observed
// truth. These are stored flagged and must never be presented as fact.
func Inferred(rel EdgeType) bool {
	return rel == RelSiblingOf || rel == RelOriginOf
}
