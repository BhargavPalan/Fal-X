package graph

import "testing"

func TestCanonicalize(t *testing.T) {
	for _, tc := range []struct {
		name    string
		typ     EntityType
		raw     string
		wantKey string
	}{
		{"host lowercases", TypeHost, "WWW.Example.COM", "www.example.com"},
		{"host strips trailing dot", TypeHost, "www.example.com.", "www.example.com"},
		{"host trims space", TypeHost, "  api.example.com ", "api.example.com"},
		{"ip canonical v6", TypeIP, "2001:DB8::0:1", "2001:db8::1"},
		{"ip v4 unchanged", TypeIP, "192.0.2.1", "192.0.2.1"},
		{"netblock masked", TypeNetblock, "192.0.2.10/24", "192.0.2.0/24"},
		{"asn normalised", TypeASN, "as13335", "AS13335"},
		{"asn bare number", TypeASN, "13335", "AS13335"},
		{"cert strips colons", TypeCertificate, "AA:BB:CC", "aabbcc"},
		{"url default https port dropped", TypeURL, "https://Example.com:443/a", "https://example.com/a"},
		{"url keeps nondefault port", TypeURL, "https://example.com:8443/a", "https://example.com:8443/a"},
		{"url drops query values", TypeURL, "https://example.com/a?id=5&t=x", "https://example.com/a?id=&t="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := Canonicalize(tc.typ, tc.raw)
			if got != tc.wantKey {
				t.Errorf("Canonicalize(%s, %q) key = %q, want %q", tc.typ, tc.raw, got, tc.wantKey)
			}
		})
	}
}

func TestValidRelationship(t *testing.T) {
	for _, tc := range []struct {
		rel      EdgeType
		src, dst EntityType
		want     bool
	}{
		{RelResolvesTo, TypeHost, TypeIP, true},
		{RelResolvesTo, TypeIP, TypeHost, false}, // wrong direction
		{RelSubdomainOf, TypeHost, TypeDomain, true},
		{RelPresentsCert, TypeService, TypeCertificate, true},
		{RelPresentsCert, TypeHost, TypeIP, false},      // not a listed pair
		{RelSiblingOf, TypeHost, TypeCertificate, true}, // sibling connects anything
		{RelSiblingOf, TypeIP, TypeURL, true},
	} {
		if got := ValidRelationship(tc.rel, tc.src, tc.dst); got != tc.want {
			t.Errorf("ValidRelationship(%s, %s, %s) = %v, want %v", tc.rel, tc.src, tc.dst, got, tc.want)
		}
	}
}

func TestInferred(t *testing.T) {
	if !Inferred(RelSiblingOf) || !Inferred(RelOriginOf) {
		t.Error("sibling_of and origin_of must be inferred")
	}
	if Inferred(RelResolvesTo) {
		t.Error("resolves_to is observed, not inferred")
	}
}
