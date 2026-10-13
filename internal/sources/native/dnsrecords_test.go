package native

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

// fakeRecords answers zone lookups from fixed maps, so the records source is tested
// without live name servers.
type fakeRecords struct {
	ns  map[string][]string
	mx  map[string][]string
	txt map[string][]string
	srv map[string][]*net.SRV // keyed by "service.proto"
}

func (f fakeRecords) LookupNS(_ context.Context, name string) ([]*net.NS, error) {
	hosts, ok := f.ns[name]
	if !ok {
		return nil, &net.DNSError{IsNotFound: true}
	}
	out := make([]*net.NS, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, &net.NS{Host: h})
	}
	return out, nil
}

func (f fakeRecords) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	hosts, ok := f.mx[name]
	if !ok {
		return nil, &net.DNSError{IsNotFound: true}
	}
	out := make([]*net.MX, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, &net.MX{Host: h, Pref: 10})
	}
	return out, nil
}

func (f fakeRecords) LookupTXT(_ context.Context, name string) ([]string, error) {
	if t, ok := f.txt[name]; ok {
		return t, nil
	}
	return nil, &net.DNSError{IsNotFound: true}
}

func (f fakeRecords) LookupSRV(_ context.Context, service, proto, _ string) (string, []*net.SRV, error) {
	if s, ok := f.srv[service+"."+proto]; ok {
		return "", s, nil
	}
	return "", nil, &net.DNSError{IsNotFound: true}
}

// hasFact reports whether a key/value fact was emitted.
func (s *recSink) hasFact(key, value string) bool {
	for _, f := range s.facts {
		if f.key == key && f.value == value {
			return true
		}
	}
	return false
}

func TestDNSRecordsMailPosture(t *testing.T) {
	r := &DNSRecords{Resolver: fakeRecords{
		ns: map[string][]string{"example.com": {"ns1.example.com."}},
		mx: map[string][]string{"example.com": {"aspmx.l.google.com."}},
		txt: map[string][]string{
			"example.com": {
				"v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.7 include:_spf.google.com ~all",
				"google-site-verification=abcdef",
			},
			"_dmarc.example.com": {"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"},
		},
	}}
	s := &recSink{}
	if err := r.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "example.com"}, s); err != nil {
		t.Fatal(err)
	}

	for _, e := range []struct {
		t   graph.EntityType
		key string
	}{
		{graph.TypeHost, "ns1.example.com"},
		{graph.TypeHost, "aspmx.l.google.com"},
		{graph.TypeNetblock, "192.0.2.0/24"},
		{graph.TypeIP, "198.51.100.7"},
		{graph.TypeEmail, "dmarc@example.com"},
	} {
		if !s.hasEntity(e.t, e.key) {
			t.Errorf("expected %s entity %q, entities=%+v", e.t, e.key, s.entities)
		}
	}
	for _, f := range [][2]string{
		{"ns", "ns1.example.com"},
		{"mx", "aspmx.l.google.com"},
		{"saas", "Google Workspace"}, // inferred from the MX host and the SPF include
		{"spf_include", "_spf.google.com"},
		{"spf_netblock", "192.0.2.0/24"},
		{"dmarc_policy", "reject"},
		{"dmarc_email", "dmarc@example.com"},
		{"txt", "google-site-verification=abcdef"},
	} {
		if !s.hasFact(f[0], f[1]) {
			t.Errorf("expected fact %s=%q, facts=%+v", f[0], f[1], s.facts)
		}
	}
	// The edge directions: an NS/MX host points at the domain it serves.
	var ns, mx int
	for _, e := range s.edges {
		switch e {
		case graph.RelNsFor:
			ns++
		case graph.RelMxFor:
			mx++
		}
	}
	if ns != 1 || mx != 1 {
		t.Errorf("ns_for=%d mx_for=%d, want 1 and 1", ns, mx)
	}
}

func TestDNSRecordsSPFQualifierStripped(t *testing.T) {
	s := &recSink{}
	self := s.Entity(graph.TypeDomain, "x.test", "x.test")
	// Leading qualifiers (-, ~) must not hide the mechanism they modify.
	parseSPF(self, "v=spf1 -ip4:203.0.113.0/24 ~include:mailgun.org -all", s)
	if !s.hasEntity(graph.TypeNetblock, "203.0.113.0/24") {
		t.Errorf("qualified ip4 mechanism was not parsed, entities=%+v", s.entities)
	}
	if !s.hasFact("saas", "Mailgun") {
		t.Errorf("qualified include was not parsed, facts=%+v", s.facts)
	}
}

func TestDNSRecordsSRV(t *testing.T) {
	r := &DNSRecords{Resolver: fakeRecords{
		srv: map[string][]*net.SRV{
			"sip.tcp": {{Target: "sipserver.example.com.", Port: 5061}},
		},
	}}
	s := &recSink{}
	if err := r.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "example.com"}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasEntity(graph.TypeHost, "sipserver.example.com") {
		t.Errorf("expected the SRV target as a host, entities=%+v", s.entities)
	}
	if !s.hasFact("srv", "_sip._tcp sipserver.example.com:5061") {
		t.Errorf("expected srv fact, facts=%+v", s.facts)
	}
}

func TestDNSRecordsSpoofabilityVerdict(t *testing.T) {
	// A domain with neither SPF nor DMARC is spoofable.
	r := &DNSRecords{Resolver: fakeRecords{}}
	s := &recSink{}
	if err := r.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "spoof.test"}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasFact("finding", "medium email-spoofable-no-spf-dmarc") {
		t.Errorf("expected a spoofable finding, facts=%+v", s.facts)
	}

	// A domain with an enforcing DMARC policy is not flagged spoofable.
	r2 := &DNSRecords{Resolver: fakeRecords{txt: map[string][]string{
		"safe.test":        {"v=spf1 -all"},
		"_dmarc.safe.test": {"v=DMARC1; p=reject"},
	}}}
	s2 := &recSink{}
	if err := r2.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "safe.test"}, s2); err != nil {
		t.Fatal(err)
	}
	for _, f := range s2.facts {
		if f.key == "finding" && strings.Contains(f.value, "spoofable") {
			t.Errorf("an enforcing domain must not be flagged spoofable, got %+v", f)
		}
	}
	if !s2.hasFact("dmarc_enforced", "reject") {
		t.Errorf("expected dmarc_enforced fact, facts=%+v", s2.facts)
	}
}

func TestDNSRecordsNoRecordsIsNotError(t *testing.T) {
	r := &DNSRecords{Resolver: fakeRecords{}}
	s := &recSink{}
	if err := r.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "empty.test"}, s); err != nil {
		t.Errorf("a domain with no records should not error, got %v", err)
	}
}
