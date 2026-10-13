package native

import (
	"context"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestClassifyCDN(t *testing.T) {
	cases := []struct {
		target, provider, category string
	}{
		{"example.map.fastly.net", "Fastly", "cdn"},
		{"d111111abcdef8.cloudfront.net", "Amazon CloudFront", "cdn"},
		{"x.incapdns.net", "Imperva Incapsula", "waf"},
		{"shop.myshopify.com", "Shopify", "cloud"},
		{"foo.github.io", "GitHub Pages", "cloud"},
		{"nothing.example.org", "", ""},
	}
	for _, c := range cases {
		p, cat := classifyCDN(c.target)
		if p != c.provider || cat != c.category {
			t.Errorf("classifyCDN(%q) = %q/%q, want %q/%q", c.target, p, cat, c.provider, c.category)
		}
	}
}

func TestCDNCheckRecordsVerdict(t *testing.T) {
	c := &CDNCheck{Resolver: fakeResolver{
		cname: map[string]string{"www.example.com": "www.example.com.cdn.cloudflare.net."},
	}}
	s := &recSink{}
	if err := c.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: "www.example.com"}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasFact("cdn", "Cloudflare") {
		t.Errorf("expected cdn verdict, facts=%+v", s.facts)
	}
}

func TestCDNCheckNoCNAMEIsSilent(t *testing.T) {
	c := &CDNCheck{Resolver: fakeResolver{}} // returns the host itself (no CNAME)
	s := &recSink{}
	if err := c.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: "plain.example.com"}, s); err != nil {
		t.Fatal(err)
	}
	if len(s.facts) != 0 {
		t.Errorf("a host with no CNAME should record nothing, got %+v", s.facts)
	}
}
