package pdtools

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// DNSx wraps ProjectDiscovery's dnsx for fast, reliable resolution through its own
// resolver pool: A/AAAA/CNAME in one pass. It is active and runs only when the binary
// is installed.
type DNSx struct{ Runner Runner }

// NewDNSx returns a dnsx adapter using the default runner.
func NewDNSx() *DNSx { return &DNSx{Runner: defaultRunner} }

// Capability marks it active, consuming a host and producing IPs and hosts.
func (d *DNSx) Capability() sources.Capability {
	return sources.Capability{
		Name:     "pdtools/dnsx",
		Consumes: []graph.EntityType{graph.TypeHost},
		Produces: []graph.EntityType{graph.TypeIP, graph.TypeHost},
		Passive:  false,
		Cost:     1,
	}
}

// Available reports whether dnsx is on PATH.
func (d *DNSx) Available(sources.Env) bool { return available("dnsx") }

// dnsxLine is the subset of dnsx's JSON output the adapter reads.
type dnsxLine struct {
	Host  string   `json:"host"`
	A     []string `json:"a"`
	AAAA  []string `json:"aaaa"`
	CNAME []string `json:"cname"`
}

// Collect feeds the host to dnsx on stdin and records its addresses and CNAME.
func (d *DNSx) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	if !safeArg(in.Key) {
		return nil
	}
	out, err := d.Runner.Run(ctx, "dnsx", []string{"-silent", "-json", "-a", "-aaaa", "-cname", "-resp"}, []byte(in.Key+"\n"))
	if err != nil {
		return err
	}
	self := sink.Entity(graph.TypeHost, in.Key, in.Key)
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r dnsxLine
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		for _, addr := range append(r.A, r.AAAA...) {
			if addr = strings.TrimSpace(addr); addr == "" {
				continue
			}
			ip := sink.Entity(graph.TypeIP, addr, addr)
			sink.Edge(self, ip, graph.RelResolvesTo, 1.0)
		}
		for _, cn := range r.CNAME {
			cn = trimName(cn)
			if validHost(cn) && cn != in.Key {
				sink.Fact(self, "cname", cn, 1.0)
				sink.Entity(graph.TypeHost, cn, cn)
			}
		}
	}
	return nil
}
