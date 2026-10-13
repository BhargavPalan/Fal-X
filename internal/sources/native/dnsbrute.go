package native

import (
	"bufio"
	"context"
	_ "embed"
	"net"
	"strings"
	"sync"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// subdomainWordlist is the built-in brute-force wordlist, embedded so the source works
// with no external files. An operator can point at a larger list by setting Words.
//
//go:embed subdomains.txt
var subdomainWordlist string

// bruteWords is the parsed built-in wordlist.
var bruteWords = parseWordlist(subdomainWordlist)

// parseWordlist splits a newline wordlist into distinct, lowercased labels.
func parseWordlist(s string) []string {
	seen := map[string]struct{}{}
	var out []string
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		w := strings.ToLower(strings.TrimSpace(sc.Text()))
		if w == "" {
			continue
		}
		if _, dup := seen[w]; dup {
			continue
		}
		seen[w] = struct{}{}
		out = append(out, w)
	}
	return out
}

// wildcardLabels are unlikely names resolved first: if the zone answers for them it is
// a wildcard, and the addresses they return are the wildcard's, used to filter the
// brute results.
var wildcardLabels = []string{"falx-wild-a7f3b1", "falx-wild-9c2e8d", "falx-wild-4b6f0a"}

// DNSBrute resolves a wordlist of candidate names against a domain to find hosts that
// appear in no passive source. It detects a wildcard zone first and drops any candidate
// that only resolves to the wildcard's addresses, so a catch-all record does not
// manufacture thousands of false hosts. It is heavy (one resolution per word) and
// active, so it runs only in full mode.
type DNSBrute struct {
	Resolver HostResolver
	Words    []string
	Conc     int
}

// NewDNSBrute returns a brute source over the built-in wordlist.
func NewDNSBrute() *DNSBrute {
	return &DNSBrute{Resolver: net.DefaultResolver, Words: bruteWords, Conc: 50}
}

// Capability marks it heavy and active, consuming a domain and producing hosts.
func (b *DNSBrute) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/dnsbrute",
		Consumes: []graph.EntityType{graph.TypeDomain},
		Produces: []graph.EntityType{graph.TypeHost, graph.TypeIP},
		Passive:  false,
		Heavy:    true,
		Cost:     2,
	}
}

// Available is always true; it uses the system resolver.
func (b *DNSBrute) Available(sources.Env) bool { return true }

// hit is a resolved candidate.
type hit struct {
	host string
	ips  []string
}

// Collect brute-forces the domain and emits the names that resolve.
func (b *DNSBrute) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	domain := in.Key
	wildcard := b.wildcardIPs(ctx, domain)

	conc := b.Conc
	if conc <= 0 {
		conc = 50
	}
	jobs := make(chan string)
	results := make(chan hit)
	var wg sync.WaitGroup
	for i := 0; i < conc; i++ {
		wg.Go(func() {
			for w := range jobs {
				host := w + "." + domain
				if !isHostname(host) {
					continue
				}
				addrs, err := b.Resolver.LookupHost(ctx, host)
				if err != nil || len(addrs) == 0 {
					continue
				}
				if onlyWildcard(addrs, wildcard) {
					continue // resolves only to the catch-all, so not a real host
				}
				results <- hit{host: host, ips: addrs}
			}
		})
	}
	go func() {
		defer close(jobs)
		for _, w := range b.Words {
			select {
			case <-ctx.Done():
				return
			case jobs <- w:
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()

	// Emit from this goroutine only, since the sink is not concurrency-safe.
	self := sink.Entity(graph.TypeDomain, domain, domain)
	for h := range results {
		host := sink.Entity(graph.TypeHost, h.host, h.host)
		sink.Edge(host, self, graph.RelSubdomainOf, 1.0)
		for _, a := range h.ips {
			ip := sink.Entity(graph.TypeIP, a, a)
			sink.Edge(host, ip, graph.RelResolvesTo, 1.0)
		}
	}
	return nil
}

// wildcardIPs returns the set of addresses the zone's wildcard answers with, or an
// empty set when the zone has no wildcard.
func (b *DNSBrute) wildcardIPs(ctx context.Context, domain string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, label := range wildcardLabels {
		addrs, err := b.Resolver.LookupHost(ctx, label+"."+domain)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			set[a] = struct{}{}
		}
	}
	return set
}

// onlyWildcard reports whether every address is one of the wildcard's.
func onlyWildcard(addrs []string, wildcard map[string]struct{}) bool {
	if len(wildcard) == 0 {
		return false
	}
	for _, a := range addrs {
		if _, ok := wildcard[a]; !ok {
			return false
		}
	}
	return true
}
