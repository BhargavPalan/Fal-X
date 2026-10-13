package native

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// maxNSECWalk bounds how many names a zone walk will follow, so a large zone cannot run
// unbounded.
const maxNSECWalk = 5000

// NSEC walks a DNSSEC-signed zone through its NSEC chain. NSEC records, meant to prove a
// name does not exist, each point to the next name in the zone, so following the chain
// enumerates every name — a zone that refuses AXFR but signs with plain NSEC still
// gives up its whole contents. It is active: it queries the zone's name servers on
// TCP/53. NSEC3 (hashed) zones do not walk online and are left alone.
type NSEC struct {
	Resolver RecordResolver
	Dial     func(ctx context.Context, addr string) (net.Conn, error)
	Timeout  time.Duration
}

// NewNSEC returns an NSEC walker using the system resolver for the NS lookup.
func NewNSEC() *NSEC { return &NSEC{Resolver: net.DefaultResolver, Timeout: 15 * time.Second} }

// Capability marks it active, consuming a domain and producing hosts.
func (n *NSEC) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/nsec",
		Consumes: []graph.EntityType{graph.TypeDomain},
		Produces: []graph.EntityType{graph.TypeHost},
		Passive:  false,
		Cost:     1,
	}
}

// Available is always true; it uses the standard library.
func (n *NSEC) Available(sources.Env) bool { return true }

// Collect walks the zone from the first name server that answers NSEC queries.
func (n *NSEC) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	zone := in.Key
	ns, _ := n.Resolver.LookupNS(ctx, zone)
	for _, server := range ns {
		if names := n.walk(ctx, trimName(server.Host), zone); len(names) > 0 {
			self := sink.Entity(graph.TypeDomain, zone, zone)
			for _, name := range names {
				if isHostname(name) && (name == zone || strings.HasSuffix(name, "."+zone)) {
					h := sink.Entity(graph.TypeHost, name, name)
					sink.Edge(h, self, graph.RelSubdomainOf, 1.0)
				}
			}
			return nil
		}
	}
	return nil
}

// walk follows the NSEC chain on one name server, returning the names it enumerated.
func (n *NSEC) walk(ctx context.Context, nsHost, zone string) []string {
	if !isHostname(nsHost) {
		return nil
	}
	conn, err := n.dial(ctx, net.JoinHostPort(nsHost, "53"))
	if err != nil {
		return nil
	}
	defer conn.Close()
	if n.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(n.Timeout))
	}

	var names []string
	seen := map[string]bool{}
	current := zone
	for range maxNSECWalk {
		if err := writeDNSMessage(conn, buildQuery(current, typeNSEC)); err != nil {
			break
		}
		msg, err := readDNSMessage(conn)
		if err != nil {
			break
		}
		next := nsecNext(msg)
		// The chain ends when it wraps back to the apex or repeats; an empty next means
		// the server did not answer with NSEC (likely NSEC3 or no DNSSEC).
		if next == "" || next == zone || seen[next] {
			break
		}
		seen[next] = true
		names = append(names, next)
		current = next
	}
	return names
}

// dial opens a TCP connection, using the injected dialer when present.
func (n *NSEC) dial(ctx context.Context, addr string) (net.Conn, error) {
	if n.Dial != nil {
		return n.Dial(ctx, addr)
	}
	d := net.Dialer{Timeout: n.Timeout}
	return d.DialContext(ctx, "tcp", addr)
}

// nsecNext returns the "next name" field of the first NSEC record in a message's answer
// section, or an empty string when there is none.
func nsecNext(msg []byte) string {
	if len(msg) < 12 {
		return ""
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	for range qd {
		_, o, e := parseName(msg, off)
		if e != nil {
			return ""
		}
		off = o + 4
	}
	for range an {
		_, o, e := parseName(msg, off)
		if e != nil || o+10 > len(msg) {
			return ""
		}
		typ := binary.BigEndian.Uint16(msg[o : o+2])
		rdlen := int(binary.BigEndian.Uint16(msg[o+8 : o+10]))
		rd := o + 10
		if rd+rdlen > len(msg) {
			return ""
		}
		if typ == typeNSEC {
			if name, _, ne := parseName(msg, rd); ne == nil {
				return name
			}
			return ""
		}
		off = rd + rdlen
	}
	return ""
}
