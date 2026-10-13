package pdtools

import (
	"context"
	"net"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// Masscan wraps masscan, an asynchronous scanner fast enough to sweep all 65535 ports
// at internet scale. It is heavy and active, so it runs only in full mode and only when
// the binary is installed (and, on most systems, with the privileges raw sockets need).
type Masscan struct {
	Runner Runner
	Rate   string // packets per second
	Ports  string // port spec
}

// NewMasscan returns a masscan adapter sweeping all ports at a modest rate.
func NewMasscan() *Masscan { return &Masscan{Runner: defaultRunner, Rate: "1000", Ports: "1-65535"} }

// Capability marks it heavy and active, consuming an IP and producing services.
func (m *Masscan) Capability() sources.Capability {
	return sources.Capability{
		Name:     "pdtools/masscan",
		Consumes: []graph.EntityType{graph.TypeIP},
		Produces: []graph.EntityType{graph.TypeService},
		Passive:  false,
		Heavy:    true,
		Cost:     3,
	}
}

// Available reports whether masscan is on PATH.
func (m *Masscan) Available(sources.Env) bool { return available("masscan") }

// Collect scans the IP and records each open port. The list output format ("open tcp
// <port> <ip> <ts>") is parsed rather than the JSON, which masscan truncates on
// interrupt.
func (m *Masscan) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	if !safeArg(in.Key) {
		return nil
	}
	rate, ports := m.Rate, m.Ports
	if rate == "" {
		rate = "1000"
	}
	if ports == "" {
		ports = "1-65535"
	}
	out, err := m.Runner.Run(ctx, "masscan", []string{in.Key, "-p", ports, "--rate", rate, "-oL", "-"}, nil)
	if err != nil {
		return err
	}
	self := sink.Entity(graph.TypeIP, in.Key, in.Key)
	for line := range strings.SplitSeq(string(out), "\n") {
		f := strings.Fields(line)
		// open <proto> <port> <ip> <timestamp>
		if len(f) < 4 || f[0] != "open" {
			continue
		}
		port := f[2]
		if port == "" || f[3] != in.Key {
			continue
		}
		addr := net.JoinHostPort(in.Key, port)
		svc := sink.Entity(graph.TypeService, addr, addr)
		sink.Edge(self, svc, graph.RelHosts, 1.0)
		sink.Fact(svc, "port", port, 1.0)
	}
	return nil
}
