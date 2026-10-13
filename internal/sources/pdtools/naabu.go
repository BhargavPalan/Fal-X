package pdtools

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// Naabu wraps ProjectDiscovery's naabu, a fast SYN/CONNECT port scanner that is
// CDN-aware. It is heavy and active, so it runs only in full mode and only when the
// binary is installed.
type Naabu struct {
	Runner   Runner
	TopPorts string // naabu -top-ports value
}

// NewNaabu returns a naabu adapter scanning the top 1000 ports.
func NewNaabu() *Naabu { return &Naabu{Runner: defaultRunner, TopPorts: "1000"} }

// Capability marks it heavy and active, consuming an IP and producing services.
func (n *Naabu) Capability() sources.Capability {
	return sources.Capability{
		Name:     "pdtools/naabu",
		Consumes: []graph.EntityType{graph.TypeIP},
		Produces: []graph.EntityType{graph.TypeService},
		Passive:  false,
		Heavy:    true,
		Cost:     2,
	}
}

// Available reports whether naabu is on PATH.
func (n *Naabu) Available(sources.Env) bool { return available("naabu") }

// naabuLine is the subset of naabu's JSON output the adapter reads.
type naabuLine struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// Collect runs naabu against the IP and records each open port as a service.
func (n *Naabu) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	if !safeArg(in.Key) {
		return nil
	}
	top := n.TopPorts
	if top == "" {
		top = "1000"
	}
	out, err := n.Runner.Run(ctx, "naabu", []string{"-silent", "-json", "-host", in.Key, "-top-ports", top}, nil)
	if err != nil {
		return err
	}
	self := sink.Entity(graph.TypeIP, in.Key, in.Key)
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r naabuLine
		if json.Unmarshal([]byte(line), &r) != nil || r.Port <= 0 {
			continue
		}
		addr := net.JoinHostPort(in.Key, strconv.Itoa(r.Port))
		svc := sink.Entity(graph.TypeService, addr, addr)
		sink.Edge(self, svc, graph.RelHosts, 1.0)
		sink.Fact(svc, "port", strconv.Itoa(r.Port), 1.0)
	}
	return nil
}
