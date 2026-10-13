package pdtools

import (
	"context"
	"encoding/xml"
	"net"
	"strconv"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// Nmap wraps nmap's service/version detection (-sV), parsed from its XML output (the
// stable interface; the text output is for humans). It gives a product and version
// for non-HTTP services the native probe cannot read, which the CVE matcher then uses.
// It is heavy and active, so it runs only in full mode and only when nmap is installed.
type Nmap struct{ Runner Runner }

// NewNmap returns an nmap adapter using the default runner.
func NewNmap() *Nmap { return &Nmap{Runner: defaultRunner} }

// Capability marks it heavy and active, consuming an IP and producing services and
// technologies.
func (n *Nmap) Capability() sources.Capability {
	return sources.Capability{
		Name:     "pdtools/nmap",
		Consumes: []graph.EntityType{graph.TypeIP},
		Produces: []graph.EntityType{graph.TypeService, graph.TypeTechnology},
		Passive:  false,
		Heavy:    true,
		Cost:     3,
	}
}

// Available reports whether nmap is on PATH.
func (n *Nmap) Available(sources.Env) bool { return available("nmap") }

// nmapRun is the subset of nmap's XML output the adapter reads.
type nmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []struct {
		Ports struct {
			Port []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   int    `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name    string `xml:"name,attr"`
					Product string `xml:"product,attr"`
					Version string `xml:"version,attr"`
					Extra   string `xml:"extrainfo,attr"`
					OSType  string `xml:"ostype,attr"`
					CPE     string `xml:"cpe"`
				} `xml:"service"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

// Collect runs nmap -sV against the IP and records each open service with its product
// and version.
func (n *Nmap) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	if !safeArg(in.Key) {
		return nil
	}
	out, err := n.Runner.Run(ctx, "nmap", []string{"-sV", "-Pn", "-oX", "-", in.Key}, nil)
	if err != nil {
		return err
	}
	// Best-effort: malformed XML parses to an empty document and emits nothing.
	var doc nmapRun
	_ = xml.Unmarshal(out, &doc)
	self := sink.Entity(graph.TypeIP, in.Key, in.Key)
	for _, host := range doc.Hosts {
		for _, p := range host.Ports.Port {
			if p.State.State != "open" || p.PortID <= 0 {
				continue
			}
			addr := net.JoinHostPort(in.Key, strconv.Itoa(p.PortID))
			svc := sink.Entity(graph.TypeService, addr, addr)
			sink.Edge(self, svc, graph.RelHosts, 1.0)
			sink.Fact(svc, "port", strconv.Itoa(p.PortID), 1.0)
			if p.Service.Name != "" {
				sink.Fact(svc, "service", p.Service.Name, 0.9)
			}
			// A product and version is the evidence the CVE matcher reads, so it is
			// recorded under the "tech" key on the service.
			if prod := strings.TrimSpace(p.Service.Product + " " + p.Service.Version); prod != "" {
				sink.Fact(svc, "tech", prod, 0.9)
			}
			if p.Service.CPE != "" {
				sink.Fact(svc, "cpe", p.Service.CPE, 0.9)
			}
			if p.Service.OSType != "" {
				sink.Fact(self, "os", p.Service.OSType, 0.6) // inferred from service banners
			}
		}
	}
	return nil
}
