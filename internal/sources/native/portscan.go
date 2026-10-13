package native

import (
	"context"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// topPorts is a compact set of commonly exposed TCP ports: enough to find the
// usual services without the weight of a full 65k sweep.
var topPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587,
	636, 993, 995, 1433, 1521, 1723, 2049, 2375, 3000, 3306, 3389, 5000, 5432,
	5601, 5900, 5984, 6379, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000,
	9200, 9300, 11211, 15672, 27017,
}

// PortScan connect-scans an IP's common TCP ports and emits a service for each open
// one. It is heavy, so it runs only in full mode; it is active (it connects).
type PortScan struct {
	Ports   []int
	Timeout time.Duration
	Conc    int
}

// NewPortScan returns a port scanner over the common ports.
func NewPortScan() *PortScan {
	return &PortScan{Ports: topPorts, Timeout: 1500 * time.Millisecond, Conc: 100}
}

// Capability marks the scan heavy and active, consuming an IP.
func (p *PortScan) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/portscan",
		Consumes: []graph.EntityType{graph.TypeIP},
		Produces: []graph.EntityType{graph.TypeService},
		Passive:  false,
		Heavy:    true,
		Cost:     2,
	}
}

// Available is always true; it uses the standard library.
func (p *PortScan) Available(sources.Env) bool { return true }

// Collect scans the IP and records each open port as a service.
func (p *PortScan) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	ip := in.Key
	self := sink.Entity(graph.TypeIP, ip, ip)
	for _, port := range p.scan(ctx, ip) {
		addr := net.JoinHostPort(ip, strconv.Itoa(port))
		svc := sink.Entity(graph.TypeService, addr, addr)
		sink.Edge(self, svc, graph.RelHosts, 1.0)
		sink.Fact(svc, "port", strconv.Itoa(port), 1.0)
	}
	return nil
}

// scan connect-scans the ports with a bounded worker pool and returns the open
// ones, sorted. It stops feeding work when the context is cancelled.
func (p *PortScan) scan(ctx context.Context, ip string) []int {
	conc := p.Conc
	if conc <= 0 {
		conc = 100
	}
	jobs := make(chan int)
	var (
		mu   sync.Mutex
		open []int
		wg   sync.WaitGroup
	)
	dialer := net.Dialer{Timeout: p.Timeout}
	for i := 0; i < conc; i++ {
		wg.Go(func() {
			for port := range jobs {
				conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
				if err != nil {
					continue
				}
				_ = conn.Close()
				mu.Lock()
				open = append(open, port)
				mu.Unlock()
			}
		})
	}
feed:
	for _, port := range p.Ports {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- port:
		}
	}
	close(jobs)
	wg.Wait()
	sort.Ints(open)
	return open
}
