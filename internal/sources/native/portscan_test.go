package native

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestPortScanFindsOpenPort(t *testing.T) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	open := ln.Addr().(*net.TCPAddr).Port
	// A port very likely closed on loopback, to prove the scanner rejects it.
	closed := open + 1

	p := &PortScan{Ports: []int{open, closed}, Timeout: time.Second, Conc: 4}
	s := &recSink{}
	if err := p.Collect(context.Background(), graph.Entity{Type: graph.TypeIP, Key: "127.0.0.1"}, s); err != nil {
		t.Fatal(err)
	}

	wantSvc := "127.0.0.1:" + strconv.Itoa(open)
	if !s.hasEntity(graph.TypeService, wantSvc) {
		t.Errorf("expected open service %s, got %+v", wantSvc, s.entities)
	}
	if s.hasEntity(graph.TypeService, "127.0.0.1:"+strconv.Itoa(closed)) {
		t.Errorf("closed port %d must not be reported", closed)
	}
	hosts := 0
	for _, r := range s.edges {
		if r == graph.RelHosts {
			hosts++
		}
	}
	if hosts != 1 {
		t.Errorf("hosts edges = %d, want 1", hosts)
	}
}
