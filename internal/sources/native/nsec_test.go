package native

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

// buildNSECResponse builds a one-answer message whose NSEC record points owner -> next.
func buildNSECResponse(owner, next string) []byte {
	rdata := appendName(nil, next)
	rdata = append(rdata, 0x00, 0x01, 0x40) // a minimal type bitmap (ignored by the parser)
	rr := buildRR(owner, typeNSEC, rdata)

	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234)
	binary.BigEndian.PutUint16(msg[2:4], 0x8400) // response, authoritative
	binary.BigEndian.PutUint16(msg[6:8], 1)      // one answer
	return append(msg, rr...)
}

func TestNSECWalksChain(t *testing.T) {
	chain := map[string]string{
		"example.com":   "a.example.com",
		"a.example.com": "b.example.com",
		"b.example.com": "example.com", // wraps back to the apex, ending the walk
	}
	n := &NSEC{
		Resolver: fakeRecords{ns: map[string][]string{"example.com": {"ns1.example.com."}}},
		Timeout:  5 * time.Second,
		Dial: func(_ context.Context, _ string) (net.Conn, error) {
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				for {
					q, err := readDNSMessage(server)
					if err != nil {
						return
					}
					qname, _, _ := parseName(q, 12)
					next, ok := chain[qname]
					if !ok {
						return
					}
					if writeDNSMessage(server, buildNSECResponse(qname, next)) != nil {
						return
					}
				}
			}()
			return client, nil
		},
	}
	s := &recSink{}
	if err := n.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "example.com"}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasEntity(graph.TypeHost, "a.example.com") || !s.hasEntity(graph.TypeHost, "b.example.com") {
		t.Errorf("expected the walked names as hosts, entities=%+v", s.entities)
	}
}
