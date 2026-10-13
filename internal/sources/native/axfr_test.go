package native

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

// buildRR encodes one uncompressed resource record.
func buildRR(name string, typ uint16, rdata []byte) []byte {
	b := appendName(nil, name)
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, classIN)
	b = binary.BigEndian.AppendUint32(b, 300)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rdata))) //nolint:gosec // test rdata is small
	return append(b, rdata...)
}

// buildAXFRResponse builds a single-message AXFR answer bracketed by two SOAs.
func buildAXFRResponse() []byte {
	soaRD := appendName(nil, "ns1.example.com")
	soaRD = appendName(soaRD, "admin.example.com")
	soaRD = append(soaRD, make([]byte, 20)...) // serial/refresh/retry/expire/minimum

	answers := [][]byte{
		buildRR("example.com", typeSOA, soaRD),
		buildRR("host1.example.com", typeA, []byte{192, 0, 2, 1}),
		buildRR("www.example.com", typeCNAME, appendName(nil, "host1.example.com")),
		buildRR("example.com", typeSOA, soaRD),
	}

	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234)
	binary.BigEndian.PutUint16(msg[2:4], 0x8400)               // response, authoritative
	binary.BigEndian.PutUint16(msg[6:8], uint16(len(answers))) //nolint:gosec // fixed small count
	for _, a := range answers {
		msg = append(msg, a...)
	}
	return msg
}

func TestAXFRParsesZone(t *testing.T) {
	a := &AXFR{
		Resolver: fakeRecords{ns: map[string][]string{"example.com": {"ns1.example.com."}}},
		Timeout:  5 * time.Second,
		Dial: func(_ context.Context, _ string) (net.Conn, error) {
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				if _, err := readDNSMessage(server); err != nil { // read the query
					return
				}
				_ = writeDNSMessage(server, buildAXFRResponse())
			}()
			return client, nil
		},
	}
	s := &recSink{}
	if err := a.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "example.com"}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasFact("finding", "high zone-transfer-allowed") {
		t.Errorf("expected the zone-transfer finding, facts=%+v", s.facts)
	}
	if !s.hasEntity(graph.TypeHost, "host1.example.com") || !s.hasEntity(graph.TypeIP, "192.0.2.1") {
		t.Errorf("expected the A record host+ip, entities=%+v", s.entities)
	}
	if !s.hasEntity(graph.TypeHost, "www.example.com") {
		t.Errorf("expected the CNAME owner host, entities=%+v", s.entities)
	}
}

func TestParseNameFollowsCompressionPointer(t *testing.T) {
	// A message with "example.com" at offset 12, then "www" + a pointer back to 12.
	msg := make([]byte, 12)
	base := len(msg)
	msg = appendName(msg, "example.com") // at offset 12
	start := len(msg)
	msg = append(msg, 3, 'w', 'w', 'w') // label "www"
	var ptr [2]byte
	binary.BigEndian.PutUint16(ptr[:], 0xC000|uint16(base)) //nolint:gosec // base offset is tiny
	msg = append(msg, ptr[:]...)

	name, next, err := parseName(msg, start)
	if err != nil {
		t.Fatal(err)
	}
	if name != "www.example.com" {
		t.Errorf("parseName = %q, want www.example.com", name)
	}
	if next != start+6 { // 1 len + 3 bytes + 2 pointer
		t.Errorf("next offset = %d, want %d", next, start+6)
	}
}
