package native

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// AXFR attempts a DNS zone transfer against each of a domain's name servers. A server
// that answers is badly misconfigured — it hands over every record in the zone, the
// single highest-yield subdomain source there is — so a successful transfer is both a
// flood of new hosts and a reported exposure. It is active: it connects to the name
// servers on TCP/53. The DNS wire format is parsed directly, since the standard
// library does not implement AXFR.
type AXFR struct {
	Resolver RecordResolver
	// Dial is injectable for testing; nil uses a real TCP dialer.
	Dial    func(ctx context.Context, addr string) (net.Conn, error)
	Timeout time.Duration
}

// NewAXFR returns an AXFR source using the system resolver for the NS lookup.
func NewAXFR() *AXFR { return &AXFR{Resolver: net.DefaultResolver, Timeout: 15 * time.Second} }

// Capability marks it active, consuming a domain and producing hosts and IPs.
func (a *AXFR) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/axfr",
		Consumes: []graph.EntityType{graph.TypeDomain},
		Produces: []graph.EntityType{graph.TypeHost, graph.TypeIP},
		Passive:  false,
		Cost:     1,
	}
}

// Available is always true; it uses the standard library.
func (a *AXFR) Available(sources.Env) bool { return true }

// Collect tries a zone transfer from each name server and emits the zone on the first
// that allows it.
func (a *AXFR) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	zone := in.Key
	// A domain with no NS (or a lookup failure) simply has nothing to transfer.
	ns, _ := a.Resolver.LookupNS(ctx, zone)
	for _, n := range ns {
		recs, ok := a.transfer(ctx, trimName(n.Host), zone)
		if !ok || len(recs) == 0 {
			continue
		}
		a.emit(zone, recs, sink)
		return nil // one successful transfer dumps the whole zone
	}
	return nil
}

// emit writes a successful transfer: the exposure itself, and every in-zone host and
// address it revealed.
func (a *AXFR) emit(zone string, recs []axfrRecord, sink sources.Sink) {
	self := sink.Entity(graph.TypeDomain, zone, zone)
	sink.Fact(self, "finding", "high zone-transfer-allowed", 0.9)
	sink.Fact(self, "exposure", "zone_transfer", 0.9)
	for _, rec := range recs {
		owner := trimName(rec.owner)
		if !isHostname(owner) || (owner != zone && !strings.HasSuffix(owner, "."+zone)) {
			continue
		}
		oh := sink.Entity(graph.TypeHost, owner, owner)
		sink.Edge(oh, self, graph.RelSubdomainOf, 1.0)
		if rec.ip != "" {
			ip := sink.Entity(graph.TypeIP, rec.ip, rec.ip)
			sink.Edge(oh, ip, graph.RelResolvesTo, 1.0)
		}
		if t := trimName(rec.target); isHostname(t) {
			sink.Entity(graph.TypeHost, t, t)
		}
	}
}

// transfer runs one AXFR against a name server and returns the records it sent.
func (a *AXFR) transfer(ctx context.Context, nsHost, zone string) ([]axfrRecord, bool) {
	if !isHostname(nsHost) {
		return nil, false
	}
	conn, err := a.dial(ctx, net.JoinHostPort(nsHost, "53"))
	if err != nil {
		return nil, false
	}
	defer conn.Close()
	if a.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(a.Timeout))
	}
	if err := writeDNSMessage(conn, buildAXFRQuery(zone)); err != nil {
		return nil, false
	}
	var all []axfrRecord
	soa := 0
	for {
		msg, err := readDNSMessage(conn)
		if err != nil {
			break
		}
		recs, soaSeen := parseRecords(msg)
		all = append(all, recs...)
		soa += soaSeen
		// An AXFR stream begins and ends with the zone's SOA, so two SOAs mark the end.
		if soa >= 2 {
			break
		}
	}
	return all, len(all) > 0
}

// dial opens a TCP connection, using the injected dialer when present.
func (a *AXFR) dial(ctx context.Context, addr string) (net.Conn, error) {
	if a.Dial != nil {
		return a.Dial(ctx, addr)
	}
	d := net.Dialer{Timeout: a.Timeout}
	return d.DialContext(ctx, "tcp", addr)
}

// axfrRecord is one resource record's recon-relevant fields.
type axfrRecord struct {
	owner  string
	ip     string // set for A/AAAA
	target string // set for CNAME/NS/PTR/MX
}

const (
	typeA     = 1
	typeNS    = 2
	typeCNAME = 5
	typeSOA   = 6
	typePTR   = 12
	typeMX    = 15
	typeNSEC  = 47
	typeAXFR  = 252
	classIN   = 1
)

var errShortMessage = errors.New("axfr: short DNS message")

// buildAXFRQuery builds a standard-query DNS message asking for the zone's AXFR.
func buildAXFRQuery(zone string) []byte { return buildQuery(zone, typeAXFR) }

// buildQuery builds a standard DNS query for one name and type.
func buildQuery(name string, qtype uint16) []byte {
	msg := make([]byte, 12, 32+len(name))
	binary.BigEndian.PutUint16(msg[0:2], 0x1234) // a fixed id is fine on a dedicated TCP connection
	binary.BigEndian.PutUint16(msg[4:6], 1)      // one question
	msg = appendName(msg, name)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, classIN)
	return msg
}

// appendName encodes a domain name as length-prefixed labels ending in a zero byte.
func appendName(b []byte, name string) []byte {
	for label := range strings.SplitSeq(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			label = label[:63]
		}
		b = append(b, byte(len(label))) //nolint:gosec // label length is capped at 63 just above
		b = append(b, label...)
	}
	return append(b, 0)
}

// writeDNSMessage writes a DNS message with the 2-byte length prefix TCP transport
// requires.
func writeDNSMessage(w io.Writer, msg []byte) error {
	if len(msg) > 0xFFFF {
		return errors.New("axfr: message too long for TCP framing")
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(msg))) //nolint:gosec // bounded to 0xFFFF just above
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

// readDNSMessage reads one length-prefixed DNS message.
func readDNSMessage(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 {
		return nil, errShortMessage
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// parseRecords walks a DNS message's answer section and returns the recon-relevant
// records plus how many SOA records it carried (for end-of-transfer detection). It is
// best-effort: a truncated or malformed message yields the records parsed so far.
func parseRecords(msg []byte) (recs []axfrRecord, soaSeen int) {
	if len(msg) < 12 {
		return nil, 0
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	for range qd {
		_, o, e := parseName(msg, off)
		if e != nil {
			return recs, soaSeen
		}
		off = o + 4 // qtype + qclass
	}
	for range an {
		owner, o, e := parseName(msg, off)
		if e != nil || o+10 > len(msg) {
			break
		}
		typ := binary.BigEndian.Uint16(msg[o : o+2])
		rdlen := int(binary.BigEndian.Uint16(msg[o+8 : o+10]))
		rd := o + 10
		if rd+rdlen > len(msg) {
			break
		}
		rec := axfrRecord{owner: owner}
		switch typ {
		case typeA:
			if rdlen == 4 {
				rec.ip = net.IP(msg[rd : rd+4]).String()
			}
		case typeAAAA:
			if rdlen == 16 {
				rec.ip = net.IP(msg[rd : rd+16]).String()
			}
		case typeCNAME, typeNS, typePTR:
			if n, _, ne := parseName(msg, rd); ne == nil {
				rec.target = n
			}
		case typeMX:
			if rdlen >= 3 {
				if n, _, ne := parseName(msg, rd+2); ne == nil {
					rec.target = n
				}
			}
		case typeSOA:
			soaSeen++
		}
		recs = append(recs, rec)
		off = rd + rdlen
	}
	return recs, soaSeen
}

// typeAAAA is 28; declared here to keep the record-type block above uncluttered.
const typeAAAA = 28

// parseName decodes a DNS name at off, following compression pointers, and returns the
// name and the offset just past the name in the original stream. A pointer budget
// stops a crafted compression loop.
func parseName(msg []byte, off int) (string, int, error) {
	var labels []string
	orig := off
	jumped := false
	budget := 0
	for {
		if off >= len(msg) {
			return "", 0, errShortMessage
		}
		b := msg[off]
		switch {
		case b == 0:
			off++
			if !jumped {
				orig = off
			}
			return strings.ToLower(strings.Join(labels, ".")), orig, nil
		case b&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, errShortMessage
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3FFF)
			if !jumped {
				orig = off + 2
			}
			jumped = true
			if budget++; budget > 128 {
				return "", 0, errors.New("axfr: compression loop")
			}
			off = ptr
		default:
			l := int(b)
			off++
			if off+l > len(msg) {
				return "", 0, errShortMessage
			}
			labels = append(labels, string(msg[off:off+l]))
			off += l
		}
	}
}
