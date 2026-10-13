package native

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// JARM computes the JARM active TLS-server fingerprint (Salesforce's algorithm,
// BSD-3-licensed): ten crafted TLS Client Hellos are sent and the server's choices
// hashed into a 62-character fingerprint. Two hosts with the same JARM run the same TLS
// stack and configuration — a strong signal of shared infrastructure (origin servers,
// sibling hosts, default malware C2 tooling). It is active: it opens ten TCP
// connections to the host on 443.
type JARM struct {
	Dial    func(ctx context.Context, addr string) (net.Conn, error)
	Timeout time.Duration
}

// NewJARM returns a JARM source.
func NewJARM() *JARM { return &JARM{Timeout: 10 * time.Second} }

// Capability marks it active, consuming a host.
func (j *JARM) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/jarm",
		Consumes: []graph.EntityType{graph.TypeHost},
		Produces: []graph.EntityType{},
		Passive:  false,
		Heavy:    true, // ten connections per host
		Cost:     2,
	}
}

// Available is always true; it uses the standard library.
func (j *JARM) Available(sources.Env) bool { return true }

// Collect fingerprints the host on 443. A host that does not speak TLS yields the
// all-zero fingerprint, which is not recorded.
func (j *JARM) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	fp := j.fingerprint(ctx, in.Key)
	if fp == "" || fp == strings.Repeat("0", 62) {
		return nil
	}
	self := sink.Entity(graph.TypeHost, in.Key, in.Key)
	sink.Fact(self, "jarm", fp, 0.9)
	return nil
}

// jarmSpec is one of the ten probe configurations.
type jarmSpec struct {
	version  string // TLS_1.1 / TLS_1.2 / TLS_1.3
	ciphers  string // ALL / NO1.3
	order    string // FORWARD / REVERSE / TOP_HALF / BOTTOM_HALF / MIDDLE_OUT
	grease   bool
	alpnRare bool
	support  string // 1.2_SUPPORT / 1.3_SUPPORT / NO_SUPPORT
	extOrder string // FORWARD / REVERSE
}

// jarmSpecs are the ten probes in order.
var jarmSpecs = []jarmSpec{
	{"TLS_1.2", "ALL", "FORWARD", false, false, "1.2_SUPPORT", "REVERSE"},
	{"TLS_1.2", "ALL", "REVERSE", false, false, "1.2_SUPPORT", "FORWARD"},
	{"TLS_1.2", "ALL", "TOP_HALF", false, false, "NO_SUPPORT", "FORWARD"},
	{"TLS_1.2", "ALL", "BOTTOM_HALF", false, true, "NO_SUPPORT", "FORWARD"},
	{"TLS_1.2", "ALL", "MIDDLE_OUT", true, true, "NO_SUPPORT", "REVERSE"},
	{"TLS_1.1", "ALL", "FORWARD", false, false, "NO_SUPPORT", "FORWARD"},
	{"TLS_1.3", "ALL", "FORWARD", false, false, "1.3_SUPPORT", "REVERSE"},
	{"TLS_1.3", "ALL", "REVERSE", false, false, "1.3_SUPPORT", "FORWARD"},
	{"TLS_1.3", "NO1.3", "FORWARD", false, false, "1.3_SUPPORT", "FORWARD"},
	{"TLS_1.3", "ALL", "MIDDLE_OUT", true, false, "1.3_SUPPORT", "REVERSE"},
}

// fingerprint runs the ten probes against host:443 and hashes the results.
func (j *JARM) fingerprint(ctx context.Context, host string) string {
	raw := make([]string, len(jarmSpecs))
	for i, spec := range jarmSpecs {
		raw[i] = j.probe(ctx, host, spec)
	}
	return jarmHash(raw)
}

// probe sends one Client Hello and reads the Server Hello, returning its component
// string ("cipher|version|alpn|types") or "|||" when nothing usable came back.
func (j *JARM) probe(ctx context.Context, host string, spec jarmSpec) string {
	conn, err := j.dial(ctx, net.JoinHostPort(host, "443"))
	if err != nil {
		return "|||"
	}
	defer conn.Close()
	if j.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(j.Timeout))
	}
	if _, err := conn.Write(buildClientHello(spec, host)); err != nil {
		return "|||"
	}
	buf := make([]byte, 1484)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return "|||"
	}
	return readServerHello(buf[:n])
}

func (j *JARM) dial(ctx context.Context, addr string) (net.Conn, error) {
	if j.Dial != nil {
		return j.Dial(ctx, addr)
	}
	d := net.Dialer{Timeout: j.Timeout}
	return d.DialContext(ctx, "tcp", addr)
}

// greaseValue is a fixed GREASE value; the server ignores GREASE, so a fixed value
// keeps the fingerprint deterministic without changing the result.
var greaseValue = []byte{0x0a, 0x0a}

func u16(n int) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(n)) //nolint:gosec // all lengths here are small TLS fields
	return b
}

// buildClientHello assembles the raw TLS record for one spec.
func buildClientHello(spec jarmSpec, host string) []byte {
	var payload, chVersion []byte
	switch spec.version {
	case "TLS_1.1":
		payload = []byte{0x16, 0x03, 0x02}
		chVersion = []byte{0x03, 0x02}
	case "TLS_1.3":
		payload = []byte{0x16, 0x03, 0x01}
		chVersion = []byte{0x03, 0x03}
	default: // TLS_1.2
		payload = []byte{0x16, 0x03, 0x03}
		chVersion = []byte{0x03, 0x03}
	}

	ch := append([]byte{}, chVersion...)
	ch = append(ch, randomBytes(32)...) // client random
	ch = append(ch, 0x20)               // session id length (32)
	ch = append(ch, randomBytes(32)...) // session id
	ciphers := getCiphers(spec)
	ch = append(ch, u16(len(ciphers))...)
	ch = append(ch, ciphers...)
	ch = append(ch, 0x01, 0x00) // compression methods
	ch = append(ch, getExtensions(spec, host)...)

	handshake := []byte{0x01, 0x00}
	handshake = append(handshake, u16(len(ch))...)
	handshake = append(handshake, ch...)

	payload = append(payload, u16(len(handshake))...)
	payload = append(payload, handshake...)
	return payload
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// jarmCipherList is the "ALL" cipher list.
var jarmCipherList = [][]byte{
	{0x00, 0x16}, {0x00, 0x33}, {0x00, 0x67}, {0xc0, 0x9e}, {0xc0, 0xa2}, {0x00, 0x9e}, {0x00, 0x39}, {0x00, 0x6b},
	{0xc0, 0x9f}, {0xc0, 0xa3}, {0x00, 0x9f}, {0x00, 0x45}, {0x00, 0xbe}, {0x00, 0x88}, {0x00, 0xc4}, {0x00, 0x9a},
	{0xc0, 0x08}, {0xc0, 0x09}, {0xc0, 0x23}, {0xc0, 0xac}, {0xc0, 0xae}, {0xc0, 0x2b}, {0xc0, 0x0a}, {0xc0, 0x24},
	{0xc0, 0xad}, {0xc0, 0xaf}, {0xc0, 0x2c}, {0xc0, 0x72}, {0xc0, 0x73}, {0xcc, 0xa9}, {0x13, 0x02}, {0x13, 0x01},
	{0xcc, 0x14}, {0xc0, 0x07}, {0xc0, 0x12}, {0xc0, 0x13}, {0xc0, 0x27}, {0xc0, 0x2f}, {0xc0, 0x14}, {0xc0, 0x28},
	{0xc0, 0x30}, {0xc0, 0x60}, {0xc0, 0x61}, {0xc0, 0x76}, {0xc0, 0x77}, {0xcc, 0xa8}, {0x13, 0x05}, {0x13, 0x04},
	{0x13, 0x03}, {0xcc, 0x13}, {0xc0, 0x11}, {0x00, 0x0a}, {0x00, 0x2f}, {0x00, 0x3c}, {0xc0, 0x9c}, {0xc0, 0xa0},
	{0x00, 0x9c}, {0x00, 0x35}, {0x00, 0x3d}, {0xc0, 0x9d}, {0xc0, 0xa1}, {0x00, 0x9d}, {0x00, 0x41}, {0x00, 0xba},
	{0x00, 0x84}, {0x00, 0xc0}, {0x00, 0x07}, {0x00, 0x04}, {0x00, 0x05},
}

// jarmCipherListNo13 is the "NO1.3" cipher list (ALL without the TLS 1.3 suites).
var jarmCipherListNo13 = [][]byte{
	{0x00, 0x16}, {0x00, 0x33}, {0x00, 0x67}, {0xc0, 0x9e}, {0xc0, 0xa2}, {0x00, 0x9e}, {0x00, 0x39}, {0x00, 0x6b},
	{0xc0, 0x9f}, {0xc0, 0xa3}, {0x00, 0x9f}, {0x00, 0x45}, {0x00, 0xbe}, {0x00, 0x88}, {0x00, 0xc4}, {0x00, 0x9a},
	{0xc0, 0x08}, {0xc0, 0x09}, {0xc0, 0x23}, {0xc0, 0xac}, {0xc0, 0xae}, {0xc0, 0x2b}, {0xc0, 0x0a}, {0xc0, 0x24},
	{0xc0, 0xad}, {0xc0, 0xaf}, {0xc0, 0x2c}, {0xc0, 0x72}, {0xc0, 0x73}, {0xcc, 0xa9}, {0xcc, 0x14}, {0xc0, 0x07},
	{0xc0, 0x12}, {0xc0, 0x13}, {0xc0, 0x27}, {0xc0, 0x2f}, {0xc0, 0x14}, {0xc0, 0x28}, {0xc0, 0x30}, {0xc0, 0x60},
	{0xc0, 0x61}, {0xc0, 0x76}, {0xc0, 0x77}, {0xcc, 0xa8}, {0xcc, 0x13}, {0xc0, 0x11}, {0x00, 0x0a}, {0x00, 0x2f},
	{0x00, 0x3c}, {0xc0, 0x9c}, {0xc0, 0xa0}, {0x00, 0x9c}, {0x00, 0x35}, {0x00, 0x3d}, {0xc0, 0x9d}, {0xc0, 0xa1},
	{0x00, 0x9d}, {0x00, 0x41}, {0x00, 0xba}, {0x00, 0x84}, {0x00, 0xc0}, {0x00, 0x07}, {0x00, 0x04}, {0x00, 0x05},
}

// getCiphers returns the cipher-suite bytes for a spec, ordered and optionally
// GREASE-prefixed.
func getCiphers(spec jarmSpec) []byte {
	list := jarmCipherList
	if spec.ciphers == "NO1.3" {
		list = jarmCipherListNo13
	}
	ordered := cipherMung(list, spec.order)
	if spec.grease {
		ordered = append([][]byte{greaseValue}, ordered...)
	}
	var out []byte
	for _, c := range ordered {
		out = append(out, c...)
	}
	return out
}

// cipherMung reorders a list per the JARM ordering rules.
func cipherMung(ciphers [][]byte, request string) [][]byte {
	n := len(ciphers)
	switch request {
	case "REVERSE":
		out := make([][]byte, n)
		for i := range ciphers {
			out[n-1-i] = ciphers[i]
		}
		return out
	case "BOTTOM_HALF":
		if n%2 == 1 {
			return ciphers[n/2+1:]
		}
		return ciphers[n/2:]
	case "TOP_HALF":
		var out [][]byte
		if n%2 == 1 {
			out = append(out, ciphers[n/2])
		}
		out = append(out, cipherMung(cipherMung(ciphers, "REVERSE"), "BOTTOM_HALF")...)
		return out
	case "MIDDLE_OUT":
		middle := n / 2
		var out [][]byte
		if n%2 == 1 {
			out = append(out, ciphers[middle])
			for i := 1; i <= middle; i++ {
				out = append(out, ciphers[middle+i], ciphers[middle-i])
			}
		} else {
			for i := 1; i <= middle; i++ {
				out = append(out, ciphers[middle-1+i], ciphers[middle-i])
			}
		}
		return out
	default: // FORWARD
		return ciphers
	}
}

// getExtensions assembles the Client Hello extensions for a spec.
func getExtensions(spec jarmSpec, host string) []byte {
	var all []byte
	if spec.grease {
		all = append(all, greaseValue...)
		all = append(all, 0x00, 0x00)
	}
	all = append(all, extServerName(host)...)
	all = append(all, 0x00, 0x17, 0x00, 0x00)             // extended_master_secret
	all = append(all, 0x00, 0x01, 0x00, 0x01, 0x01)       // max_fragment_length
	all = append(all, 0xff, 0x01, 0x00, 0x01, 0x00)       // renegotiation_info
	all = append(all, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, // supported_groups
		0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19)
	all = append(all, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00) // ec_point_formats
	all = append(all, 0x00, 0x23, 0x00, 0x00)             // session_ticket
	all = append(all, extALPN(spec)...)
	all = append(all, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, // signature_algorithms
		0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01)
	all = append(all, extKeyShare(spec.grease)...)
	all = append(all, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01) // psk_key_exchange_modes
	if spec.version == "TLS_1.3" || spec.support == "1.2_SUPPORT" {
		all = append(all, extSupportedVersions(spec)...)
	}
	return append(u16(len(all)), all...)
}

// extServerName builds the SNI extension.
func extServerName(host string) []byte {
	ext := []byte{0x00, 0x00}
	ext = append(ext, u16(len(host)+5)...)
	ext = append(ext, u16(len(host)+3)...)
	ext = append(ext, 0x00)
	ext = append(ext, u16(len(host))...)
	return append(ext, host...)
}

var alpnAll = []string{"http/0.9", "http/1.0", "http/1.1", "spdy/1", "spdy/2", "spdy/3", "h2", "h2c", "hq"}
var alpnRare = []string{"http/0.9", "http/1.0", "spdy/1", "spdy/2", "spdy/3", "h2c", "hq"}

// extALPN builds the ALPN extension for a spec.
func extALPN(spec jarmSpec) []byte {
	protos := alpnAll
	if spec.alpnRare {
		protos = alpnRare
	}
	entries := make([][]byte, len(protos))
	for i, p := range protos {
		entries[i] = append([]byte{byte(len(p))}, p...) //nolint:gosec // protocol names are a handful of bytes
	}
	if spec.extOrder != "FORWARD" {
		entries = cipherMung(entries, spec.extOrder)
	}
	var all []byte
	for _, e := range entries {
		all = append(all, e...)
	}
	ext := []byte{0x00, 0x10}
	ext = append(ext, u16(len(all)+2)...)
	ext = append(ext, u16(len(all))...)
	return append(ext, all...)
}

// extKeyShare builds the key_share extension.
func extKeyShare(grease bool) []byte {
	var share []byte
	if grease {
		share = append(share, greaseValue...)
		share = append(share, 0x00, 0x01, 0x00)
	}
	share = append(share, 0x00, 0x1d) // group x25519
	share = append(share, 0x00, 0x20) // key length 32
	share = append(share, randomBytes(32)...)
	ext := []byte{0x00, 0x33}
	ext = append(ext, u16(len(share)+2)...)
	ext = append(ext, u16(len(share))...)
	return append(ext, share...)
}

// extSupportedVersions builds the supported_versions extension.
func extSupportedVersions(spec jarmSpec) []byte {
	tls := [][]byte{{0x03, 0x01}, {0x03, 0x02}, {0x03, 0x03}, {0x03, 0x04}}
	if spec.support == "1.2_SUPPORT" {
		tls = [][]byte{{0x03, 0x01}, {0x03, 0x02}, {0x03, 0x03}}
	}
	if spec.extOrder != "FORWARD" {
		tls = cipherMung(tls, spec.extOrder)
	}
	var versions []byte
	if spec.grease {
		versions = append(versions, greaseValue...)
	}
	for _, v := range tls {
		versions = append(versions, v...)
	}
	ext := []byte{0x00, 0x2b}
	ext = append(ext, u16(len(versions)+1)...)
	ext = append(ext, byte(len(versions))) //nolint:gosec // at most a few TLS version bytes
	return append(ext, versions...)
}

// readServerHello extracts the component string from a Server Hello.
func readServerHello(data []byte) string {
	if len(data) < 44 || data[0] == 21 {
		return "|||"
	}
	if data[0] != 22 || len(data) <= 5 || data[5] != 2 {
		return "|||"
	}
	shLen := int(data[3])<<8 | int(data[4])
	counter := int(data[43])
	if counter+46 > len(data) || len(data) < 11 {
		return "|||"
	}
	cipher := hex.EncodeToString(data[counter+44 : counter+46])
	version := hex.EncodeToString(data[9:11])
	return cipher + "|" + version + "|" + extractExtensions(data, counter, shLen)
}

// extractExtensions reads the Server Hello extensions into the "alpn|types" form.
func extractExtensions(data []byte, counter, shLen int) string {
	if counter+49 > len(data) || data[counter+47] == 11 {
		return "|"
	}
	if counter+53 <= len(data) && string(data[counter+50:counter+53]) == "\x0e\xac\x0b" {
		return "|"
	}
	if len(data) >= 85 && string(data[82:85]) == "\x0f\xf0\x0b" {
		return "|"
	}
	if counter+42 >= shLen {
		return "|"
	}
	count := 49 + counter
	length := int(data[counter+47])<<8 | int(data[counter+48])
	maximum := length + (count - 1)
	var types [][]byte
	var values [][]byte
	for count < maximum {
		if count+4 > len(data) {
			break
		}
		types = append(types, data[count:count+2])
		extLen := int(data[count+2])<<8 | int(data[count+3])
		if extLen == 0 {
			count += 4
			values = append(values, nil)
			continue
		}
		if count+4+extLen > len(data) {
			break
		}
		values = append(values, data[count+4:count+4+extLen])
		count += extLen + 4
	}
	var result strings.Builder
	result.WriteString(alpnValue(types, values) + "|")
	for i, t := range types {
		result.WriteString(hex.EncodeToString(t))
		if i != len(types)-1 {
			result.WriteString("-")
		}
	}
	return result.String()
}

// alpnValue returns the negotiated ALPN protocol string, or "".
func alpnValue(types, values [][]byte) string {
	for i, t := range types {
		if len(t) == 2 && t[0] == 0x00 && t[1] == 0x10 {
			if i < len(values) && len(values[i]) > 3 {
				return string(values[i][3:])
			}
			return ""
		}
	}
	return ""
}

// jarmCipherIndex is the cipher ordering used for the fuzzy hash index.
var jarmCipherIndex = []string{
	"0004", "0005", "0007", "000a", "0016", "002f", "0033", "0035", "0039", "003c", "003d", "0041", "0045",
	"0067", "006b", "0084", "0088", "009a", "009c", "009d", "009e", "009f", "00ba", "00be", "00c0", "00c4",
	"c007", "c008", "c009", "c00a", "c011", "c012", "c013", "c014", "c023", "c024", "c027", "c028", "c02b",
	"c02c", "c02f", "c030", "c060", "c061", "c072", "c073", "c076", "c077", "c09c", "c09d", "c09e", "c09f",
	"c0a0", "c0a1", "c0a2", "c0a3", "c0ac", "c0ad", "c0ae", "c0af", "cc13", "cc14", "cca8", "cca9", "1301",
	"1302", "1303", "1304", "1305",
}

// jarmHash turns the ten component strings into the 62-character fingerprint.
func jarmHash(raw []string) string {
	allEmpty := true
	for _, h := range raw {
		if h != "|||" {
			allEmpty = false
		}
	}
	if allEmpty {
		return strings.Repeat("0", 62)
	}
	var fuzzy, ext strings.Builder
	for _, h := range raw {
		c := strings.SplitN(h, "|", 4)
		for len(c) < 4 {
			c = append(c, "")
		}
		fuzzy.WriteString(cipherIndexByte(c[0]) + versionByte(c[1]))
		ext.WriteString(c[2] + c[3])
	}
	sum := sha256.Sum256([]byte(ext.String()))
	return fuzzy.String() + hex.EncodeToString(sum[:])[:32]
}

// cipherIndexByte returns the 1-based index (two hex chars) of a cipher in the index
// list, "00" for none.
func cipherIndexByte(cipher string) string {
	if cipher == "" {
		return "00"
	}
	count := 1
	for _, c := range jarmCipherIndex {
		if c == cipher {
			break
		}
		count++
	}
	return fmt.Sprintf("%02x", count)
}

// versionByte maps a TLS version to its single-character code.
func versionByte(version string) string {
	if len(version) < 4 {
		return "0"
	}
	const options = "abcdef"
	n, err := strconv.Atoi(version[3:4])
	if err != nil || n >= len(options) {
		return "0"
	}
	return string(options[n])
}
