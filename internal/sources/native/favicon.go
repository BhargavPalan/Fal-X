package native

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// Favicon fetches a host's favicon and records its MurmurHash3 fingerprint the way
// Shodan and Censys index it, so two hosts serving the same icon can be correlated as
// sibling infrastructure (the hash is the pivot key). It is active: it fetches from
// the host.
//
// The hash is a non-cryptographic fingerprint chosen to match the external
// convention, not a security digest; mmh3 is the correct and intended algorithm here.
type Favicon struct {
	Client Doer
}

// NewFavicon returns a favicon source with a bounded client.
func NewFavicon() *Favicon {
	return &Favicon{Client: &http.Client{Timeout: 10 * time.Second}}
}

// Capability marks the source active, consuming a host.
func (f *Favicon) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/favicon",
		Consumes: []graph.EntityType{graph.TypeHost},
		Produces: []graph.EntityType{},
		Passive:  false,
		Cost:     1,
	}
}

// Available is always true; it uses the standard library.
func (f *Favicon) Available(sources.Env) bool { return true }

// Collect fetches /favicon.ico over HTTPS then HTTP and records its mmh3 hash. A host
// that serves no favicon is not an error. The host key is restricted to DNS
// characters upstream (isHostname), so it is safe to interpolate into the URL.
func (f *Favicon) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	host := in.Key
	for _, base := range []string{"https://" + host, "http://" + host} {
		body, err := getBody(ctx, f.Client, base+"/favicon.ico", 1)
		if err != nil || len(body) == 0 {
			continue
		}
		self := sink.Entity(graph.TypeHost, host, host)
		sink.Fact(self, "favicon_mmh3", strconv.Itoa(int(faviconHash(body))), 0.9)
		return nil
	}
	return nil
}

// faviconHash returns the signed 32-bit MurmurHash3 of the base64-encoded favicon,
// matching the http.favicon.hash value Shodan and Censys publish (base64 with a
// newline every 76 bytes and a trailing newline, then mmh3 with seed 0).
func faviconHash(body []byte) int32 {
	enc := base64.StdEncoding.EncodeToString(body)
	var b strings.Builder
	for i := 0; i < len(enc); i += 76 {
		end := min(i+76, len(enc))
		b.WriteString(enc[i:end])
		b.WriteByte('\n')
	}
	//nolint:gosec // the favicon hash is published as a signed 32-bit int; the reinterpretation is the format
	return int32(murmur3x86(([]byte)(b.String()), 0))
}

// murmur3x86 is the 32-bit x86 MurmurHash3 of data with the given seed.
func murmur3x86(data []byte, seed uint32) uint32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	h := seed
	n := len(data) / 4
	for i := range n {
		k := binary.LittleEndian.Uint32(data[i*4:])
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
		h = (h << 13) | (h >> 19)
		h = h*5 + 0xe6546b64
	}
	var k uint32
	tail := data[n*4:]
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data)) //nolint:gosec // body length is bounded well below 2^32; standard mmh3 finalization
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}
