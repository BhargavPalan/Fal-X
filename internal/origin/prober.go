package origin

import (
	"context"
	"crypto/tls"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// titleRe extracts the first HTML title for the signature.
var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// sigBodyPrefix is how much of a body contributes to the signature.
const sigBodyPrefix = 4 << 10

// httpProber confirms origins over HTTP. TLS verification is skipped because an origin
// reached by IP serves a certificate for its own name, not the one we claim.
type httpProber struct{ client *http.Client }

// NewHTTPProber returns the default network prober.
func NewHTTPProber() Prober {
	return &httpProber{client: &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // an origin reached by IP presents a cert for its own name
	}}
}

// Signature fetches the host through its normal path.
func (p *httpProber) Signature(ctx context.Context, host string) (string, bool) {
	return p.first(ctx, host, host)
}

// Probe fetches the IP directly while claiming to be host.
func (p *httpProber) Probe(ctx context.Context, ip, host string) (string, bool) {
	return p.first(ctx, ip, host)
}

// first tries HTTPS then HTTP against connectTo, sending hostHeader as the Host, and
// returns a response signature.
func (p *httpProber) first(ctx context.Context, connectTo, hostHeader string) (string, bool) {
	for _, scheme := range []string{"https://", "http://"} {
		if sig, ok := p.fetch(ctx, scheme+connectTo+"/", hostHeader); ok {
			return sig, true
		}
	}
	return "", false
}

// fetch requests one URL with a Host header and returns a content signature. Only a 200
// with a non-trivial body yields a signature, so error and placeholder pages do not
// produce spurious matches.
func (p *httpProber) fetch(ctx context.Context, rawURL, hostHeader string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", false
	}
	req.Host = hostHeader
	req.Header.Set("User-Agent", "fal-x")
	resp, err := p.client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, sigBodyPrefix))
	if len(body) < 64 {
		return "", false // too little content to compare safely
	}
	title := ""
	if m := titleRe.FindSubmatch(body); m != nil {
		title = strings.Join(strings.Fields(string(m[1])), " ")
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(title))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(body)
	return fmt.Sprintf("%s:%x", title, h.Sum64()), true
}
