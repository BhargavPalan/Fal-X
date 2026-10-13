package native

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// takeoverSig is a subdomain-takeover fingerprint: a CNAME target suffix that points at
// a claimable service, and the response-body signature that service returns for an
// unclaimed name. The CNAME alone is only a candidate; the signature confirms the name
// is actually unclaimed and therefore takeoverable.
type takeoverSig struct {
	provider  string
	suffix    string
	signature string
}

// takeoverSigs is the confirmation catalogue (drawn from the can-i-take-over-xyz /
// baddns fingerprint set). The crucial point the simple NXDOMAIN check misses: these
// names RESOLVE (NOERROR) and the host answers HTTP — it is the body that reveals the
// service has no claim for this name.
var takeoverSigs = []takeoverSig{
	{"GitHub Pages", "github.io", "There isn't a GitHub Pages site here"},
	{"Amazon S3", "amazonaws.com", "NoSuchBucket"},
	{"Heroku", "herokudns.com", "No such app"},
	{"Heroku", "herokuapp.com", "No such app"},
	{"Fastly", "fastly.net", "Fastly error: unknown domain"},
	{"Ghost", "ghost.io", "Domain error"},
	{"Surge", "surge.sh", "project not found"},
	{"Bitbucket", "bitbucket.io", "Repository not found"},
	{"Pantheon", "pantheonsite.io", "The gods are wise, but do not know of the site which you seek"},
	{"Tumblr", "tumblr.com", "Whatever you were looking for doesn't currently exist at this address"},
	{"Wordpress", "wordpress.com", "Do you want to register"},
	{"Cargo", "cargocollective.com", "If you're moving your domain away from Cargo"},
	{"Readme", "readme.io", "Project doesnt exist... yet!"},
	{"Help Scout", "helpscoutdocs.com", "No settings were found for this company"},
	{"Unbounce", "unbouncepages.com", "The requested URL was not found on this server"},
	{"Netlify", "netlify.app", "Not Found - Request ID"},
}

// Takeover confirms a subdomain takeover: it resolves a host's CNAME and, when it
// points at a claimable service, fetches the host and checks for that service's
// "unclaimed" signature. A confirmed takeover is reported high; nothing is claimed or
// registered — detection is read-only. It is active.
type Takeover struct {
	Resolver CNAMEResolver
	Client   Doer
}

// NewTakeover returns a takeover confirmer using the system resolver.
func NewTakeover() *Takeover {
	return &Takeover{Resolver: net.DefaultResolver, Client: &http.Client{Timeout: 10 * time.Second}}
}

// Capability marks it active, consuming a host and producing findings.
func (t *Takeover) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/takeover",
		Consumes: []graph.EntityType{graph.TypeHost},
		Produces: []graph.EntityType{graph.TypeFinding},
		Passive:  false,
		Cost:     1,
	}
}

// Available is always true; it uses the standard library.
func (t *Takeover) Available(sources.Env) bool { return true }

// Collect checks the host for a confirmed takeover.
func (t *Takeover) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	// A host with no CNAME errors here; the empty-target check below handles it.
	cname, _ := t.Resolver.LookupCNAME(ctx, in.Key)
	target := trimName(cname)
	if target == "" || strings.EqualFold(target, in.Key) {
		return nil
	}
	sig := takeoverSigForTarget(target)
	if sig == nil {
		return nil // the CNAME does not point at a known claimable service
	}
	body := t.fetch(ctx, in.Key)
	if len(body) == 0 || !bytes.Contains(body, []byte(sig.signature)) {
		return nil // the service serves content for this name, so it is claimed
	}
	self := sink.Entity(graph.TypeHost, in.Key, in.Key)
	sink.Fact(self, "finding", "high subdomain-takeover-confirmed "+sig.provider, 0.9)
	sink.Fact(self, "exposure", "takeover", 0.9)
	sink.Fact(self, "cname_target", target, 0.9)
	return nil
}

// takeoverSigForTarget returns the fingerprint matching a CNAME target, or nil.
func takeoverSigForTarget(target string) *takeoverSig {
	for i := range takeoverSigs {
		s := &takeoverSigs[i]
		if target == s.suffix || strings.HasSuffix(target, "."+s.suffix) || strings.Contains(target, s.suffix) {
			return s
		}
	}
	return nil
}

// fetch gets the host over HTTPS then HTTP and returns the body for ANY status, since
// an unclaimed service typically answers 404.
func (t *Takeover) fetch(ctx context.Context, host string) []byte {
	for _, scheme := range []string{"https://", "http://"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+host+"/", nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "fal-x")
		resp, err := t.Client.Do(req)
		if err != nil {
			continue
		}
		body := readBounded(resp.Body, 64<<10)
		_ = resp.Body.Close()
		if len(body) > 0 {
			return body
		}
	}
	return nil
}
