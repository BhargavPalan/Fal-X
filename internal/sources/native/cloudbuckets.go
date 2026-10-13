package native

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// bucketAffixes are combined with a domain's base label to guess bucket names, the way
// an organisation tends to name its storage.
var bucketAffixes = []string{
	"", "backup", "backups", "assets", "static", "media", "uploads", "files",
	"data", "public", "private", "dev", "staging", "prod", "logs", "db", "dump",
	"cdn", "images", "downloads", "archive",
}

// CloudBuckets guesses an organisation's object-storage buckets from its domain and
// probes the major providers for each guess: a public bucket that lists its contents
// is a direct exposure, and a private-but-present bucket is still attack surface. The
// probes are read-only GETs; nothing is written or downloaded beyond the listing
// marker. It is heavy (many probes per domain) and active, so it runs only in full
// mode.
type CloudBuckets struct {
	Client Doer
}

// NewCloudBuckets returns a bucket enumerator with a bounded client.
func NewCloudBuckets() *CloudBuckets {
	return &CloudBuckets{Client: &http.Client{Timeout: 10 * time.Second}}
}

// Capability marks it heavy and active, consuming a domain and producing buckets.
func (c *CloudBuckets) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/cloudbuckets",
		Consumes: []graph.EntityType{graph.TypeDomain},
		Produces: []graph.EntityType{graph.TypeBucket, graph.TypeFinding},
		Passive:  false,
		Heavy:    true,
		Cost:     3,
	}
}

// Available is always true; it uses the standard library.
func (c *CloudBuckets) Available(sources.Env) bool { return true }

// listMarker is the XML element a public S3/GCS bucket returns when it lists.
const listMarker = "<ListBucketResult"

// Collect generates candidate names from the domain's base label and probes each on
// S3, GCS and Azure.
func (c *CloudBuckets) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	base := baseLabel(in.Key)
	if base == "" {
		return nil
	}
	self := sink.Entity(graph.TypeDomain, in.Key, in.Key)
	seen := map[string]struct{}{}
	for _, affix := range bucketAffixes {
		for _, name := range bucketNames(base, affix) {
			if _, dup := seen[name]; dup || !validBucketName(name) {
				continue
			}
			seen[name] = struct{}{}
			c.probe(ctx, name, self, sink)
		}
	}
	return nil
}

// probe checks one candidate name on each provider.
func (c *CloudBuckets) probe(ctx context.Context, name string, self graph.Ref, sink sources.Sink) {
	for _, p := range []struct {
		provider, url string
	}{
		{"aws-s3", "https://" + name + ".s3.amazonaws.com/"},
		{"gcs", "https://storage.googleapis.com/" + name + "/"},
		{"azure-blob", "https://" + name + ".blob.core.windows.net/" + name + "?restype=container&comp=list"},
	} {
		body, status := c.get(ctx, p.url)
		switch {
		case status == http.StatusOK && bytes.Contains(body, []byte(listMarker)):
			emitBucket(name, p.provider, "public", sink)
			sink.Fact(self, "finding", "high open-cloud-bucket "+p.provider, 0.8)
		case status == http.StatusForbidden || status == http.StatusConflict:
			// 403 (S3/GCS) or 409 (Azure) means the bucket exists but is not listable.
			emitBucket(name, p.provider, "private", sink)
		}
	}
}

// emitBucket records a discovered bucket and its access.
func emitBucket(name, provider, access string, sink sources.Sink) {
	key := provider + ":" + name
	b := sink.Entity(graph.TypeBucket, key, key)
	sink.Fact(b, "provider", provider, 0.9)
	sink.Fact(b, "access", access, 0.9)
	if access == "public" {
		sink.Fact(b, "exposure", "open_bucket", 0.8)
	}
}

// bucketProbeBody bounds the bytes read to check for a listing marker.
const bucketProbeBody = 4 << 10

// get fetches a URL and returns a bounded body and the status, or 0 on error.
func (c *CloudBuckets) get(ctx context.Context, rawURL string) ([]byte, int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0
	}
	req.Header.Set("User-Agent", "fal-x")
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, bucketProbeBody))
	return body, resp.StatusCode
}

// baseLabel returns a domain's registrable label (the part before the public suffix,
// approximated as the second-to-last label), lowercased.
func baseLabel(domain string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(domain)), ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2]
}

// bucketNames combines a base label and an affix in the common orderings.
func bucketNames(base, affix string) []string {
	if affix == "" {
		return []string{base}
	}
	return []string{base + "-" + affix, affix + "-" + base, base + affix}
}

// validBucketName reports whether s is a syntactically valid S3-style bucket name.
func validBucketName(s string) bool {
	if len(s) < 3 || len(s) > 63 {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9', ch == '-', ch == '.':
		default:
			return false
		}
	}
	return s[0] != '-' && s[0] != '.' && s[len(s)-1] != '-' && s[len(s)-1] != '.'
}
