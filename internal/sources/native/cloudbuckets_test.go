package native

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestBucketHelpers(t *testing.T) {
	if got := baseLabel("www.example.co.uk"); got != "co" {
		t.Errorf("baseLabel approximates the registrable label; got %q", got) // documents the limitation
	}
	if got := baseLabel("example.com"); got != "example" {
		t.Errorf("baseLabel(example.com) = %q, want example", got)
	}
	if !validBucketName("example-backup") || validBucketName("-bad") || validBucketName("x") {
		t.Error("validBucketName rules are wrong")
	}
}

// bucketDoer returns a public S3 listing for one target bucket and 404 for the rest.
type bucketDoer struct{ publicURL string }

func (d bucketDoer) Do(r *http.Request) (*http.Response, error) {
	body, status := "", http.StatusNotFound
	if strings.HasPrefix(r.URL.String(), d.publicURL) {
		body, status = `<?xml version="1.0"?><ListBucketResult><Name>example</Name></ListBucketResult>`, http.StatusOK
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
}

func TestCloudBucketsDetectsPublic(t *testing.T) {
	c := &CloudBuckets{Client: bucketDoer{publicURL: "https://example.s3.amazonaws.com/"}}
	s := &recSink{}
	if err := c.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "example.com"}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasEntity(graph.TypeBucket, "aws-s3:example") {
		t.Errorf("expected the discovered bucket entity, entities=%+v", s.entities)
	}
	if !s.hasFact("exposure", "open_bucket") {
		t.Errorf("expected the open_bucket exposure, facts=%+v", s.facts)
	}
	if !s.hasFact("finding", "high open-cloud-bucket aws-s3") {
		t.Errorf("expected the open-bucket finding, facts=%+v", s.facts)
	}
}
