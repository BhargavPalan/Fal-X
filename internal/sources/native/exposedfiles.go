package native

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// sensitiveFile is a path worth probing and the content signature that confirms a hit,
// so a server returning 200 for everything (a soft 404) does not produce a false
// finding.
type sensitiveFile struct {
	path      string
	signature string // a substring the genuine file contains
	class     string
	value     string // the finding value, severity-first for the prioritiser
}

// sensitiveFiles are the exposures most worth a cheap, read-only GET.
var sensitiveFiles = []sensitiveFile{
	{"/.git/config", "[core]", "exposed_git", "high exposed-git-repository"},
	{"/.git/HEAD", "ref:", "exposed_git", "high exposed-git-repository"},
	{"/.env", "=", "exposed_env", "high exposed-env-file"},
	{"/.svn/entries", "dir", "exposed_svn", "medium exposed-svn-repository"},
	{"/.aws/credentials", "aws_access_key", "exposed_secret", "high exposed-aws-credentials"},
	{"/config.php.bak", "<?php", "exposed_backup", "high exposed-source-backup"},
	{"/web.config.bak", "<configuration", "exposed_backup", "high exposed-source-backup"},
	{"/phpinfo.php", "phpinfo()", "exposed_phpinfo", "medium exposed-phpinfo"},
	{"/server-status", "Apache Server Status", "exposed_status", "medium exposed-server-status"},
	{"/actuator/env", "\"propertySources\"", "exposed_actuator", "high exposed-spring-actuator"},
	{"/.DS_Store", "Bud1", "exposed_dsstore", "low exposed-ds-store"},
}

// SensitiveFileSignature returns the content signature, exposure class and finding
// value for a sensitive path, so a verifier can re-confirm a reported hit with the same
// signature this probe used. ok is false for a path that is not in the probe set.
func SensitiveFileSignature(path string) (signature, class, value string, ok bool) {
	for _, f := range sensitiveFiles {
		if f.path == path {
			return f.signature, f.class, f.value, true
		}
	}
	return "", "", "", false
}

// ExposedFiles probes a web host for a short list of sensitive files that should never
// be served, confirming each by a content signature so a soft 404 does not trigger a
// false finding. A hit is recorded read-only; nothing is downloaded beyond the
// signature check. It is active: it fetches from the host.
type ExposedFiles struct {
	Client Doer
}

// NewExposedFiles returns the probe with a bounded client.
func NewExposedFiles() *ExposedFiles {
	return &ExposedFiles{Client: &http.Client{Timeout: 10 * time.Second}}
}

// Capability marks it active, consuming a host and producing findings.
func (p *ExposedFiles) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/exposedfiles",
		Consumes: []graph.EntityType{graph.TypeHost},
		Produces: []graph.EntityType{graph.TypeFinding},
		Passive:  false,
		Heavy:    true, // a dozen probes per host, so reserved for full mode
		Cost:     2,
	}
}

// Available is always true; it uses the standard library.
func (p *ExposedFiles) Available(sources.Env) bool { return true }

// bodyPrefix is how much of a file is read to check its signature.
const bodyPrefix = 4 << 10

// Collect probes the sensitive paths once a working scheme is found and the host is
// not answering 200 to everything.
func (p *ExposedFiles) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	host := in.Key
	base, ok := p.workingBase(ctx, host)
	if !ok {
		return nil // the host serves no web, or answers 200 to a random path (soft 404)
	}
	self := sink.Entity(graph.TypeHost, host, host)
	for _, f := range sensitiveFiles {
		body, status := p.get(ctx, base+f.path)
		if status != http.StatusOK || !bytes.Contains(body, []byte(f.signature)) {
			continue
		}
		u := base + f.path
		sink.Entity(graph.TypeURL, u, u)
		sink.Fact(self, "finding", f.value, 0.8)
		sink.Fact(self, "exposure", f.class, 0.8)
	}
	return nil
}

// workingBase returns the scheme+host that answers, and false when the host serves no
// web or returns 200 for a random path (so every signature check would be unreliable).
func (p *ExposedFiles) workingBase(ctx context.Context, host string) (string, bool) {
	for _, scheme := range []string{"https://", "http://"} {
		base := scheme + host
		if _, status := p.get(ctx, base+"/"); status == 0 {
			continue // nothing answered on this scheme
		}
		// A random path that returns 200 means the host soft-404s, so file probes here
		// would be false positives.
		if _, status := p.get(ctx, base+"/falx-nonexistent-9f3a2b1c"); status == http.StatusOK {
			return "", false
		}
		return base, true
	}
	return "", false
}

// get fetches a URL and returns a bounded body prefix and the status, or 0 on error.
func (p *ExposedFiles) get(ctx context.Context, rawURL string) ([]byte, int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0
	}
	req.Header.Set("User-Agent", "fal-x")
	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, bodyPrefix))
	return body, resp.StatusCode
}
