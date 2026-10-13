package premium

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// emailRe matches an address well enough to accept a harvested contact.
var emailRe = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// keyFromContext returns the named credential the engine carries on the context.
func keyFromContext(ctx context.Context, name string) string {
	return sources.EnvFromContext(ctx).Keys[name]
}

// authGet issues one GET with the given headers and returns the body on 200, or nil.
// Every premium adapter funnels through it so credential handling stays in one place
// and a key never leaks into a log or an error.
func authGet(ctx context.Context, client Doer, rawURL string, headers map[string]string) []byte {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "fal-x")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		// cause() drops the URL the net/http error wraps, since it can carry a key.
		logging.Warn("premium: request to %s failed: %v", hostOf(rawURL), cause(err))
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// A misconfigured key or a throttled or down endpoint must be visible; a plain
		// 404 just means this input had no data, so it stays quiet. The host is logged,
		// never the URL or headers, so a key in the query string is not disclosed.
		switch {
		case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
			logging.Warn("premium: %s rejected the credential (HTTP %d); check the API key", hostOf(rawURL), resp.StatusCode)
		case resp.StatusCode == http.StatusTooManyRequests:
			logging.Warn("premium: %s rate-limited the request (HTTP 429)", hostOf(rawURL))
		case resp.StatusCode >= 500:
			logging.Warn("premium: %s returned server error HTTP %d", hostOf(rawURL), resp.StatusCode)
		}
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return body
}

// hostOf returns a URL's host for a log line. The host is not secret; the path,
// query and headers (which may carry a key) are never logged.
func hostOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		return u.Host
	}
	return "the endpoint"
}

// cause unwraps the net/http *url.Error so a logged transport failure shows the
// underlying cause (a timeout, a refused dial) without the URL, which can carry a key.
func cause(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err
	}
	return err
}

// emitSub emits a hostname under a domain from either a bare label or a full FQDN,
// scoped to the domain so a stray value cannot inject an unrelated host.
func emitSub(sink sources.Sink, domain, nameOrLabel string) {
	name := strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(nameOrLabel)), "."), "*.")
	if name == "" {
		return
	}
	if !strings.Contains(name, ".") {
		name = name + "." + domain // a bare label is a subdomain of the queried domain
	}
	if name != domain && !strings.HasSuffix(name, "."+domain) {
		return
	}
	if !isHostname(name) {
		return
	}
	h := sink.Entity(graph.TypeHost, name, name)
	d := sink.Entity(graph.TypeDomain, domain, domain)
	sink.Edge(h, d, graph.RelSubdomainOf, 1.0)
}
