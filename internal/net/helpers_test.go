package net

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// countingServer is a loopback HTTP server that records whether it was
// contacted at all.
//
// That record is the point. A refusal that still issued a request would pass
// every other assertion in this file while doing exactly the thing the gate
// exists to prevent.
type countingServer struct {
	srv  *httptest.Server
	hits *atomic.Int64
}

// newCountingServer starts a server that serves "ok" and counts requests.
func newCountingServer(t *testing.T, contacted *bool) *countingServer {
	t.Helper()

	cs := &countingServer{hits: new(atomic.Int64)}
	cs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.hits.Add(1)
		if contacted != nil {
			*contacted = true
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(cs.srv.Close)

	return cs
}

func (cs *countingServer) port() string {
	u := cs.srv.URL
	_, port, err := net.SplitHostPort(strings.TrimPrefix(u, "http://"))
	if err != nil || port == "" {
		return ""
	}
	if _, err := strconv.Atoi(port); err != nil {
		return ""
	}
	return port
}

// redirectingServer starts a server that answers every request with a redirect
// to target.
func redirectingServer(t *testing.T, target string, contacted *atomic.Int64) *countingServer {
	t.Helper()

	cs := &countingServer{hits: contacted}
	cs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.hits.Add(1)
		http.Redirect(w, r, target, http.StatusFound)
	}))
	t.Cleanup(cs.srv.Close)

	return cs
}
