// Package net is the Go-side path to scan targets, and the dry-run switch.
//
// Gate.GetContext is the only place this program's own code issues an HTTP request
// to a target. It authorizes the URL before sending and again for every redirect
// hop, which it follows by hand. Traffic from the external tools (naabu, httpx,
// nuclei and the rest) is authorized differently: each stage filters the list it
// hands a tool through Gate.Scope().Gate before launching it, so the tool never
// sees a target the scope refuses.
//
// Both rest on one decision, scope.Scope.Gate. This package adds the dry-run
// switch and a single log line per refused target.
//
// The other outbound HTTP in the program is not here and is deliberately ungated:
// internal/intel fetches the NVD, CISA KEV and EPSS feeds, and internal/wordlists
// fetches its lists. Those URLs are fixed in source and are never derived from a
// scan target, so there is nothing an operator's input could redirect. Anything
// whose URL *can* come from a target belongs in this package.
package net

import (
	"errors"
	"fmt"
	"sync"

	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/scope"
)

// Gate applies the scope decision for one run. One Gate is shared by every stage.
type Gate struct {
	sc *scope.Scope

	dryRun bool

	// client is the HTTP client GetContext uses; nil means the package default.
	// Tests replace it with SetHTTPClient.
	client HTTPDoer

	// reported deduplicates denial messages. A denylist that rejects 40,000
	// URLs must not produce 40,000 log lines, and the seen set must not grow
	// without bound either.
	reportMu   sync.Mutex
	reported   map[string]struct{}
	reportedN  int
	reportWarn int
}

// New returns a Gate that authorizes through sc.
func New(sc *scope.Scope) *Gate {
	return &Gate{sc: sc, reported: make(map[string]struct{})}
}

// Scope returns the scope this gate decides against.
func (g *Gate) Scope() *scope.Scope { return g.sc }

// SetDryRun makes RequireAllowed pass everything without evaluating it. The caller
// is responsible for not issuing the request, which keeps --dry-run the same code
// path as a real run with the network closed, not a separate implementation.
func (g *Gate) SetDryRun(v bool) { g.dryRun = v }

// SetHTTPClient replaces the client GetContext uses, so a test can point it at a
// local server.
func (g *Gate) SetHTTPClient(c HTTPDoer) { g.client = c }

// ErrScopeRefused marks a refusal by the scope, distinct from a transport failure.
var ErrScopeRefused = errors.New("refused: target is outside the authorized scope")

// RequireAllowed reports whether a request to target may be issued. It never
// touches the network.
func (g *Gate) RequireAllowed(target, port string) error {
	if g.dryRun {
		logging.Debug("dry run, would contact %s", target)
		return nil
	}

	if g.sc.Gate(target, port) {
		return nil
	}

	g.logDenial(target, port)

	return fmt.Errorf("%w: %s", ErrScopeRefused, describeTarget(target, port))
}

// logDenial explains a refusal once per distinct target.
func (g *Gate) logDenial(target, port string) {
	key := describeTarget(target, port)

	g.reportMu.Lock()
	if _, seen := g.reported[key]; seen {
		g.reportMu.Unlock()
		return
	}
	g.reported[key] = struct{}{}
	g.reportedN++
	// Bound the seen set. Past the cap it is dropped rather than grown, so a
	// wide denylist cannot turn the log into an allocation sink.
	if g.reportedN > g.reportWarn {
		g.reported = make(map[string]struct{})
		g.reportedN = 0
		g.reportWarn = g.reportWarn*2 + 400
	}
	g.reportMu.Unlock()

	logging.Debug("blocked %s, outside scope", key)
}

func describeTarget(target, port string) string {
	if port == "" {
		return target
	}
	return target + ":" + port
}
