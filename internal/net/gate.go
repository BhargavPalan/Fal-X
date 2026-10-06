// Package net is the single network authorization choke point.
//
// No outbound request is issued without passing through Gate.RequireAllowed.
// Stages never construct an HTTP client directly; they call the helpers here,
// and every helper gates first.
//
// This package exists so the authorization decision cannot drift away from the
// request. Adding a new network call means adding a helper here, which makes
// the gate unavoidable.
package net

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/scope"
)

// Gate applies the scope decision and records what it decided.
//
// One Gate is shared by every stage of a run, so the counters describe the run
// as a whole rather than one stage.
type Gate struct {
	sc *scope.Scope

	dryRun bool

	// The HTTP client every helper in this package uses. Set by SetHTTPClient.
	// A nil client means the package default.
	client HTTPDoer

	allowed  atomic.Int64
	denied   atomic.Int64
	redirect atomic.Int64

	// reported deduplicates denial messages. A denylist that rejects 40,000
	// URLs must not produce 40,000 log lines, and it must not grow the seen
	// set without bound either.
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

// SetDryRun closes the network without changing any other decision path.
//
// In dry run the gate is bypassed rather than evaluated, and the caller is
// responsible for not issuing the request. That keeps --dry-run the same code
// path with the network closed instead of a separate implementation that
// quietly skips authorization.
func (g *Gate) SetDryRun(v bool) { g.dryRun = v }

// SetHTTPClient replaces the client every helper uses.
func (g *Gate) SetHTTPClient(c HTTPDoer) { g.client = c }

// Counts returns how many targets were permitted and refused.
//
// The denied count is what makes a run honest: a scan that suppressed 40,000
// out-of-scope requests looks identical to one that found nothing without it.
func (g *Gate) Counts() (allowed, denied int64) {
	return g.allowed.Load(), g.denied.Load()
}

// RedirectsBlocked returns how many redirect hops were refused as out of scope.
func (g *Gate) RedirectsBlocked() int64 { return g.redirect.Load() }

// ErrScopeRefused marks a refusal by the authorization boundary.
//
// It is distinguished from a transport failure so the exit-status contract can
// report an authorization problem differently from a broken tool.
var ErrScopeRefused = errors.New("refused: target is outside the authorized scope")

// RequireAllowed is the gate. It reports whether a request to target may be
// issued.
//
// It never touches the network.
func (g *Gate) RequireAllowed(target, port string) error {
	if g.dryRun {
		logging.Debug("dry run, would contact %s", target)
		return nil
	}

	if g.sc.Gate(target, port) {
		g.allowed.Add(1)
		return nil
	}

	g.denied.Add(1)
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

// describeTarget renders a target for a message.
func describeTarget(target, port string) string {
	if port == "" {
		return target
	}
	return target + ":" + port
}
