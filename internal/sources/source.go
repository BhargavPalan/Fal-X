// Package sources defines the recon source plugin: a unit that consumes one kind
// of entity and produces others, declaring up front what it reads, what it emits,
// whether it touches the target, and what it costs.
//
// A source never writes to the database itself. It emits into a Sink, and the
// engine commits a whole Collect as one transaction, so a source that fails
// half-way adds nothing. This keeps sources pure and testable: a fake Sink records
// the emissions and asserts them without a database.
package sources

import (
	"context"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

// Capability describes what a source does, so the engine can schedule it and keep
// it inside the brake.
type Capability struct {
	// Name is a stable identifier, e.g. "native/dns" or "premium/shodan". It is
	// recorded as the source of every fact the source emits.
	Name string
	// Consumes is the entity types this source acts on; Produces is what it emits.
	Consumes []graph.EntityType
	Produces []graph.EntityType
	// Passive is true when the source never sends a packet to the target (it reads
	// third-party data). A passive-only run registers only these.
	Passive bool
	// NeedsAuth is true when the source requires an API key.
	NeedsAuth bool
	// RateLimit is the ceiling in calls per second, 0 for unlimited.
	RateLimit float64
	// CacheTTL is how long a passive result may be reused from source_cache.
	CacheTTL time.Duration
	// Cost is the budget units one Collect spends, defaulting to 1.
	Cost int
	// Heavy marks a source as expensive or noisy (a full port scan, brute force),
	// run only in full mode so an active scan stays responsive.
	Heavy bool
}

// Env is what a source needs from its surroundings: credentials, and later a tool
// runner and an HTTP fetcher. It is passed to Available, and carried on the context
// into Collect so a keyed source can read its credential there too.
type Env struct {
	// Keys holds API credentials by source name. A source reads its own key.
	Keys map[string]string
}

// ctxKey is the unexported type for this package's context values.
type ctxKey int

const envContextKey ctxKey = 0

// WithEnv returns a context carrying env, so a source's Collect can read credentials
// the interface does not pass directly.
func WithEnv(ctx context.Context, env Env) context.Context {
	return context.WithValue(ctx, envContextKey, env)
}

// EnvFromContext returns the Env carried on the context, or the zero Env.
func EnvFromContext(ctx context.Context) Env {
	env, _ := ctx.Value(envContextKey).(Env)
	return env
}

// Sink receives a source's emissions. Entity returns a handle the source uses to
// attach facts and edges; the same (type, key) always returns the same handle
// within one Collect, so a source can reference an entity it just emitted.
type Sink interface {
	Entity(t graph.EntityType, key, display string) graph.Ref
	Fact(on graph.Ref, key, value string, confidence float64)
	Edge(from, to graph.Ref, rel graph.EdgeType, confidence float64)
}

// Source is one recon module.
type Source interface {
	Capability() Capability
	// Available reports whether the source can run: its tool is installed, or its
	// key is present. An unavailable source is skipped, not an error.
	Available(env Env) bool
	// Collect acts on one entity and emits what it finds into the sink.
	Collect(ctx context.Context, in graph.Entity, sink Sink) error
}

// Registry indexes sources by the entity type they consume, so the engine can ask
// "what runs on a host?" and get every applicable source.
type Registry struct {
	byConsumed map[graph.EntityType][]Source
	all        []Source
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byConsumed: map[graph.EntityType][]Source{}}
}

// Register adds a source. A source that consumes several types is indexed under
// each.
func (r *Registry) Register(s Source) {
	r.all = append(r.all, s)
	for _, t := range s.Capability().Consumes {
		r.byConsumed[t] = append(r.byConsumed[t], s)
	}
}

// For returns the sources that consume an entity type, in registration order.
func (r *Registry) For(t graph.EntityType) []Source {
	return r.byConsumed[t]
}

// All returns every registered source.
func (r *Registry) All() []Source {
	return r.all
}
