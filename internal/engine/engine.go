// Package engine is the self-driving recon scheduler. It starts from seed
// entities, runs every source that consumes an entity's type, writes what they
// find into the graph, and feeds the newly discovered entities back in, so an IP
// found in a DNS record gets scanned and a certificate SAN gets resolved without a
// second command.
//
// Recursion is bounded only by the brake (seed distance, a global cost budget, and
// a per-collect fan-out cap). There is no scope allowlist: the brake is the sole
// guard against a pivot walking the whole internet, so it is checked before every
// source call.
package engine

import (
	"context"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// Brake bounds recursion. A zero field means that dimension is unbounded.
type Brake struct {
	// MaxDepth is the furthest an entity may be from a seed, in hops.
	MaxDepth int
	// Budget is the total cost units a run may spend across all sources.
	Budget int
	// MaxFanout caps how many new entities one Collect may enqueue.
	MaxFanout int
}

// Produced is a distinct entity a source emitted, returned by a committer so the
// engine can enqueue it.
type Produced struct {
	Type graph.EntityType
	Key  string
}

// Committer writes a buffer's emissions to the graph as the tenant and returns the
// entities produced. It is an interface so the engine can be tested without a
// database.
type Committer interface {
	Commit(ctx context.Context, b *Buffer, source string, passive bool, seedDistance int) ([]Produced, error)
}

// Stats is a summary of what a run did.
type Stats struct {
	Jobs       int // entities dequeued and worked
	Collects   int // source runs attempted
	Produced   int // distinct new entities enqueued
	BudgetUsed int
	Errors     int // source failures (not fatal)
}

// Engine runs the recursive scheduler.
type Engine struct {
	Reg         *sources.Registry
	Committer   Committer
	Brake       Brake
	Env         sources.Env
	PassiveOnly bool
	// Full enables heavy sources (full port scans, brute force). Off keeps an
	// active scan fast.
	Full bool
}

type job struct {
	t     graph.EntityType
	key   string
	depth int
}

func visitKey(t graph.EntityType, key string) string { return string(t) + "\x00" + key }

// Run drives the scheduler from the seeds until the queue drains, the budget is
// spent, or the context is cancelled. A source failure is recorded and the run
// continues; only a commit (database) failure is fatal.
func (e *Engine) Run(ctx context.Context, seeds []graph.Seed) (Stats, error) {
	var stats Stats
	visited := map[string]bool{}
	var queue []job

	// Carry the environment on the context so a keyed source can read its credential
	// in Collect, which the Source interface does not pass directly.
	ctx = sources.WithEnv(ctx, e.Env)

	// Write the seeds at distance 0 and enqueue them.
	seedBuf := NewBuffer()
	for _, s := range seeds {
		ck, disp := graph.Canonicalize(s.Type, s.Key)
		seedBuf.Entity(s.Type, ck, disp)
	}
	if _, err := e.Committer.Commit(ctx, seedBuf, "seed", true, 0); err != nil {
		return stats, err
	}
	for _, s := range seeds {
		ck, _ := graph.Canonicalize(s.Type, s.Key)
		vk := visitKey(s.Type, ck)
		if visited[vk] {
			continue
		}
		visited[vk] = true
		queue = append(queue, job{t: s.Type, key: ck, depth: 0})
	}

	for len(queue) > 0 {
		if ctx.Err() != nil {
			return stats, ctx.Err()
		}
		if e.Brake.Budget > 0 && stats.BudgetUsed >= e.Brake.Budget {
			logging.Info("engine: budget of %d units spent, stopping", e.Brake.Budget)
			break
		}

		j := queue[0]
		queue = queue[1:]
		stats.Jobs++

		for _, src := range e.Reg.For(j.t) {
			c := src.Capability()
			if e.PassiveOnly && !c.Passive {
				continue
			}
			if c.Heavy && !e.Full {
				continue // heavy sources run only in full mode
			}
			if !src.Available(e.Env) {
				continue
			}
			cost := c.Cost
			if cost <= 0 {
				cost = 1
			}
			if e.Brake.Budget > 0 && stats.BudgetUsed+cost > e.Brake.Budget {
				continue // this source would overrun the budget; try cheaper ones
			}

			buf := NewBuffer()
			buf.Entity(j.t, j.key, j.key) // the input, so facts can attach to it
			if err := src.Collect(ctx, graph.Entity{Type: j.t, Key: j.key, SeedDistance: j.depth}, buf); err != nil {
				stats.Errors++
				logging.Warn("engine: source %s on %s %q: %v", c.Name, j.t, j.key, err)
				continue
			}
			stats.Collects++

			produced, err := e.Committer.Commit(ctx, buf, c.Name, c.Passive, j.depth+1)
			if err != nil {
				return stats, err // a database failure is not recoverable mid-run
			}
			stats.BudgetUsed += cost

			fan := 0
			for _, p := range produced {
				if e.Brake.MaxFanout > 0 && fan >= e.Brake.MaxFanout {
					break
				}
				ck, _ := graph.Canonicalize(p.Type, p.Key)
				vk := visitKey(p.Type, ck)
				if visited[vk] {
					continue
				}
				nd := j.depth + 1
				if e.Brake.MaxDepth > 0 && nd > e.Brake.MaxDepth {
					continue
				}
				visited[vk] = true
				queue = append(queue, job{t: p.Type, key: ck, depth: nd})
				stats.Produced++
				fan++
			}
		}
	}
	return stats, nil
}
