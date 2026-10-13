package engine

import (
	"context"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// emitSpec is one entity a fakeSource emits for a given input key.
type emitSpec struct {
	t   graph.EntityType
	key string
}

// fakeSource emits a fixed set of entities per input key, so a run is fully
// deterministic without any network or database.
type fakeSource struct {
	cap  sources.Capability
	emit map[string][]emitSpec
	ran  int
}

func (f *fakeSource) Capability() sources.Capability { return f.cap }
func (f *fakeSource) Available(sources.Env) bool     { return true }

func (f *fakeSource) Collect(_ context.Context, in graph.Entity, sink sources.Sink) error {
	f.ran++
	for _, e := range f.emit[in.Key] {
		r := sink.Entity(e.t, e.key, e.key)
		sink.Fact(r, "seen", "yes", 1.0)
	}
	return nil
}

// fakeCommitter returns the buffer's entities as produced, without a database.
// It is white-box: it reads the unexported buffer because the test is in-package.
type fakeCommitter struct{ commits int }

func (c *fakeCommitter) Commit(_ context.Context, b *Buffer, _ string, _ bool, _ int) ([]Produced, error) {
	c.commits++
	out := make([]Produced, 0, len(b.entities))
	for _, e := range b.entities {
		out = append(out, Produced{Type: e.t, Key: e.key})
	}
	return out, nil
}

// chain builds a registry where host->ip and ip->netblock, the classic recursion
// the engine exists to drive.
func chain() *sources.Registry {
	reg := sources.NewRegistry()
	reg.Register(&fakeSource{
		cap:  sources.Capability{Name: "host2ip", Consumes: []graph.EntityType{graph.TypeHost}, Passive: true, Cost: 1},
		emit: map[string][]emitSpec{"a.example.com": {{graph.TypeIP, "192.0.2.1"}}},
	})
	reg.Register(&fakeSource{
		cap:  sources.Capability{Name: "ip2net", Consumes: []graph.EntityType{graph.TypeIP}, Passive: true, Cost: 1},
		emit: map[string][]emitSpec{"192.0.2.1": {{graph.TypeNetblock, "192.0.2.0/24"}}},
	})
	return reg
}

func seedHost() []graph.Seed { return []graph.Seed{{Type: graph.TypeHost, Key: "a.example.com"}} }

func TestEngineRecurses(t *testing.T) {
	e := &Engine{Reg: chain(), Committer: &fakeCommitter{}, Brake: Brake{MaxDepth: 5}}
	st, err := e.Run(context.Background(), seedHost())
	if err != nil {
		t.Fatal(err)
	}
	// host (seed) -> ip -> netblock: two entities produced beyond the seed.
	if st.Produced != 2 {
		t.Errorf("produced = %d, want 2 (ip, netblock)", st.Produced)
	}
	if st.Jobs != 3 {
		t.Errorf("jobs = %d, want 3 (host, ip, netblock)", st.Jobs)
	}
}

func TestBrakeMaxDepth(t *testing.T) {
	e := &Engine{Reg: chain(), Committer: &fakeCommitter{}, Brake: Brake{MaxDepth: 1}}
	st, err := e.Run(context.Background(), seedHost())
	if err != nil {
		t.Fatal(err)
	}
	// ip is at depth 1 (enqueued); netblock would be depth 2 (refused).
	if st.Produced != 1 {
		t.Errorf("produced = %d, want 1 (ip only; netblock is past MaxDepth)", st.Produced)
	}
}

func TestBrakeBudget(t *testing.T) {
	e := &Engine{Reg: chain(), Committer: &fakeCommitter{}, Brake: Brake{Budget: 1}}
	st, err := e.Run(context.Background(), seedHost())
	if err != nil {
		t.Fatal(err)
	}
	// One unit of budget: only the host's source runs; the ip is never worked.
	if st.Collects != 1 {
		t.Errorf("collects = %d, want 1 (budget stops after the first)", st.Collects)
	}
	if st.BudgetUsed != 1 {
		t.Errorf("budget used = %d, want 1", st.BudgetUsed)
	}
}

func TestBrakeFanout(t *testing.T) {
	reg := sources.NewRegistry()
	reg.Register(&fakeSource{
		cap: sources.Capability{Name: "fanout", Consumes: []graph.EntityType{graph.TypeHost}, Passive: true, Cost: 1},
		emit: map[string][]emitSpec{"a.example.com": {
			{graph.TypeIP, "192.0.2.1"}, {graph.TypeIP, "192.0.2.2"}, {graph.TypeIP, "192.0.2.3"},
		}},
	})
	e := &Engine{Reg: reg, Committer: &fakeCommitter{}, Brake: Brake{MaxDepth: 5, MaxFanout: 1}}
	st, err := e.Run(context.Background(), seedHost())
	if err != nil {
		t.Fatal(err)
	}
	if st.Produced != 1 {
		t.Errorf("produced = %d, want 1 (fan-out capped at 1)", st.Produced)
	}
}

func TestPassiveOnlySkipsActive(t *testing.T) {
	reg := sources.NewRegistry()
	reg.Register(&fakeSource{
		cap:  sources.Capability{Name: "active", Consumes: []graph.EntityType{graph.TypeHost}, Passive: false, Cost: 1},
		emit: map[string][]emitSpec{"a.example.com": {{graph.TypeIP, "192.0.2.1"}}},
	})
	e := &Engine{Reg: reg, Committer: &fakeCommitter{}, Brake: Brake{MaxDepth: 5}, PassiveOnly: true}
	st, err := e.Run(context.Background(), seedHost())
	if err != nil {
		t.Fatal(err)
	}
	if st.Collects != 0 {
		t.Errorf("collects = %d, want 0 (active source skipped in passive-only)", st.Collects)
	}
}

func TestDedupAcrossSources(t *testing.T) {
	reg := sources.NewRegistry()
	// Two sources on host both produce the same ip; it must be enqueued once.
	for _, name := range []string{"a", "b"} {
		reg.Register(&fakeSource{
			cap:  sources.Capability{Name: name, Consumes: []graph.EntityType{graph.TypeHost}, Passive: true, Cost: 1},
			emit: map[string][]emitSpec{"a.example.com": {{graph.TypeIP, "192.0.2.1"}}},
		})
	}
	e := &Engine{Reg: reg, Committer: &fakeCommitter{}, Brake: Brake{MaxDepth: 5}}
	st, err := e.Run(context.Background(), seedHost())
	if err != nil {
		t.Fatal(err)
	}
	if st.Produced != 1 {
		t.Errorf("produced = %d, want 1 (same ip from two sources deduped)", st.Produced)
	}
}
