package attackpath

import "testing"

// chain builds: seed(1) -resolves_to- ip(2) -hosts- service(3, origin_exposed) -> bucket(4, jewel),
// plus a dead branch seed(1) -> host(5).
func chain() *Graph {
	g := NewGraph()
	g.AddNode(&Node{ID: 1, Type: "host", Key: "seed.test", SeedDistance: 0})
	g.AddNode(&Node{ID: 2, Type: "ip", Key: "192.0.2.1", SeedDistance: 1})
	g.AddNode(&Node{ID: 3, Type: "service", Key: "192.0.2.1:443", SeedDistance: 2, Exposures: []string{"origin_exposed"}})
	g.AddNode(&Node{ID: 4, Type: "bucket", Key: "aws-s3:data", SeedDistance: 3})
	g.AddNode(&Node{ID: 5, Type: "host", Key: "other.test", SeedDistance: 1})
	g.AddEdge(1, 2, "resolves_to", 1.0)
	g.AddEdge(2, 3, "hosts", 1.0)
	g.AddEdge(3, 4, "serves_url", 0.9)
	g.AddEdge(1, 5, "subdomain_of", 1.0)
	return g
}

func TestAnalyzeFindsEntryToJewelPath(t *testing.T) {
	paths := Analyze(chain())
	if len(paths) != 1 {
		t.Fatalf("got %d paths, want 1 (only the bucket is a reachable jewel)", len(paths))
	}
	p := paths[0]
	if p.Target != 4 {
		t.Errorf("target = %d, want 4 (the bucket)", p.Target)
	}
	ids := make([]int64, len(p.Hops))
	for i, h := range p.Hops {
		ids[i] = h.Node
	}
	want := []int64{1, 2, 3, 4}
	for i := range want {
		if i >= len(ids) || ids[i] != want[i] {
			t.Fatalf("hops = %v, want %v", ids, want)
		}
	}
	if p.Hops[0].Rel != "" {
		t.Errorf("the entry hop should carry no relationship, got %q", p.Hops[0].Rel)
	}
	// jewel(bucket)=30 + exposure(origin_exposed)=15 - chain penalty (3-1)*5=10 => 35.
	if p.Risk != 35 {
		t.Errorf("risk = %d, want 35; reasons=%v", p.Risk, p.Reasons)
	}
	if p.Decision != Attend {
		t.Errorf("decision = %s, want Attend", p.Decision)
	}
}

func TestChokesRanksIntermediates(t *testing.T) {
	chokes := Chokes(Analyze(chain()))
	// Nodes 2 and 3 are intermediates on the single path; the entry and jewel are not.
	seen := map[int64]int{}
	for _, c := range chokes {
		seen[c.Node] = c.PathsCut
	}
	if seen[2] != 1 || seen[3] != 1 {
		t.Errorf("expected intermediates 2 and 3 as choke points, got %+v", chokes)
	}
	if _, ok := seen[1]; ok {
		t.Error("the entry node must not be a choke point")
	}
	if _, ok := seen[4]; ok {
		t.Error("the jewel must not be a choke point")
	}
}

func TestBlastRadius(t *testing.T) {
	g := chain()
	// From the ip (2): reaches service(3) and bucket(4); not the seed-side branch host(5)
	// unless through the seed — the seed(1) is reachable, and from it host(5).
	reach := Blast(g, 2)
	set := map[int64]bool{}
	for _, id := range reach {
		set[id] = true
	}
	if !set[3] || !set[4] {
		t.Errorf("blast from ip should reach service and bucket, got %v", reach)
	}
	if set[2] {
		t.Error("the starting node must not be in its own blast radius")
	}
	// A node with no edges has an empty blast radius.
	g.AddNode(&Node{ID: 9, Type: "host", Key: "island.test"})
	if r := Blast(g, 9); len(r) != 0 {
		t.Errorf("an isolated node has no blast radius, got %v", r)
	}
}

func TestNodeByKey(t *testing.T) {
	g := chain()
	if id, ok := g.NodeByKey("aws-s3:data"); !ok || id != 4 {
		t.Errorf("NodeByKey(bucket) = %d,%v, want 4,true", id, ok)
	}
	if _, ok := g.NodeByKey("missing"); ok {
		t.Error("NodeByKey(missing) should report not found")
	}
}

func TestAnalyzeExcludesSeedJewelAndUnreachable(t *testing.T) {
	g := NewGraph()
	// A jewel that is itself a seed is not an attack path.
	g.AddNode(&Node{ID: 1, Type: "bucket", Key: "aws-s3:seed", SeedDistance: 0})
	// An unreachable jewel (no edge from any entry).
	g.AddNode(&Node{ID: 2, Type: "host", Key: "seed.test", SeedDistance: 0})
	g.AddNode(&Node{ID: 3, Type: "credential", Key: "secret:x", SeedDistance: 5})
	if paths := Analyze(g); len(paths) != 0 {
		t.Errorf("expected no paths (seed-jewel + unreachable), got %d", len(paths))
	}
}
