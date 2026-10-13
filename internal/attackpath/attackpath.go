// Package attackpath models the chains of abusable steps from an attacker's entry
// point to a crown jewel, and surfaces the choke points whose removal severs the most
// paths. It is BloodHound for the external surface: a node is an entity plus its
// exposures, an edge is a reachability step the recon graph already recorded, and a
// path is the shortest route an attacker could take from a seed the operator named to
// something worth stealing.
//
// The path finding is pure and operates on an in-memory graph, so it is fully testable
// without a database; the loader in load.go fills that graph from the entity graph.
// Recon graphs are sparse, so an in-memory multi-source shortest path is tractable far
// past the sizes that matter here.
package attackpath

import (
	"container/heap"
	"slices"
	"sort"
)

// Decisions, matching the prioritiser's scale.
const (
	Track  = "Track"
	Attend = "Attend"
	Act    = "Act"
)

// Node is one entity in the attack graph with the state that makes it an entry point or
// a target.
type Node struct {
	ID           int64
	Type         string
	Key          string
	SeedDistance int
	Criticality  int
	Exposures    []string // exposure classes recorded on the entity
}

// Edge is a reachability step. Confidence is the recon edge's confidence; an inferred
// edge (a low-confidence sibling link) costs more to traverse.
type Edge struct {
	To         int64
	Rel        string
	Confidence float64
}

// Graph is the in-memory attack graph.
type Graph struct {
	Nodes map[int64]*Node
	Adj   map[int64][]Edge
}

// NewGraph returns an empty graph.
func NewGraph() *Graph { return &Graph{Nodes: map[int64]*Node{}, Adj: map[int64][]Edge{}} }

// AddNode adds or replaces a node.
func (g *Graph) AddNode(n *Node) { g.Nodes[n.ID] = n }

// AddEdge adds a reachability step in both directions: an attacker who controls either
// endpoint can pivot to the other.
func (g *Graph) AddEdge(a, b int64, rel string, confidence float64) {
	g.Adj[a] = append(g.Adj[a], Edge{To: b, Rel: rel, Confidence: confidence})
	g.Adj[b] = append(g.Adj[b], Edge{To: a, Rel: rel, Confidence: confidence})
}

// Hop is one step of a path, with why it is reachable.
type Hop struct {
	Node int64
	Key  string
	Type string
	Rel  string // the relationship traversed to reach this node ("" for the entry)
}

// Path is one entry-to-jewel route with its attributed risk.
type Path struct {
	Hops     []Hop
	Target   int64
	Risk     int
	Decision string
	Reasons  []string
}

// isEntry reports whether a node is an attacker entry point: a seed the operator named.
func isEntry(n *Node) bool { return n.SeedDistance == 0 }

// jewelValue returns the base worth of a node as a target and a reason, or 0.
func jewelValue(n *Node) (int, string) {
	switch n.Type {
	case "credential", "leak":
		return 40, "a credential or leak is directly valuable"
	case "bucket", "repository", "cloud_resource":
		return 30, "a bucket, repository or cloud resource holds data"
	}
	if n.Criticality >= 70 {
		return min(n.Criticality/2, 50), "the operator rated this asset critical"
	}
	if p := exposureValue(n.Exposures); p >= 25 {
		return p, "a high-impact exposure makes this a target"
	}
	return 0, ""
}

// exposureValue returns the strongest exposure weight on a node.
func exposureValue(exposures []string) int {
	best := 0
	for _, e := range exposures {
		if p := exposureWeight[e]; p > best {
			best = p
		}
	}
	return best
}

// exposureWeight is the risk each exposure class contributes.
var exposureWeight = map[string]int{
	"leaked_secret": 30, "takeover": 25, "exposed_git": 20, "exposed_env": 20,
	"open_bucket": 20, "origin_exposed": 15, "zone_transfer": 15, "exposed_secret": 25,
	"access_control_bypass": 15, "dangling_cname": 12, "cors_reflect_credentials": 12,
	"graphql_introspection": 8, "breach": 8, "exposed_api_spec": 5, "email_spoofable": 5,
}

// isJewel reports whether a node is worth reaching.
func isJewel(n *Node) bool {
	v, _ := jewelValue(n)
	return v > 0
}

// Analyze returns the ranked shortest attack paths from any entry to each reachable
// jewel. Only one path per jewel (the lowest-cost) is kept, entry-to-jewel never
// all-pairs, so the result stays bounded.
func Analyze(g *Graph) []Path {
	dist, prev, rel := multiSourceDijkstra(g)

	var paths []Path
	for id, n := range g.Nodes {
		if !isJewel(n) || isEntry(n) {
			continue // a jewel that is itself a seed is not an attack path
		}
		if _, reached := dist[id]; !reached {
			continue
		}
		paths = append(paths, buildPath(g, id, prev, rel))
	}
	sort.SliceStable(paths, func(i, j int) bool {
		if paths[i].Risk != paths[j].Risk {
			return paths[i].Risk > paths[j].Risk
		}
		if len(paths[i].Hops) != len(paths[j].Hops) {
			return len(paths[i].Hops) < len(paths[j].Hops)
		}
		return paths[i].Target < paths[j].Target
	})
	return paths
}

// buildPath reconstructs and scores one path ending at target.
func buildPath(g *Graph, target int64, prev map[int64]int64, rel map[int64]string) Path {
	var ids []int64
	for at := target; ; {
		ids = append(ids, at)
		p, ok := prev[at]
		if !ok {
			break
		}
		at = p
	}
	// prev chains from target back to the entry; reverse to entry-first order.
	for i, j := 0, len(ids)-1; i < j; i, j = i+1, j-1 {
		ids[i], ids[j] = ids[j], ids[i]
	}

	p := Path{Target: target}
	for _, id := range ids {
		n := g.Nodes[id]
		p.Hops = append(p.Hops, Hop{Node: id, Key: n.Key, Type: n.Type, Rel: rel[id]})
	}
	p.Risk, p.Reasons = scorePath(g, ids)
	switch {
	case p.Risk >= 50:
		p.Decision = Act
	case p.Risk >= 25:
		p.Decision = Attend
	default:
		p.Decision = Track
	}
	return p
}

// scorePath attributes a path's risk: the jewel's value, the exposures encountered
// along the way, less a penalty for each extra hop (a longer chain is less likely).
func scorePath(g *Graph, ids []int64) (int, []string) {
	var reasons []string
	total := 0

	target := g.Nodes[ids[len(ids)-1]]
	jv, jr := jewelValue(target)
	total += jv
	reasons = append(reasons, reason(jv, "crown jewel: "+jr))

	exp := 0
	for _, id := range ids {
		if v := exposureValue(g.Nodes[id].Exposures); v > exp {
			exp = v
		}
	}
	if exp > 0 {
		total += exp
		reasons = append(reasons, reason(exp, "an exposure on the path can be a foothold"))
	}

	if hops := len(ids) - 1; hops > 1 {
		pen := (hops - 1) * 5
		total -= pen
		reasons = append(reasons, reason(-pen, "a longer chain is less likely to be exploitable end to end"))
	}

	if total > 100 {
		reasons = append(reasons, reason(100-total, "capped at 100"))
		total = 100
	}
	if total < 0 {
		reasons = append(reasons, reason(-total, "floored at 0"))
		total = 0
	}
	return total, reasons
}

func reason(points int, detail string) string {
	sign := "+"
	if points < 0 {
		sign = ""
	}
	return sign + itoa(points) + " " + detail
}

// Blast returns the blast radius of a node: every node reachable from it. If an
// attacker controls `from`, everything returned here is reachable from that foothold.
// The result is sorted and excludes the starting node.
func Blast(g *Graph, from int64) []int64 {
	seen := map[int64]bool{from: true}
	queue := []int64{from}
	var out []int64
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range g.Adj[cur] {
			if !seen[e.To] {
				seen[e.To] = true
				out = append(out, e.To)
				queue = append(queue, e.To)
			}
		}
	}
	slices.Sort(out)
	return out
}

// NodeByKey returns the id of the node with a given key, or 0 and false.
func (g *Graph) NodeByKey(key string) (int64, bool) {
	for id, n := range g.Nodes {
		if n.Key == key {
			return id, true
		}
	}
	return 0, false
}

// Choke is an intermediate node that lies on many entry-to-jewel paths; fixing it cuts
// the most routes.
type Choke struct {
	Node     int64
	Key      string
	Type     string
	PathsCut int
}

// Chokes ranks the non-endpoint nodes by how many paths they appear on.
func Chokes(paths []Path) []Choke {
	count := map[int64]int{}
	meta := map[int64]Hop{}
	for _, p := range paths {
		for i, h := range p.Hops {
			if i == 0 || i == len(p.Hops)-1 {
				continue // the entry and the jewel are not choke points
			}
			count[h.Node]++
			meta[h.Node] = h
		}
	}
	var out []Choke
	for id, c := range count {
		out = append(out, Choke{Node: id, Key: meta[id].Key, Type: meta[id].Type, PathsCut: c})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].PathsCut != out[j].PathsCut {
			return out[i].PathsCut > out[j].PathsCut
		}
		return out[i].Node < out[j].Node
	})
	return out
}

// edgeCost is the traversal cost of an edge: a low-confidence (inferred) step costs
// more, so a path through solid observations is preferred.
func edgeCost(e Edge) float64 { return 1 + (1 - e.Confidence) }

// multiSourceDijkstra computes the shortest cost from the nearest entry to every node,
// recording the predecessor and the relationship used to reach it.
func multiSourceDijkstra(g *Graph) (dist map[int64]float64, prev map[int64]int64, rel map[int64]string) {
	dist = map[int64]float64{}
	prev = map[int64]int64{}
	rel = map[int64]string{}
	pq := &pathHeap{}
	heap.Init(pq)
	for id, n := range g.Nodes {
		if isEntry(n) {
			dist[id] = 0
			heap.Push(pq, pqItem{node: id, cost: 0})
		}
	}
	for pq.Len() > 0 {
		cur := heap.Pop(pq).(pqItem)
		if cur.cost > dist[cur.node] {
			continue
		}
		for _, e := range g.Adj[cur.node] {
			nd := cur.cost + edgeCost(e)
			if old, ok := dist[e.To]; !ok || nd < old {
				dist[e.To] = nd
				prev[e.To] = cur.node
				rel[e.To] = e.Rel
				heap.Push(pq, pqItem{node: e.To, cost: nd})
			}
		}
	}
	// An entry has no predecessor and no inbound relationship.
	for id, n := range g.Nodes {
		if isEntry(n) {
			delete(prev, id)
			delete(rel, id)
		}
	}
	return dist, prev, rel
}

// pqItem and pathHeap are the Dijkstra priority queue.
type pqItem struct {
	node int64
	cost float64
}
type pathHeap []pqItem

func (h pathHeap) Len() int           { return len(h) }
func (h pathHeap) Less(i, j int) bool { return h[i].cost < h[j].cost }
func (h pathHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *pathHeap) Push(x any)        { *h = append(*h, x.(pqItem)) }
func (h *pathHeap) Pop() any {
	old := *h
	n := len(old)
	it := old[n-1]
	*h = old[:n-1]
	return it
}

// itoa avoids a strconv import for the small reason integers.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
