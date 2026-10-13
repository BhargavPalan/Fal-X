// Package correlate finds related infrastructure the collection sources cannot see
// on their own: entities that share a distinguishing fact are likely siblings.
//
// This is the pivot that makes the graph more than the sum of its sources. Two hosts
// presenting the same leaf certificate, serving the same favicon, or answering with
// the same TLS stack are almost certainly the same operator's infrastructure even when
// nothing else links them. Such links are inferred, not observed, so they are recorded
// as sibling_of edges, which the graph marks inferred.
//
// Two things make the correlation more than a set of same-value joins. First, a shared
// value is weighted by how rare it is: a certificate on two hosts is a strong signal,
// the same certificate on two hundred is noise, so the edge confidence scales inversely
// with the size of the sharing group. Second, the pivots are unioned transitively: a
// host tied to one set by its certificate and to another by its JARM is placed in one
// cluster spanning both, not two disconnected stars.
package correlate

import (
	"context"
	"database/sql"
	"math"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/store"
)

// maxGroup bounds a correlation cluster. A certificate or favicon shared by thousands
// of hosts (a shared CDN default, a hosting provider) is noise, not a useful pivot, so
// a group larger than this is skipped.
const maxGroup = 200

// pivot is one fact whose shared value implies the entities are related, with the base
// confidence (before rarity weighting) to record on the resulting edge.
type pivot struct {
	factKey    string
	confidence float64
}

// pivots are the correlation rules. A shared TLS fingerprint, favicon or JARM is a
// strong same-operator signal; a shared nameserver is weaker (many estates share a
// provider). Rarity weighting and maxGroup together suppress the common values.
var pivots = []pivot{
	{factKey: "tls_sha256", confidence: 0.6},    // the same leaf certificate
	{factKey: "favicon_mmh3", confidence: 0.5},  // the same favicon
	{factKey: "jarm", confidence: 0.5},          // the same TLS stack/configuration fingerprint
	{factKey: "analytics_id", confidence: 0.55}, // the same analytics / tag-manager id
	{factKey: "ns", confidence: 0.35},           // the same authoritative nameserver
}

// Run clusters entities that share pivot facts and records the sibling_of edges. The
// transaction is opened for the organization.
func Run(ctx context.Context, db *store.DB, orgID int64) error {
	return db.InTx(ctx, func(tx *sql.Tx) error {
		uf := newUnionFind()
		types := map[int64]graph.EntityType{}
		best := map[int64]float64{} // strongest rarity- and freshness-weighted evidence each entity carries
		now := time.Now()

		for _, p := range pivots {
			groups, err := graph.EntitiesByFact(ctx, tx, p.factKey)
			if err != nil {
				return err
			}
			for _, ents := range groups {
				if len(ents) < 2 || len(ents) > maxGroup {
					continue
				}
				base := p.confidence * rarity(len(ents))
				rep := ents[0].ID
				for _, e := range ents {
					types[e.ID] = e.Type
					// A stale shared value is weaker evidence than a freshly observed one.
					w := store.Decay(base, now.Sub(e.LastSeen))
					if w > best[e.ID] {
						best[e.ID] = w
					}
					uf.union(rep, e.ID)
				}
			}
		}

		// Emit one star of edges per connected component, each edge carrying the
		// strongest evidence its endpoint participated in.
		members := map[int64][]int64{}
		for id := range types {
			root := uf.find(id)
			members[root] = append(members[root], id)
		}
		for root, ids := range members {
			if len(ids) < 2 {
				continue
			}
			for _, id := range ids {
				if id == root {
					continue
				}
				if err := graph.AddEdge(ctx, tx, orgID, graph.Ref(root), graph.Ref(id),
					graph.RelSiblingOf, types[root], types[id], best[id]); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// rarity returns an inverse-frequency weight in (0,1]: a value shared by few entities
// is weighted near 1, one shared by close to maxGroup near 0, so a distinctive pivot
// dominates a common one.
func rarity(groupSize int) float64 {
	if groupSize <= 2 {
		return 1.0
	}
	w := math.Log(float64(maxGroup)/float64(groupSize)) / math.Log(float64(maxGroup))
	if w < 0.05 {
		return 0.05
	}
	if w > 1 {
		return 1
	}
	return w
}

// unionFind is a disjoint-set over entity ids, for transitive clustering across pivots.
type unionFind struct{ parent map[int64]int64 }

func newUnionFind() *unionFind { return &unionFind{parent: map[int64]int64{}} }

func (u *unionFind) find(x int64) int64 {
	if _, ok := u.parent[x]; !ok {
		u.parent[x] = x
		return x
	}
	for u.parent[x] != x {
		u.parent[x] = u.parent[u.parent[x]] // path halving
		x = u.parent[x]
	}
	return x
}

func (u *unionFind) union(a, b int64) {
	ra, rb := u.find(a), u.find(b)
	if ra == rb {
		return
	}
	// Keep the smaller id as the root, so the representative is stable between runs.
	if rb < ra {
		ra, rb = rb, ra
	}
	u.parent[rb] = ra
}
