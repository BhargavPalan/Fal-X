package engine

import "github.com/BhargavPalan/Fal-X/internal/graph"

// Buffer collects a source's emissions during one Collect. It implements
// sources.Sink. Nothing is written to the database until the engine commits the
// buffer, so a source that fails part-way leaves no partial state.
//
// Entity handles are local indices into the buffer, not database ids; the
// committer resolves them to real ids when it writes. The same (type, key) returns
// the same handle, so a source can emit an entity once and then reference it.
type Buffer struct {
	entities []bufEntity
	index    map[string]graph.Ref
	facts    []bufFact
	edges    []bufEdge
}

type bufEntity struct {
	t       graph.EntityType
	key     string
	display string
}

type bufFact struct {
	on         graph.Ref
	key, value string
	confidence float64
}

type bufEdge struct {
	from, to   graph.Ref
	rel        graph.EdgeType
	confidence float64
}

// NewBuffer returns an empty buffer.
func NewBuffer() *Buffer { return &Buffer{index: map[string]graph.Ref{}} }

// Entity records an entity and returns its handle, deduplicating within the buffer
// by (type, key) so repeated emissions collapse to one.
func (b *Buffer) Entity(t graph.EntityType, key, display string) graph.Ref {
	ck, _ := graph.Canonicalize(t, key)
	idx := string(t) + "\x00" + ck
	if ref, ok := b.index[idx]; ok {
		return ref
	}
	b.entities = append(b.entities, bufEntity{t: t, key: ck, display: display})
	ref := graph.Ref(len(b.entities)) // 1-based; 0 is never a valid handle
	b.index[idx] = ref
	return ref
}

// Fact records a fact about an entity handle.
func (b *Buffer) Fact(on graph.Ref, key, value string, confidence float64) {
	b.facts = append(b.facts, bufFact{on: on, key: key, value: value, confidence: confidence})
}

// Edge records a relationship between two entity handles.
func (b *Buffer) Edge(from, to graph.Ref, rel graph.EdgeType, confidence float64) {
	b.edges = append(b.edges, bufEdge{from: from, to: to, rel: rel, confidence: confidence})
}

// entityAt returns the buffered entity behind a handle, and whether the handle is
// valid.
func (b *Buffer) entityAt(ref graph.Ref) (bufEntity, bool) {
	i := int(ref) - 1
	if i < 0 || i >= len(b.entities) {
		return bufEntity{}, false
	}
	return b.entities[i], true
}
