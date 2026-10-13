package recon

import (
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// has reports whether a named source is in a list.
func has(list []sources.Source, name string) bool {
	for _, s := range list {
		if s.Capability().Name == name {
			return true
		}
	}
	return false
}

// TestDefaultRegistryWiresNewSources pins that the new discovery sources are registered
// and indexed under the entity type they consume, so the engine actually runs them.
func TestDefaultRegistryWiresNewSources(t *testing.T) {
	reg := DefaultRegistry()

	if !has(reg.All(), "native/vhost") {
		t.Error("DefaultRegistry is missing native/vhost")
	}
	if !has(reg.All(), "native/jsanalysis") {
		t.Error("DefaultRegistry is missing native/jsanalysis")
	}
	if !has(reg.For(graph.TypeHost), "native/vhost") {
		t.Error("native/vhost is not indexed under host")
	}
	if !has(reg.For(graph.TypeURL), "native/jsanalysis") {
		t.Error("native/jsanalysis is not indexed under url")
	}
}
