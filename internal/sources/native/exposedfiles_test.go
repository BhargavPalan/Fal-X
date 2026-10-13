package native

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestExposedFilesDetectsGitWithSignature(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.git/config":
			_, _ = w.Write([]byte("[core]\n\trepositoryformatversion = 0\n"))
		case "/", "/falx-nonexistent-9f3a2b1c":
			if r.URL.Path == "/falx-nonexistent-9f3a2b1c" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte("home"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	p := &ExposedFiles{Client: srv.Client()}
	s := &recSink{}
	if err := p.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: host}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasFact("finding", "high exposed-git-repository") {
		t.Errorf("expected an exposed-git finding, facts=%+v", s.facts)
	}
	if !s.hasFact("exposure", "exposed_git") {
		t.Errorf("expected the exposure class, facts=%+v", s.facts)
	}
}

func TestExposedFilesSoftFourOhFourIsSkipped(t *testing.T) {
	// A host that answers 200 to everything, including the random path, must produce no
	// findings, because every signature check would be unreliable.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("[core] this looks like a git config but is a soft 404"))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	p := &ExposedFiles{Client: srv.Client()}
	s := &recSink{}
	if err := p.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: host}, s); err != nil {
		t.Fatal(err)
	}
	for _, f := range s.facts {
		if f.key == "finding" {
			t.Errorf("a soft-404 host must produce no findings, got %+v", f)
		}
	}
}
