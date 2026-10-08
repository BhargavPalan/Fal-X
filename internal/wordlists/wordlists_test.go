package wordlists

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// serve points Sources at an https test server answering with h, and returns a
// client that trusts it.
func serve(t *testing.T, h http.HandlerFunc) (*http.Client, func()) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	old := Sources
	Sources = []Source{{Name: "x", File: "x.txt", URL: srv.URL + "/x", Licence: "test", Use: "test"}}
	return srv.Client(), func() { Sources = old; srv.Close() }
}

func TestNormalise(t *testing.T) {
	out, n := normalise([]byte("# c\r\nwww\r\n\r\nwww\r\napi\n"))
	if string(out) != "www\napi\n" || n != 2 {
		t.Fatalf("got %q, %d", out, n)
	}
}

func TestFetchWritesAndLeavesExistingAlone(t *testing.T) {
	client, done := serve(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("a\nb\n")) })
	defer done()
	dir := t.TempDir()
	dest := filepath.Join(dir, "x.txt")

	if err := Fetch(context.Background(), Options{Dir: dir, Client: client}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "a\nb\n" {
		t.Fatalf("got %q", b)
	}

	// An operator's own edits survive a plain fetch.
	_ = os.WriteFile(dest, []byte("mine\n"), 0o644)
	if err := Fetch(context.Background(), Options{Dir: dir, Client: client}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "mine\n" {
		t.Fatalf("existing file was overwritten: %q", b)
	}
	if err := Fetch(context.Background(), Options{Dir: dir, Client: client, Force: true}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "a\nb\n" {
		t.Fatalf("--force did not replace: %q", b)
	}
}

func TestFetchFailureKeepsPreviousFile(t *testing.T) {
	client, done := serve(t, func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "gone", http.StatusNotFound) })
	defer done()
	dir := t.TempDir()
	dest := filepath.Join(dir, "x.txt")
	_ = os.WriteFile(dest, []byte("keep\n"), 0o644)

	if err := Fetch(context.Background(), Options{Dir: dir, Client: client, Force: true}); err == nil {
		t.Fatal("a 404 did not fail the fetch")
	}
	if b, _ := os.ReadFile(dest); string(b) != "keep\n" {
		t.Fatalf("failed fetch damaged the file: %q", b)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, ".fetch-*")); len(m) != 0 {
		t.Fatalf("temp file left behind: %v", m)
	}
}

func TestLookupRejectsUnknown(t *testing.T) {
	if _, err := Lookup([]string{"nope"}); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("got %v", err)
	}
}
