package report

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A run directory is a bundle that can be handed to someone else, unpacked from
// an archive, or copied off a build server, so its contents cannot be assumed
// benign. The artifact paths are fixed, but a symlink standing where an artifact
// belongs would otherwise be read and its contents placed in a report meant for
// someone else, or imported into the inventory.
func TestSymlinkedArtifactIsNotRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink on Windows needs privileges the test runner may not have")
	}

	const canary = "SYMLINK-ESCAPE-CANARY-9931"

	// A file the attacker wants read, well outside any run directory.
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte(canary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	artifacts := map[string]string{
		fileProbe:      `{"url":"http://leaked.example.com","status_code":200,"title":"` + canary + `"}`,
		fileURLs:       canary,
		fileSubdomains: canary,
		fileFindings:   "[" + canary + "] [http] [low] http://leaked.example.com",
	}
	for rel := range artifacts {
		t.Run(rel, func(t *testing.T) {
			dir := newRun(t)
			full := filepath.Join(dir, rel)
			if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
				t.Fatal(err)
			}
			_ = os.Remove(full)
			if err := os.Symlink(outside, full); err != nil {
				t.Skipf("symlink unsupported here: %v", err)
			}

			m, err := Load(dir)
			if err != nil {
				// Refusing the artifact outright is the safe outcome.
				if !strings.Contains(err.Error(), "outside the run directory") {
					t.Fatalf("Load returned an unexpected error: %v", err)
				}
				t.Logf("Load refused the symlinked artifact: %v", err)
				return
			}
			if strings.Contains(dump(m), canary) {
				t.Fatalf("BUG: contents of %s (a symlink to %s) were read into the "+
					"report model", rel, outside)
			}
			t.Logf("Load ignored the symlinked artifact %s", rel)
		})
	}
}

// dump renders everything the model holds as one string, so a single check can
// look for the canary wherever it might have landed.
func dump(m *Model) string {
	var b strings.Builder
	b.WriteString(m.RunID + m.Target + m.Profile)
	for _, s := range m.Stages {
		b.WriteString(s.Name + s.Status + s.Note)
	}
	for _, s := range m.Subdomains.Items {
		b.WriteString(s)
	}
	for _, s := range m.Resolved.Items {
		b.WriteString(s)
	}
	for _, s := range m.Addresses.Items {
		b.WriteString(s)
	}
	for _, s := range m.OpenPorts.Items {
		b.WriteString(s)
	}
	for _, s := range m.URLs.Items {
		b.WriteString(s)
	}
	for _, s := range m.Endpoints.Items {
		b.WriteString(s)
	}
	for _, s := range m.Services.Items {
		b.WriteString(s.URL + s.Title + s.Server + s.Host)
		for _, t := range s.Tech {
			b.WriteString(t)
		}
	}
	for _, f := range m.Findings.Items {
		b.WriteString(f.Template + f.Matcher + f.Protocol + f.Severity + f.Target + f.Detail + f.Raw)
	}
	return b.String()
}

// A directory symlink standing in for a stage folder is the same attack one
// level up, and must be caught too.
func TestSymlinkedStageDirectoryIsNotRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink on Windows needs privileges the test runner may not have")
	}
	const canary = "DIR-SYMLINK-CANARY-4417"
	outside := t.TempDir()
	writeFile(t, outside, filepath.Join("6-content", "urls.txt"), canary)

	dir := newRun(t)
	full := filepath.Join(dir, "6-content")
	_ = os.RemoveAll(full)
	if err := os.Symlink(filepath.Join(outside, "6-content"), full); err != nil {
		t.Skipf("symlink unsupported here: %v", err)
	}

	m, err := Load(dir)
	if err != nil {
		t.Logf("Load refused the symlinked stage directory: %v", err)
		return
	}
	if strings.Contains(dump(m), canary) {
		t.Fatalf("BUG: a symlinked 6-content directory was read; %q reached the model", canary)
	}
	t.Log("Load ignored the symlinked stage directory")
}

// A regular artifact must still load: the fix must not break ordinary runs.
func TestOrdinaryArtifactStillLoads(t *testing.T) {
	dir := newRun(t)
	writeFile(t, dir, fileURLs, "http://example.com/a\n")
	m, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !m.URLs.Present || len(m.URLs.Items) != 1 {
		t.Fatalf("a regular urls.txt did not load: present=%v items=%d", m.URLs.Present, len(m.URLs.Items))
	}
}
