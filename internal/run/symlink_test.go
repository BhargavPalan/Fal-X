package run

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSymlinkedManifestIsNotRead pins that Load refuses a run.json or stages.json
// that is a symlink pointing outside the run directory.
//
// A run directory is a bundle that can arrive from anywhere (assets import --from,
// report --run), and archive extraction preserves symlinks. The report package
// guards its artifact reads; the manifests are read here, so they need the same
// guard or a crafted bundle reads any JSON file the operator can read and shows
// fields of it in the report.
func TestSymlinkedManifestIsNotRead(t *testing.T) {
	for _, name := range []string{"run.json", "stages.json"} {
		t.Run(name, func(t *testing.T) {
			outside := t.TempDir()
			secret := filepath.Join(outside, "secret.json")
			if err := os.WriteFile(secret,
				[]byte(`{"run_id":"LEAKED-RUN-ID","target":"LEAKED-TARGET","schema_version":1,"stages":[]}`), 0o600); err != nil {
				t.Fatal(err)
			}

			dir := t.TempDir()
			files := map[string]string{
				"run.json":    `{"run_id":"r","target":"t","stamp":"s","started_at":"x"}`,
				"stages.json": `{"schema_version":1,"run_id":"r","stages":[]}`,
			}
			for n, body := range files {
				if n == name {
					if err := os.Symlink(secret, filepath.Join(dir, n)); err != nil {
						t.Skipf("symlinks are not available here: %v", err)
					}
					continue
				}
				if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			m, _, err := Load(dir)
			if err == nil {
				t.Fatalf("a manifest symlinked outside the run directory was read: %+v", m)
			}
			if !strings.Contains(err.Error(), "outside") {
				t.Errorf("the error should say the file resolves outside the run directory: %v", err)
			}
			if m != nil && (m.RunID == "LEAKED-RUN-ID" || m.Target == "LEAKED-TARGET") {
				t.Errorf("content of the outside file reached the manifest: %+v", m)
			}
		})
	}
}

func TestOrdinaryManifestStillLoads(t *testing.T) {
	r, err := Init(t.TempDir(), "example.com", "20261003-123456")
	if err != nil {
		t.Fatal(err)
	}
	r.SetTarget("example.com")
	if err := r.Finalise(); err != nil {
		t.Fatal(err)
	}
	m, _, err := Load(r.Dir)
	if err != nil || m.Target != "example.com" {
		t.Fatalf("a normal run no longer loads: %v %+v", err, m)
	}
}
