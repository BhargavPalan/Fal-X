package util

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveWithin(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "a.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// An ordinary file resolves to itself, inside the directory.
	got, err := ResolveWithin(dir, filepath.Join("sub", "a.txt"))
	if err != nil || !strings.HasSuffix(got, filepath.Join("sub", "a.txt")) {
		t.Errorf("an ordinary file: %q, %v", got, err)
	}
	// A file that is not there is "absent", not an error.
	got, err = ResolveWithin(dir, "missing.txt")
	if err != nil || !strings.HasSuffix(got, "missing.txt") {
		t.Errorf("an absent file must come back unresolved without error: %q, %v", got, err)
	}
	// A directory that does not exist is the same.
	if _, err := ResolveWithin(filepath.Join(dir, "no-such-dir"), "x"); err != nil {
		t.Errorf("an absent directory must not be an error here: %v", err)
	}
}

func TestResolveWithinRefusesLinksThatLeave(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("S"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(outside, "stage"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "stage", "f.txt"), []byte("S"), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(dir, "file.txt")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "stage"), filepath.Join(dir, "stage")); err != nil {
		t.Fatal(err)
	}

	for _, rel := range []string{"file.txt", filepath.Join("stage", "f.txt")} {
		_, err := ResolveWithin(dir, rel)
		if err == nil || !strings.Contains(err.Error(), "outside the run directory") {
			t.Errorf("%s: a link leaving the directory was accepted: %v", rel, err)
		}
	}

	// A link that stays inside is fine.
	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("r"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "real.txt"), filepath.Join(dir, "alias.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveWithin(dir, "alias.txt"); err != nil {
		t.Errorf("a link that stays inside the directory was refused: %v", err)
	}
}
