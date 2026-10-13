package util

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// nonBlankLines counts the non-empty lines in a file; an absent file is 0.
func nonBlankLines(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n := 0
	for l := range strings.SplitSeq(string(b), "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n
}

// TestClean pins in-place sort and dedupe, which several stages rely on for a
// deterministic output order.
func TestClean(t *testing.T) {
	dir := t.TempDir()

	p := write(t, filepath.Join(dir, "d.txt"), "b\na\nb\n\nc\n")
	if err := Clean(p); err != nil {
		t.Fatalf("Clean: %v", err)
	}
	if got := nonBlankLines(t, p); got != 3 {
		t.Errorf("Count after Clean = %d, want 3", got)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "a\nb\nc\n" {
		t.Errorf("Clean produced %q, want %q", b, "a\nb\nc\n")
	}

	// An absent file is a no-op, not an error. Stages call this before they
	// know whether the producer ran.
	if err := Clean(filepath.Join(dir, "absent.txt")); err != nil {
		t.Errorf("Clean(absent) = %v, want nil", err)
	}
}

// TestTruncateFileCreatesParents pins that the parent directory is created.
// Stages write into output paths that do not exist yet, so this has to make
// them rather than assume them.
func TestTruncateFileCreatesParents(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a", "b", "c.txt")

	if err := TruncateFile(p); err != nil {
		t.Fatalf("TruncateFile: %v", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Errorf("TruncateFile did not create the file: %v", err)
	}

	write(t, p, "content\n")
	if err := TruncateFile(p); err != nil {
		t.Fatalf("TruncateFile on existing: %v", err)
	}
	if got := nonBlankLines(t, p); got != 0 {
		t.Errorf("TruncateFile left %d lines, want 0", got)
	}
}

// TestReadLines pins blank-line skipping and the distinction between an absent
// file and an empty result.
func TestReadLines(t *testing.T) {
	dir := t.TempDir()

	p := write(t, filepath.Join(dir, "blanks.txt"), "a\n\n\nb\n")
	lines, ok := ReadLines(p)
	if !ok {
		t.Error("ReadLines returned not-ok for a file with content")
	}
	if len(lines) != 2 || lines[0] != "a" || lines[1] != "b" {
		t.Errorf("ReadLines = %q, want [a b]", lines)
	}

	// A file that exists but holds nothing is "ran and found nothing", which
	// is different from an absent file. Both are not-ok for the caller, but
	// only one of them means the stage never ran.
	empty := write(t, filepath.Join(dir, "empty.txt"), "")
	if _, ok := ReadLines(empty); ok {
		t.Error("ReadLines returned ok for an empty file")
	}

	if _, ok := ReadLines(filepath.Join(dir, "absent")); ok {
		t.Error("ReadLines returned ok for an absent file")
	}
}

// TestReadLinesKeepsCRLFPin keeps a stray carriage return from becoming part of
// a host name, which would fail the scope gate for every Windows-authored file.
func TestReadLinesStripsCR(t *testing.T) {
	dir := t.TempDir()
	p := write(t, filepath.Join(dir, "crlf.txt"), "a\r\nb\r\n")

	lines, _ := ReadLines(p)
	for _, l := range lines {
		if l != "a" && l != "b" {
			t.Errorf("ReadLines left %q, want it trimmed of CR", l)
		}
	}
}

// TestSHA256 pins the digest against a known value, because the scope digests
// recorded with each run are compared across runs.
func TestSHA256(t *testing.T) {
	got := SHA256String("hello\n")
	const want = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
	if got != want {
		t.Errorf("SHA256String(hello) = %s, want %s", got, want)
	}
}

// TestWriteLinesAtomic pins that a partially written output file is never
// observable. A stage killed mid-write must leave either the old content or
// nothing, never a truncated host list that a later stage would read as a
// complete result.
func TestWriteLinesAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "out.txt")

	if err := WriteLines(p, []string{"a", "b", "c"}); err != nil {
		t.Fatalf("WriteLines: %v", err)
	}
	lines, _ := ReadLines(p)
	if len(lines) != 3 {
		t.Errorf("ReadLines after WriteLines = %q, want 3 entries", lines)
	}

	// Rewriting replaces rather than appends.
	if err := WriteLines(p, []string{"z"}); err != nil {
		t.Fatalf("WriteLines rewrite: %v", err)
	}
	if got := nonBlankLines(t, p); got != 1 {
		t.Errorf("WriteLines appended instead of replacing: %d lines", got)
	}

	// An empty slice still produces the file, because a missing output and an
	// empty one mean different things to stages.json.
	empty := filepath.Join(dir, "empty.txt")
	if err := WriteLines(empty, nil); err != nil {
		t.Fatalf("WriteLines empty: %v", err)
	}
	if _, err := os.Stat(empty); err != nil {
		t.Errorf("WriteLines(nil) did not create the file: %v", err)
	}
}
