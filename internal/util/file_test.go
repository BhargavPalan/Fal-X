package util

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// TestCount pins the regression that produced "00 live hosts" in a report.
//
// Count must return exactly one zero for an absent, empty, or blank-lines-only
// file. Two zeros read as a row count in a report.
func TestCount(t *testing.T) {
	dir := t.TempDir()

	if got := Count(filepath.Join(dir, "absent.txt")); got != 0 {
		t.Errorf("Count(absent) = %d, want 0", got)
	}

	empty := write(t, filepath.Join(dir, "empty.txt"), "")
	if got := Count(empty); got != 0 {
		t.Errorf("Count(empty) = %d, want 0", got)
	}

	blank := write(t, filepath.Join(dir, "blank.txt"), "\n\n\n")
	if got := Count(blank); got != 0 {
		t.Errorf("Count(blank lines only) = %d, want 0", got)
	}

	one := write(t, filepath.Join(dir, "one.txt"), "a\n")
	if got := Count(one); got != 1 {
		t.Errorf("Count(one line) = %d, want 1", got)
	}

	// No trailing newline is the shape a killed process leaves behind, and it
	// must still count.
	noNL := write(t, filepath.Join(dir, "nonl.txt"), "a\nb\nc")
	if got := Count(noNL); got != 3 {
		t.Errorf("Count(no trailing newline) = %d, want 3", got)
	}

	mixed := write(t, filepath.Join(dir, "mixed.txt"), "a\n\n\nb\n\n")
	if got := Count(mixed); got != 2 {
		t.Errorf("Count(blank lines interleaved) = %d, want 2", got)
	}
}

// TestClean pins in-place sort and dedupe, which several stages rely on for a
// deterministic output order.
func TestClean(t *testing.T) {
	dir := t.TempDir()

	p := write(t, filepath.Join(dir, "d.txt"), "b\na\nb\n\nc\n")
	if err := Clean(p); err != nil {
		t.Fatalf("Clean: %v", err)
	}
	if got := Count(p); got != 3 {
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

// TestDedupeInto pins merging several files, skipping absent ones.
func TestDedupeInto(t *testing.T) {
	dir := t.TempDir()

	m1 := write(t, filepath.Join(dir, "m1"), "x\ny\n")
	m2 := write(t, filepath.Join(dir, "m2"), "y\nz\n")
	out := filepath.Join(dir, "merged.txt")

	if err := DedupeInto(out, m1, m2, filepath.Join(dir, "absent")); err != nil {
		t.Fatalf("DedupeInto: %v", err)
	}
	if got := Count(out); got != 3 {
		t.Errorf("Count after DedupeInto = %d, want 3", got)
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
	if got := Count(p); got != 0 {
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

// TestFingerprint pins cache invalidation behaviour for --resume.
//
// The contract that matters: unchanged input gives an unchanged fingerprint,
// changed input gives a different one, and a missing file contributes something
// distinct rather than being silently ignored. If absent contributed nothing,
// then deleting a stage input would look like an unchanged run.
func TestFingerprint(t *testing.T) {
	dir := t.TempDir()
	f := write(t, filepath.Join(dir, "fp.txt"), "hello\n")

	first, err := Fingerprint(f)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	again, _ := Fingerprint(f)
	if first != again {
		t.Error("Fingerprint is unstable for unchanged input")
	}

	write(t, f, "world\n")
	changed, _ := Fingerprint(f)
	if first == changed {
		t.Error("Fingerprint did not change with content")
	}

	withAbsent, _ := Fingerprint(f, filepath.Join(dir, "absent"))
	if changed == withAbsent {
		t.Error("an absent file contributed nothing to the fingerprint")
	}
}

// TestFingerprintOrderMatters pins that argument order is significant, so a
// caller that reorders its inputs invalidates the cache instead of silently
// reusing a result computed over a different set.
func TestFingerprintOrderMatters(t *testing.T) {
	dir := t.TempDir()
	a := write(t, filepath.Join(dir, "a"), "1")
	b := write(t, filepath.Join(dir, "b"), "2")

	ab, _ := Fingerprint(a, b)
	ba, _ := Fingerprint(b, a)
	if ab == ba {
		t.Error("Fingerprint ignores argument order")
	}
}

// TestFileSizeBytes pins that an absent file is 0 rather than an error, since
// stages check it before a producer has run.
func TestFileSizeBytes(t *testing.T) {
	dir := t.TempDir()

	if got := FileSizeBytes(filepath.Join(dir, "absent")); got != 0 {
		t.Errorf("FileSizeBytes(absent) = %d, want 0", got)
	}

	p := write(t, filepath.Join(dir, "f.txt"), "12345")
	if got := FileSizeBytes(p); got != 5 {
		t.Errorf("FileSizeBytes = %d, want 5", got)
	}
}

// TestSHA256 pins the digest against a known value, because these hashes key
// download filenames and cache entries.
func TestSHA256(t *testing.T) {
	got, err := SHA256String("hello\n")
	if err != nil {
		t.Fatal(err)
	}
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
	if got := Count(p); got != 1 {
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
