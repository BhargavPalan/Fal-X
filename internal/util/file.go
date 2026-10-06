package util

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// lineScannerInitial and lineScannerMax bound a line read from a list file.
//
// A few kilobytes is generous for a hostname or a prefix. The ceiling exists so
// a pathological line is reported rather than silently truncating the file.
const (
	lineScannerInitial = 4096
	lineScannerMax     = 4 * 1024 * 1024
)

// newLineScanner returns a scanner configured for line-oriented list files.
func newLineScanner(f *os.File) *bufio.Scanner {
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, lineScannerInitial), lineScannerMax)
	return sc
}

// Count returns the number of non-empty lines in path.
//
// An absent file is 0. So is a file holding only blank lines. Callers use this
// to tell "the stage ran and found nothing" from "the stage never ran", which
// is why an empty result must be a single zero rather than a zero with an error
// path beside it.
func Count(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	n := 0
	sc := newLineScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n
}

// FileSizeBytes returns the size of path in bytes, or 0 when it is absent.
func FileSizeBytes(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// TruncateFile creates path empty, creating parent directories as needed.
//
// Modules call this before they know the directory exists, which is why it
// exists rather than a bare truncate.
func TruncateFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("util: create parent of %s: %w", path, err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		return fmt.Errorf("util: truncate %s: %w", path, err)
	}
	return nil
}

// WriteLines replaces path with lines, each terminated by a newline.
//
// The write goes to a temporary file and is renamed into place, so a stage
// killed mid-write leaves either the previous content or nothing. A truncated
// host list that a later stage would read as a complete result is worse than a
// missing file, which is detectable.
//
// A nil or empty slice still creates the file: an empty output and a missing
// one mean different things.
func WriteLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("util: create parent of %s: %w", path, err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("util: create temp for %s: %w", path, err)
	}
	tmpName := tmp.Name()

	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}

	w := bufio.NewWriter(tmp)
	for _, l := range lines {
		if _, err := w.WriteString(l + "\n"); err != nil {
			cleanup()
			return fmt.Errorf("util: write %s: %w", path, err)
		}
	}
	if err := w.Flush(); err != nil {
		cleanup()
		return fmt.Errorf("util: flush %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("util: sync %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("util: close %s: %w", path, err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("util: chmod %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("util: rename into %s: %w", path, err)
	}
	return nil
}

// Clean sorts and dedupes path in place. An absent file is a no-op.
func Clean(path string) error {
	lines, ok := ReadLines(path)
	if !ok {
		return nil
	}

	seen := make(map[string]struct{}, len(lines))
	uniq := make([]string, 0, len(lines))
	for _, l := range lines {
		if _, dup := seen[l]; dup {
			continue
		}
		seen[l] = struct{}{}
		uniq = append(uniq, l)
	}
	sort.Strings(uniq)

	return WriteLines(path, uniq)
}

// DedupeInto concatenates the named files into out, sorted and deduped.
// Absent inputs are skipped.
func DedupeInto(out string, ins ...string) error {
	seen := make(map[string]struct{})
	uniq := make([]string, 0)

	for _, in := range ins {
		lines, ok := ReadLines(in)
		if !ok {
			continue
		}
		for _, l := range lines {
			if _, dup := seen[l]; dup {
				continue
			}
			seen[l] = struct{}{}
			uniq = append(uniq, l)
		}
	}

	sort.Strings(uniq)
	return WriteLines(out, uniq)
}

// ReadLines returns the non-blank lines of path.
//
// It reports false when the file is absent or holds nothing, which callers use
// to distinguish "found no results" from "never got this far". Blank lines are
// skipped and a trailing carriage return is trimmed, so a file written on
// Windows does not fail the scope gate on every line.
func ReadLines(path string) ([]string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()

	var out []string
	sc := newLineScanner(f)
	for sc.Scan() {
		l := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(l) == "" {
			continue
		}
		out = append(out, l)
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// SHA256String returns the hex sha256 of s.
func SHA256String(s string) (string, error) {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:]), nil
}

// SHA256File returns the hex sha256 of a file's contents.
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("util: hash %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := copyBuffered(h, f); err != nil {
		return "", fmt.Errorf("util: hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Fingerprint returns a stable digest over the contents of the named files,
// used to decide whether a cached stage result can be reused.
//
// A missing file contributes a distinct marker rather than nothing. If absent
// contributed nothing, deleting a stage input would look like an unchanged run
// and a stale result would be reused.
func Fingerprint(paths ...string) (string, error) {
	h := sha256.New()
	for _, p := range paths {
		digest, err := SHA256File(p)
		if err != nil {
			if !os.IsNotExist(err) {
				// Unreadable for a reason other than absence is worth
				// reporting, but it still cannot be hashed.
				digest = "unreadable"
			} else {
				digest = "absent"
			}
		}
		h.Write([]byte(digest))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
