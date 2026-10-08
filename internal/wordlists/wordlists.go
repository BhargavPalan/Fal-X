// Package wordlists fetches the open-source wordlists Fal-X's brute-force stages
// read, so a fresh clone can populate wordlists/ with one command.
//
// The files are data with their upstream licences and are gitignored, so this
// package is the only thing that puts them on disk. It never overwrites a file
// the operator already has unless asked to, and it replaces a file only after the
// whole download has succeeded.
package wordlists

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Source is one fetchable wordlist.
type Source struct {
	// Name is the short name used on the command line.
	Name string
	// File is the file name written under the wordlists directory. It matches the
	// compiled-in defaults in internal/config.
	File string
	// URL is the upstream raw file. It must be https.
	URL     string
	Licence string
	// Use says which stage reads it.
	Use string
}

// Sources are the lists Fal-X can fetch. resolvers.txt is deliberately absent: it
// is a curated list kept in the repository's own documentation.
var Sources = []Source{
	{
		Name:    "subdomains",
		File:    "subdomains.txt",
		URL:     "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
		Licence: "MIT (SecLists)",
		Use:     "subs --brute",
	},
	{
		Name:    "content",
		File:    "content.txt",
		URL:     "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
		Licence: "MIT (SecLists)",
		Use:     "content --dirs",
	},
}

// maxBytes caps one download. The largest list Fal-X uses is well under 1 MiB;
// the cap only stops a wrong URL from filling a disk.
const maxBytes = 32 << 20

// Options controls Fetch.
type Options struct {
	// Dir is the wordlists directory.
	Dir string
	// Only limits the fetch to these source names. Empty means all.
	Only []string
	// Force replaces files that already exist.
	Force bool
	// Client is the HTTP client. Nil uses one with a sane timeout.
	Client *http.Client
	// Out receives progress lines.
	Out io.Writer
}

// Lookup returns the named sources, or an error naming the first unknown one.
func Lookup(names []string) ([]Source, error) {
	if len(names) == 0 {
		return Sources, nil
	}
	var out []Source
	for _, n := range names {
		found := false
		for _, s := range Sources {
			if s.Name == n || s.File == n {
				out = append(out, s)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown wordlist %q (known: %s)", n, knownNames())
		}
	}
	return out, nil
}

func knownNames() string {
	var names []string
	for _, s := range Sources {
		names = append(names, s.Name)
	}
	return strings.Join(names, ", ")
}

// List prints each source and whether it is present locally.
func List(w io.Writer, dir string) {
	fmt.Fprintf(w, "%-12s %-14s %-9s %-16s %s\n", "NAME", "FILE", "STATUS", "USED BY", "LICENCE")
	for _, s := range Sources {
		status := "missing"
		if n, err := countLines(filepath.Join(dir, s.File)); err == nil {
			status = fmt.Sprintf("%d", n)
		}
		fmt.Fprintf(w, "%-12s %-14s %-9s %-16s %s\n", s.Name, s.File, status, s.Use, s.Licence)
	}
}

// Fetch downloads the selected sources into opts.Dir.
//
// A failure on one source does not stop the others; the returned error joins
// whatever failed.
func Fetch(ctx context.Context, opts Options) error {
	srcs, err := Lookup(opts.Only)
	if err != nil {
		return err
	}
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	if err := os.MkdirAll(opts.Dir, 0o755); err != nil { //nolint:gosec // a data directory needs its execute bit
		return fmt.Errorf("could not create %s: %w", opts.Dir, err)
	}

	var errs []error
	for _, s := range srcs {
		dest := filepath.Join(opts.Dir, s.File)
		if _, statErr := os.Stat(dest); statErr == nil && !opts.Force {
			fmt.Fprintf(opts.Out, "[+] %s already exists, left alone (use --force to replace)\n", dest)
			continue
		}
		fmt.Fprintf(opts.Out, "[*] fetching %s from %s\n", s.File, s.URL)
		n, sum, err := fetchOne(ctx, client, s, dest)
		if err != nil {
			fmt.Fprintf(opts.Out, "[!] %s: %v\n", s.File, err)
			errs = append(errs, fmt.Errorf("%s: %w", s.File, err))
			continue
		}
		fmt.Fprintf(opts.Out, "[+] wrote %s: %d entries, sha256 %s\n", dest, n, sum[:16])
	}
	return errors.Join(errs...)
}

func fetchOne(ctx context.Context, client *http.Client, s Source, dest string) (int, string, error) {
	if !strings.HasPrefix(s.URL, "https://") {
		return 0, "", fmt.Errorf("refusing non-https source %q", s.URL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return 0, "", err
	}
	if len(body) > maxBytes {
		return 0, "", fmt.Errorf("download exceeds %d bytes", maxBytes)
	}

	clean, n := normalise(body)
	if n == 0 {
		return 0, "", errors.New("download held no entries")
	}

	// Write beside the destination and rename, so an interrupted run leaves the
	// previous file intact rather than a truncated list.
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".fetch-*")
	if err != nil {
		return 0, "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(clean); err != nil {
		tmp.Close()
		return 0, "", err
	}
	if err := tmp.Close(); err != nil {
		return 0, "", err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil { //nolint:gosec // a public wordlist
		return 0, "", err
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return 0, "", err
	}
	sum := sha256.Sum256(clean)
	return n, hex.EncodeToString(sum[:]), nil
}

// normalise converts line endings to LF and drops blank lines, comment lines and
// duplicates, keeping the upstream order. It returns the cleaned bytes and the
// entry count.
func normalise(b []byte) ([]byte, int) {
	var out bytes.Buffer
	seen := make(map[string]struct{})
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, dup := seen[line]; dup {
			continue
		}
		seen[line] = struct{}{}
		out.WriteString(line)
		out.WriteByte('\n')
		n++
	}
	return out.Bytes(), n
}

func countLines(path string) (int, error) {
	f, err := os.Open(path) //nolint:gosec // a fixed path under the wordlists directory
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		n++
	}
	return n, sc.Err()
}
