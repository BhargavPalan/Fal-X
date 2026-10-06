// Package installer installs the external reconnaissance tools Fal-X drives.
//
// It is the single source of truth for which tools are needed and at which
// versions. The `fal-x install` command is the only caller; there is no separate
// shell or PowerShell script to drift out of step with this table.
//
// Tools are installed with `go install <pkg>@<version>`. The Go toolchain builds
// each one for the host operating system and architecture automatically, so the
// same command produces the right binary on linux/amd64, darwin/arm64,
// windows/amd64, a Raspberry Pi's linux/arm, and everything in between. There is
// no per-architecture download to get wrong.
package installer

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Tool is one external binary Fal-X can drive.
type Tool struct {
	Name     string // the binary name, as it appears on PATH
	Pkg      string // the Go package path
	Optional bool   // installed only with --with-opt
}

// Tools is the set Fal-X drives. Core tools back the default pipeline; optional
// tools back the opt-in stages (--deep reverse-whois, brute-force resolution).
//
// Each is installed at @latest rather than a fixed tag. A fixed old tag fails to
// build on a newer Go toolchain -- some carry a go.mod `replace` directive, which
// `go install` refuses outright, and others pin dependencies that stopped
// compiling on current Go. @latest is what the maintainers keep building, and
// the exact version that lands is recorded in tools.lock.
var Tools = []Tool{
	{Name: "dnsx", Pkg: "github.com/projectdiscovery/dnsx/cmd/dnsx"},
	{Name: "httpx", Pkg: "github.com/projectdiscovery/httpx/cmd/httpx"},
	{Name: "naabu", Pkg: "github.com/projectdiscovery/naabu/v2/cmd/naabu"},
	{Name: "nuclei", Pkg: "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"},
	{Name: "subfinder", Pkg: "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"},
	{Name: "katana", Pkg: "github.com/projectdiscovery/katana/cmd/katana"},
	{Name: "gau", Pkg: "github.com/lc/gau/v2/cmd/gau"},
	{Name: "ffuf", Pkg: "github.com/ffuf/ffuf/v2"},
	{Name: "amass", Pkg: "github.com/owasp-amass/amass/v4/...", Optional: true},
	{Name: "puredns", Pkg: "github.com/d3mondev/puredns/v2", Optional: true},
}

// Options controls one install run.
type Options struct {
	WithOpt bool      // also install the optional-stage tools
	Out     io.Writer // progress goes here; defaults to os.Stdout
}

func (o Options) out() io.Writer {
	if o.Out != nil {
		return o.Out
	}
	return os.Stdout
}

// selected returns the tools for the chosen mode.
func selected(withOpt bool) []Tool {
	out := make([]Tool, 0, len(Tools))
	for _, t := range Tools {
		if t.Optional && !withOpt {
			continue
		}
		out = append(out, t)
	}
	return out
}

// available reports whether a binary is on PATH.
func available(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Check reports which tools are present and which are missing, and returns the
// number missing. It installs nothing.
func Check(w io.Writer, withOpt bool) int {
	fmt.Fprintf(w, "platform: %s/%s\n\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(w, "%-12s %s\n", "TOOL", "STATUS")
	fmt.Fprintf(w, "%-12s %s\n", "------------", "------")
	missing := 0
	for _, t := range selected(withOpt) {
		status := "missing"
		if available(t.Name) {
			status = "installed"
		} else {
			missing++
		}
		if t.Optional {
			status += " (optional)"
		}
		fmt.Fprintf(w, "%-12s %s\n", t.Name, status)
	}
	fmt.Fprintf(w, "\n%d of %d missing\n", missing, len(selected(withOpt)))
	return missing
}

// Install installs every selected tool that is not already present.
//
// It returns an error listing the tools that failed, after attempting all of
// them, so one broken package does not hide which others would have worked.
func Install(ctx context.Context, opts Options) error {
	w := opts.out()

	goBin, err := goToolchain(ctx, w)
	if err != nil {
		return err
	}

	var failed []string
	for _, t := range selected(opts.WithOpt) {
		if available(t.Name) {
			fmt.Fprintf(w, "[+] %s already installed\n", t.Name)
			continue
		}
		fmt.Fprintf(w, "[*] installing %s (latest)\n", t.Name)
		if err := goInstall(ctx, goBin, t); err != nil {
			fmt.Fprintf(w, "[x] %s: %v\n", t.Name, err)
			failed = append(failed, t.Name)
			continue
		}
		fmt.Fprintf(w, "[+] %s installed\n", t.Name)
	}

	writeLock(ctx, w, opts.WithOpt)
	platformNotes(w, opts.WithOpt)

	if len(failed) > 0 {
		return fmt.Errorf("failed to install: %s", strings.Join(failed, ", "))
	}
	fmt.Fprintf(w, "\n[+] install complete; verify with: fal-x install --check\n")
	fmt.Fprintf(w, "[*] ensure the Go bin directory is on PATH: %s\n", goBin)
	return nil
}

// goToolchain locates the Go toolchain and the directory it installs into,
// returning a clear, OS-specific error when Go is absent.
func goToolchain(ctx context.Context, w io.Writer) (goBin string, err error) {
	if !available("go") {
		return "", fmt.Errorf("go is required to install the tools but is not on PATH.\n"+
			"Install it from https://go.dev/dl and re-run `fal-x install` (detected %s/%s)",
			runtime.GOOS, runtime.GOARCH)
	}
	ver, _ := exec.CommandContext(ctx, "go", "version").Output()
	fmt.Fprintf(w, "[*] using %s\n", strings.TrimSpace(string(ver)))

	gopath, err := exec.CommandContext(ctx, "go", "env", "GOPATH").Output()
	if err != nil {
		return "", fmt.Errorf("could not read GOPATH: %w", err)
	}
	goBin = filepath.Join(strings.TrimSpace(string(gopath)), "bin")
	if err := os.MkdirAll(goBin, 0o755); err != nil { //nolint:gosec // a bin directory needs its execute bit
		return "", fmt.Errorf("could not create %s: %w", goBin, err)
	}
	return goBin, nil
}

// goInstall runs `go install pkg@latest` into goBin.
func goInstall(ctx context.Context, goBin string, t Tool) error {
	cmd := exec.CommandContext(ctx, "go", "install", t.Pkg+"@latest")
	cmd.Env = append(os.Environ(), "GOBIN="+goBin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return err
		}
		return fmt.Errorf("%s", lastLine(msg))
	}
	return nil
}

// writeLock records what is installed, so a later run can prove what it ran
// against. It is best-effort: a lock that cannot be written does not fail an
// otherwise successful install.
func writeLock(ctx context.Context, w io.Writer, withOpt bool) {
	path := filepath.Join(".", "tools.lock")
	f, err := os.Create(path) //nolint:gosec // a fixed, non-user path in the working directory
	if err != nil {
		fmt.Fprintf(w, "[!] could not write %s: %v\n", path, err)
		return
	}
	defer f.Close()

	bw := bufio.NewWriter(f)
	fmt.Fprintf(bw, "# tools.lock -- generated by `fal-x install`. Do not edit by hand.\n")
	fmt.Fprintf(bw, "# generated_at: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(bw, "# host:         %s/%s\n#\n", runtime.GOOS, runtime.GOARCH)
	for _, t := range selected(withOpt) {
		if p, err := exec.LookPath(t.Name); err == nil {
			fmt.Fprintf(bw, "%s\t%s\t%s\n", t.Name, moduleVersion(ctx, p), p)
		}
	}
	if err := bw.Flush(); err != nil {
		fmt.Fprintf(w, "[!] could not write %s: %v\n", path, err)
		return
	}
	fmt.Fprintf(w, "[+] wrote %s\n", path)
}

// platformNotes prints guidance that depends on the host, so a user is not left
// wondering why a tool behaves differently than on another OS.
func platformNotes(w io.Writer, withOpt bool) {
	if runtime.GOOS == "windows" {
		fmt.Fprintf(w, "[!] naabu's fast SYN scan needs Npcap on Windows (https://npcap.com);\n"+
			"    without it naabu falls back to a slower CONNECT scan.\n")
	}
	// nmap is not a Go program, so it is never installed here.
	if withOpt && !available("nmap") {
		fmt.Fprintf(w, "[!] nmap is optional and installed separately: "+
			"https://nmap.org/download (used only with --nmap)\n")
	}
}

// lastLine returns the final non-empty line of s, which for a `go install`
// failure is the actionable error rather than the download chatter above it.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}

// scopeStarter is the starter config/scope.txt written by Setup. It is a minimal
// header rather than a copy of config/scope.txt.example: the example is full of
// placeholder entries that would deny every real target while looking
// configured, so an empty, commented file is the honest starting point. The full
// syntax reference stays in config/scope.txt.example.
const scopeStarter = `# Fal-X scope allowlist. One authorised target per line.
#
# This file is optional. With no --scope flag every target you name is
# reachable, which is what most single-target runs want. Fill this in to hold a
# run to a boundary instead.
#
#   example.com           the domain and every subdomain
#   *.wild.test           subdomains only
#   192.0.2.0/24          an address range
#   example.com:8443      one port on one host
#
# Blank lines and lines starting with # are ignored.
# See config/scope.txt.example for the full syntax.
`

// Setup creates the local config files in ./config without installing anything.
//
// It never overwrites: an existing config/scope.txt holds an authorization
// decision somebody made. scope.txt is generated from the starter above;
// out-of-scope.txt and .env are copied from their .example siblings when those
// are present (they are in a source checkout and in the release archive).
func Setup(w io.Writer) error {
	dir := filepath.Join(".", "config")
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // a config directory needs its execute bit
		return fmt.Errorf("could not create %s: %w", dir, err)
	}

	created := 0
	// scope.txt from the inline starter.
	n, err := writeIfAbsent(w, filepath.Join(dir, "scope.txt"), []byte(scopeStarter))
	if err != nil {
		return err
	}
	created += n
	// out-of-scope.txt and .env from their examples, when present.
	for _, name := range []string{"out-of-scope.txt", ".env"} {
		src := filepath.Join(dir, name+".example")
		b, err := os.ReadFile(src) //nolint:gosec // a fixed path under ./config
		if err != nil {
			continue // no example shipped alongside; skip quietly
		}
		n, err := writeIfAbsent(w, filepath.Join(dir, name), b)
		if err != nil {
			return err
		}
		created += n
	}

	if created > 0 {
		fmt.Fprintf(w, "\n[*] a bare target scans directly: fal-x scan scanme.nmap.org\n")
		fmt.Fprintf(w, "[*] to hold a run to an allowlist, fill config/scope.txt and pass --scope\n")
	}
	return nil
}

// writeIfAbsent writes data to path only when path does not exist, reporting
// what it did. It returns 1 when it created the file, 0 otherwise.
func writeIfAbsent(w io.Writer, path string, data []byte) (int, error) {
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(w, "[+] %s already exists, left alone\n", path)
		return 0, nil
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return 0, fmt.Errorf("could not create %s: %w", path, err)
	}
	fmt.Fprintf(w, "[+] created %s\n", path)
	return 1, nil
}

// moduleVersion returns the module version stamped into an installed binary, via
// `go version -m`. It falls back to "unknown" for a tool not built by the Go
// toolchain or when the probe fails, so tools.lock always has a row.
func moduleVersion(ctx context.Context, binPath string) string {
	out, err := exec.CommandContext(ctx, "go", "version", "-m", binPath).Output()
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		// The main module line reads: "\tmod\t<path>\t<version>\t<sum>".
		if len(f) >= 3 && f[0] == "mod" {
			return f[2]
		}
	}
	return "unknown"
}
