// Command fal-x is the Fal-X command line: scan a target, keep what it finds, enrich
// it with exploitation intelligence, and rank it. The exit-status contract is in
// internal/logging.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"syscall"

	"github.com/BhargavPalan/Fal-X/internal/config"
	"github.com/BhargavPalan/Fal-X/internal/logging"
)

// command is one subcommand.
type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string) error
}

var commands = []command{
	{"scan", "self-driving attack-surface recon into the entity graph", runScan},
	{"intel", "vulnerability intelligence: sync, enrich, status, show, search", runIntel},
	{"assets", "inventory in Postgres: import, list, show, criticality", runAssets},
	{"match", "match the inventory against the vulnerability data", runMatch},
	{"prioritize", "rank stored findings by urgency, showing why", runPrioritize},
	{"diff", "show what changed since a point in time: new, gone, and changed assets", runDiff},
	{"monitor", "re-scan on a schedule and alert on what changed since the previous run", runMonitor},
	{"paths", "rank attack paths from a seed to a crown jewel, and the choke points", runPaths},
	{"verify", "re-check reported exposures against the live target, read-only", runVerify},
	{"exploit", "run a gated exploit module (not built yet)", runExploit},
	{"session", "session tracking and evidence collection (not built yet)", runSession},
	{"report", "render findings as markdown, JSON, or SARIF", runReport},
	{"serve", "run the HTTP API (not built yet)", runServe},
	{"migrate", "apply, roll back, or inspect database migrations", runMigrate},
	{"version", "print version information", runVersion},
}

// exitCode maps the result of a subcommand onto the exit status. A help request is
// a success; everything else is classified by logging.ExitFor.
func exitCode(err error) int {
	switch {
	case err == nil:
		return logging.StatusOK
	case errors.Is(err, errHelp):
		return logging.StatusOK
	case errors.Is(err, context.Canceled):
		return logging.StatusInterrupted
	default:
		return logging.ExitFor(err)
	}
}

func main() {
	os.Exit(realMain())
}

// realMain runs the command and returns the exit status. It is apart from main so
// its deferred cleanup runs before os.Exit.
func realMain() int {
	// A signal cancels the context, so a stage stops at its next checkpoint instead
	// of being killed mid-write.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := dispatch(ctx, os.Args[1:])
	switch {
	case err == nil, errors.Is(err, errHelp):
	case errors.Is(err, context.Canceled):
		logging.Error("interrupted")
	default:
		logging.Error("%v", err)
	}
	return exitCode(err)
}

// globals are the flags accepted before the subcommand name.
type globals struct {
	debug   bool
	quiet   bool
	json    bool
	noColor bool
}

func dispatch(ctx context.Context, args []string) error {
	g := &globals{}
	rest := args

	// Leading global flags, up to the first non-flag argument.
	for len(rest) > 0 {
		switch rest[0] {
		case "-h", "--help", "help":
			usage(os.Stdout)
			return nil
		case "-v", "--version":
			rest = []string{"version"}
		case "--debug":
			g.debug = true
			rest = rest[1:]
		case "--quiet":
			g.quiet = true
			rest = rest[1:]
		case "--json":
			g.json = true
			rest = rest[1:]
		case "--no-color":
			g.noColor = true
			rest = rest[1:]
		default:
			goto dispatchDone
		}
	}
dispatchDone:

	applyLogging(g)

	if len(rest) == 0 {
		usage(os.Stdout)
		return nil
	}

	name, cmdArgs := rest[0], rest[1:]
	for _, c := range commands {
		if c.name == name {
			return c.run(ctx, cmdArgs)
		}
	}

	logging.Error("unknown subcommand: %s", name)
	usage(os.Stderr)
	return logging.Usagef("unknown subcommand: %s", name)
}

func applyLogging(g *globals) {
	switch {
	case g.quiet:
		logging.SetLevel(logging.LevelError)
	case g.debug:
		logging.SetLevel(logging.LevelDebug)
	}
	if g.json {
		logging.SetJSON(true)
		logging.SetTimestamps(false)
	}
	if g.noColor {
		logging.SetColor(false)
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, "fal-x %s\n\n", config.Version)
	fmt.Fprintf(w, "Usage:\n  fal-x [global flags] <command> [flags]\n\nCommands:\n")

	cmds := make([]command, len(commands))
	copy(cmds, commands)
	sort.Slice(cmds, func(i, j int) bool { return cmds[i].name < cmds[j].name })

	width := 0
	for _, c := range cmds {
		width = max(width, len(c.name))
	}
	for _, c := range cmds {
		fmt.Fprintf(w, "  %-*s  %s\n", width, c.name, c.summary)
	}

	fmt.Fprintf(w, `
Exit status:
  0  success
  1  runtime failure
  2  usage or validation error

Global flags:
  --debug      verbose internal logging
  --quiet      errors only
  --json       machine-readable logging
  --no-color   disable ANSI colour
  --help       this help

Run "fal-x <command> --help" for the flags of a command.
`)
}

// errHelp means a subcommand printed its own usage. It is not nil, so "printed the
// help" and "ran and succeeded" stay different outcomes to the caller.
var errHelp = errors.New("help requested")

// flagSet returns a flag set that reports usage errors through the status
// contract rather than the flag package's own exit.
func flagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Bool("h", false, "print this help")
	fs.Bool("help", false, "print this help")
	return fs
}

// wantsHelpArgs reports whether help was requested anywhere in args. It scans rather
// than parsing, because a probe flag set would have to declare every flag the
// subcommand accepts just to survive the parse.
func wantsHelpArgs(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" {
			return true
		}
	}
	return false
}

// printUsage renders a usage line followed by a flag table.
func printUsage(synopsis string, fs *flag.FlagSet) {
	fmt.Printf("Usage: %s\n\nFlags:\n", synopsis)
	if fs != nil {
		fs.SetOutput(os.Stdout)
		fs.PrintDefaults()
	}
}

// parseFlags parses args; a parse failure is a usage error. synopsis is the caller's
// usage line, since only the caller knows which positional arguments matter.
func parseFlags(fs *flag.FlagSet, synopsis string, args []string) error {
	if wantsHelpArgs(args) {
		printUsage(synopsis, fs)
		return errHelp
	}
	if err := fs.Parse(flagsFirst(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUsage(synopsis, fs)
			return errHelp
		}
		return logging.Usagef("%v", err)
	}
	return nil
}

// flagsFirst moves every flag in args ahead of the positional arguments, so a flag
// means the same wherever it is typed. The flag package stops at the first
// non-flag, which would turn "intel search fortinet --limit 3" into a search for
// the text "fortinet --limit 3". A "--" ends flags as usual.
func flagsFirst(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i:]...)
			break
		}
		if len(a) < 2 || a[0] != '-' {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue // the value is attached
		}
		f := fs.Lookup(name)
		if f == nil {
			continue // unknown: let Parse report it
		}
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i]) // this flag's value
		}
	}
	return append(flags, positional...)
}

func runVersion(_ context.Context, args []string) error {
	fs := flagSet("version")
	asJSON := fs.Bool("json", false, "print the version information as JSON")
	if err := parseFlags(fs, "fal-x version [--json]", args); err != nil {
		return err
	}

	rev, built := buildVCS()
	if *asJSON {
		b, err := json.MarshalIndent(map[string]string{
			"version":  config.Version,
			"commit":   rev,
			"built":    built,
			"go":       runtime.Version(),
			"platform": runtime.GOOS + "/" + runtime.GOARCH,
			"home":     config.Home(),
		}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("fal-x %s\n", config.Version)
	if rev != "" {
		fmt.Printf("commit:   %s\n", rev)
		if built != "" {
			fmt.Printf("built:    %s\n", built)
		}
	}
	fmt.Printf("go:       %s\n", runtime.Version())
	fmt.Printf("platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("home:     %s\n", config.Home())
	return nil
}

// buildVCS returns the commit and build time the Go toolchain stamps into a
// binary built from a repository, with a -dirty suffix for an uncommitted tree.
// Both are empty when the binary was built outside version control.
func buildVCS() (revision, built string) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", ""
	}
	var modified bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.time":
			built = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if modified && revision != "" {
		revision += "-dirty"
	}
	return revision, built
}
