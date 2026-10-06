// Command fal-x is the Fal-X entrypoint: reconnaissance, exposure
// management, and authorized security assessment.
//
// Exit status contract:
//
//	0  success
//	1  runtime failure, such as a stage or tool failing
//	2  usage or validation error
//	3  authorization or scope refusal
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sort"
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
	{"scan", "reconnaissance pipeline against authorized targets", runScan},
	{"intel", "vulnerability intelligence: sync, show, search", runIntel},
	{"assets", "inventory management: import, list, show", runAssets},
	{"match", "match the inventory against the vulnerability corpus", runMatch},
	{"prioritize", "rank findings by exploitability and asset criticality", runPrioritize},
	{"verify", "confirm a finding against the live target", runVerify},
	{"exploit", "run an exploit module (requires authorization and consent)", runExploit},
	{"session", "session tracking and evidence collection", runSession},
	{"report", "render findings as markdown, JSON, or SARIF", runReport},
	{"serve", "run the HTTP API", runServe},
	{"migrate", "apply, roll back, or inspect database migrations", runMigrate},
	{"install", "install the external reconnaissance tools for this platform", runInstall},
	{"version", "print version information", runVersion},
}

// exitCode maps the result of a subcommand onto the exit status.
//
// It lives here rather than in logging because a help request is not a failure
// and not a usage error: the command succeeded at its only job. Everything else
// is classified by the one exit-status contract in internal/logging, so there is
// still exactly one place that decides what each failure means.
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

// realMain executes the command and returns the process exit status. It is kept
// apart from main so its deferred cleanup runs before the process exits, which
// os.Exit would otherwise skip.
func realMain() int {
	// A signal cancels the context so a stage can stop at the next checkpoint
	// rather than the process being killed mid-write.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := dispatch(ctx, os.Args[1:])
	switch {
	case err == nil, errors.Is(err, errHelp):
		// errHelp means the subcommand printed its own usage. That is a success.
		return logging.StatusOK
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
		if len(c.name) > width {
			width = len(c.name)
		}
	}
	for _, c := range cmds {
		fmt.Fprintf(w, "  %-*s  %s\n", width, c.name, c.summary)
	}

	fmt.Fprintf(w, `
Exit status:
  0  success
  1  runtime failure
  2  usage or validation error
  3  authorization or scope refusal

Global flags:
  --debug      verbose internal logging
  --quiet      errors only
  --json       machine-readable logging
  --no-color   disable ANSI colour
  --help       this help

Run "fal-x <command> --help" for the flags of a command.
`)
}

// errHelp signals that a subcommand was asked for its own usage.
//
// It is a sentinel rather than a nil error because "printed the help and exited
// zero" and "ran and succeeded" must not be the same outcome to the caller.
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

// wantsHelpArgs reports whether help was requested anywhere in args.
//
// Help is detected by scanning rather than by running the arguments through a
// flag set. A probe set would have to declare every flag the subcommand accepts
// just to survive the parse, and the moment one is added to the real parser and
// forgotten in the probe, every invocation of that subcommand fails with
// "flag provided but not defined".
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

// parseFlags parses and reports. A parse failure is a usage error.
//
// synopsis is the caller's usage line, because it knows which subcommand
// arguments matter. Deriving one from the flag set name loses that, which is how
// "fal-x migrate" came to advertise neither <up>, <down> nor <status>.
func parseFlags(fs *flag.FlagSet, synopsis string, args []string) error {
	if wantsHelpArgs(args) {
		printUsage(synopsis, fs)
		return errHelp
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUsage(synopsis, fs)
			return errHelp
		}
		return logging.Usagef("%v", err)
	}
	return nil
}

func runVersion(_ context.Context, _ []string) error {
	fmt.Printf("fal-x %s\n", config.Version)
	if rev, built := buildVCS(); rev != "" {
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
