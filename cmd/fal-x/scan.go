package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/cli"
	"github.com/BhargavPalan/Fal-X/internal/config"
	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/net"
	"github.com/BhargavPalan/Fal-X/internal/run"
	"github.com/BhargavPalan/Fal-X/internal/scope"
	"github.com/BhargavPalan/Fal-X/internal/stage"
	"github.com/BhargavPalan/Fal-X/internal/tools"
	"github.com/BhargavPalan/Fal-X/internal/util"
)

// runScan is the reconnaissance pipeline.
func runScan(ctx context.Context, args []string) error {
	// Help is intercepted before parsing. The scan flags are declared by
	// internal/cli, which is where the safety preconditions live and therefore
	// the one place that must see every flag.
	if wantsHelpArgs(args) {
		fmt.Print(scanUsage())
		return errHelp
	}

	opts, err := cli.Parse(args...)
	if err != nil {
		return err
	}

	// Precheck reports a wide target rather than refusing outright, so the
	// operator gets to answer for it. A single domain never reaches this.
	err = opts.Precheck()

	var needs *cli.NeedsConfirm
	if errors.As(err, &needs) {
		confirmed, cerr := confirmWideTarget(needs, stdinIsTerminal())
		if cerr != nil {
			return cerr
		}
		if !confirmed {
			logging.Warn("not confirmed; nothing was contacted")
			return nil
		}
		opts.Yes = true
		if err = opts.Precheck(); err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}

	// --why-denied explains one decision and exits. It runs before anything
	// else because an operator debugging a rejection should not have to start a
	// run to get an answer.
	if opts.WhyDenied != "" {
		fmt.Println(opts.Explain(opts.WhyDenied))
		return nil
	}

	if opts.DryRun {
		printPlan(opts)
		return nil
	}

	// The stage port is not finished. Refusing here rather than running a
	// partial pipeline matters: a scan that quietly skipped its content and scan
	// stages would report itself as a clean run.
	return runPipeline(ctx, opts)
}

// runPipeline executes the enabled stages and reports the run.
//
// The stage outcomes are authoritative. A stage that failed is recorded as
// failed and the run's exit status reflects that, regardless of what the log
// says about finishing.
func runPipeline(ctx context.Context, opts *cli.Options) error {
	if errs := opts.LoadCredentials(); len(errs) > 0 {
		return errs[0]
	}

	r, paths, err := newRun(opts)
	if err != nil {
		return err
	}

	if err := paths.Ensure(); err != nil {
		return err
	}

	env := &stage.Env{
		Run:   r,
		Gate:  newGate(opts),
		Tools: tools.NewRecording(tools.New()),
		Opts:  opts,
		Paths: paths,
	}

	// The two concurrent pairs are real. They are run through the stage runner
	// in order here so that a failure is recorded per stage; making them
	// genuinely concurrent is the next step, and it must not be done by simply
	// reordering, because no stage may assume its peer's output exists.
	if err := stage.Run(ctx, env, opts.StageEnabled); err != nil {
		logging.Error("%v", err)
		return logging.Runtimef("%v", err)
	}

	logging.Ok("%s", r.SummaryLine())
	return nil
}

// printPlan renders the dry-run plan.
//
// This is the same code path as a real run with the network gate forced closed,
// not a separate implementation, so the plan reflects what would actually
// happen.
func printPlan(opts *cli.Options) {
	var b strings.Builder

	fmt.Fprintf(&b, "fal-x %s -- dry run, no network requests will be made\n\n", config.Version)

	fmt.Fprintf(&b, "targets:\n")
	for _, seed := range opts.Seeds() {
		fmt.Fprintf(&b, "  %s\n", seed)
	}
	if opts.IPTarget != "" {
		fmt.Fprintf(&b, "  %s (ip/cidr)\n", opts.IPTarget)
	}
	if opts.ASN != "" {
		fmt.Fprintf(&b, "  %s (asn)\n", opts.ASN)
	}

	fmt.Fprintln(&b)
	if opts.Scope() != nil && opts.Scope().Loaded() {
		fmt.Fprintf(&b, "authorization:  restricted to the scope allowlist\n")
	} else {
		fmt.Fprintf(&b, "authorization:  none configured, every named target is reachable\n")
	}
	fmt.Fprintf(&b, "scope allowlist: %s%s\n", orUnset(opts.ScopeFile), readableSuffix(opts.ScopeFile))
	fmt.Fprintf(&b, "scope denylist:  %s%s\n", orUnset(opts.OutOfScopeFile), readableSuffix(opts.OutOfScopeFile))
	fmt.Fprintf(&b, "allow-private:   %v\n", opts.AllowPrivate)
	fmt.Fprintf(&b, "allow-any:       %v\n", opts.AllowAny)
	fmt.Fprintf(&b, "profile:         %s\n", opts.Profile)
	fmt.Fprintf(&b, "output root:     %s\n", opts.Output)
	fmt.Fprintf(&b, "stages enabled:  %s\n", stageList(opts.Stages()))

	sc := opts.Scope()
	switch {
	case sc == nil, !sc.Loaded():
		fmt.Fprintf(&b, "\nscope effective: unrestricted, the targets named above are what "+
			"gets scanned\n  pass --scope <file> to hold the run to an allowlist\n")
	default:
		printRules(&b, sc.Rules())
	}

	fmt.Fprintf(&b, "\nmissing tools: %s\n", joinComma(missingTools()))

	fmt.Print(b.String())
}

// printRules renders the effective scope rules.
//
// The counts and the entries are both shown. A count alone hides a rule that was
// dropped by a parse error, which is exactly what an operator needs to notice
// before the run rather than after.
//
// Addresses and prefixes are listed separately rather than merged, because an
// exact address and a range are different permissions to grant and a reader
// should not have to guess which one a line is.
func printRules(b *strings.Builder, r scope.Rules) {
	fmt.Fprintf(b, "\nscope effective:\n")
	fmt.Fprintf(b, "  allow apex:      %s\n", orNone(r.AllowApex))
	fmt.Fprintf(b, "  allow wildcard:  %s\n", orNone(r.AllowWildcard))
	fmt.Fprintf(b, "  allow host:port: %s\n", orNone(r.AllowHostPort))
	fmt.Fprintf(b, "  allow ip:        %s\n", orNone(r.AllowIP))
	fmt.Fprintf(b, "  allow cidr:      %s\n", orNone(r.AllowCIDR))
	fmt.Fprintf(b, "  deny apex:       %s\n", orNone(r.DenyApex))
	fmt.Fprintf(b, "  deny wildcard:   %s\n", orNone(r.DenyWildcard))
	fmt.Fprintf(b, "  deny host:port:  %s\n", orNone(r.DenyHostPort))
	fmt.Fprintf(b, "  deny ip:         %s\n", orNone(r.DenyIP))
	fmt.Fprintf(b, "  deny cidr:       %s\n", orNone(r.DenyCIDR))
}

// missingTools lists the external tools that are not installed.
//
// It is advisory. A missing tool fails its stage, which is recorded in
// stages.json, rather than aborting the run before anything has been attempted.
func missingTools() []string {
	required := []string{"httpx", "naabu", "nuclei", "subfinder", "dnsx", "tlsx"}
	var missing []string
	for _, tool := range required {
		path, err := execLookPath(tool)
		if err != nil {
			missing = append(missing, tool)
			continue
		}
		if _, err := os.Stat(path); err != nil {
			missing = append(missing, tool)
		}
	}
	return missing
}

// newGate builds the network gate for a run.
func newGate(opts *cli.Options) *net.Gate {
	g := net.New(opts.Scope())
	g.SetDryRun(opts.DryRun)
	return g
}

// newRun prepares the run directory and records the authorization context.
//
// The stage paths are returned alongside the run rather than stored on it, so
// the run package does not have to know the pipeline's directory layout.
func newRun(opts *cli.Options) (*run.Run, stage.Paths, error) {
	label := sanitiseLabel(opts.Target())
	stamp := util.RunStamp(now())

	dir := filepathJoin(opts.Output, label, stamp)
	r, err := run.Init(dir, label, stamp)
	if err != nil {
		return nil, stage.Paths{}, err
	}
	paths := stage.NewPaths(dir)

	r.SetTarget(opts.Target())
	r.SetProfile(opts.Profile)
	r.SetDryRun(opts.DryRun)
	r.SetAllowPrivate(opts.AllowPrivate)

	// The exact allowlist and denylist text the run is authorized under is
	// recorded, because a result is only meaningful alongside its authorization.
	if b, err := os.ReadFile(opts.ScopeFile); err == nil {
		r.SetScope(string(b), readText(opts.OutOfScopeFile))
	}

	return r, paths, nil
}

// helpers

func orUnset(s string) string {
	if s == "" {
		return "<unset>"
	}
	return s
}

// orNone renders a rule list, or "none" when it is empty.
func orNone(list []string) string {
	if len(list) == 0 {
		return "none"
	}
	return strings.Join(list, " ")
}

func stageList(stages []string) string {
	if len(stages) == 0 {
		return "none"
	}
	return " " + strings.Join(stages, " ")
}

// readableSuffix reports whether a path can be read, for the plan display.
func readableSuffix(path string) string {
	if path == "" {
		return ""
	}
	if _, err := os.Stat(path); err != nil {
		return " (MISSING)"
	}
	return " (readable)"
}

func readText(path string) string {
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// sanitiseLabel makes a target safe to use as a directory name.
func sanitiseLabel(s string) string {
	if s == "" {
		return "run"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	label := b.String()
	if len(label) > 64 {
		label = label[:64]
	}
	return label
}
