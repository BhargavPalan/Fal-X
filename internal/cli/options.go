// Package cli parses and validates the command line.
//
// It is pure: parsing and prechecks make no network request and write nothing.
// That separation is what makes the safety preconditions trustworthy, because
// the decision to contact a target is reached before anything can contact it.
package cli

import (
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/config"
	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/scope"
	"github.com/BhargavPalan/Fal-X/internal/util"
)

// AllStages is the pipeline stage order.
//
// The order is significant: roots feeds subs, subs feeds resolve, resolve feeds
// both ports and http, and content and scan both need http. The two concurrent
// pairs are real, so no stage may assume a peer's output exists.
var AllStages = []string{"roots", "subs", "resolve", "ports", "http", "content", "scan"}

// Refusal classifies why a run will not proceed.
//
// The classification is derived from the error types in internal/logging rather
// than being a parallel type. Two representations of the same three-way split
// would be one more thing to keep in step, and the exit-status contract has to
// mean the same thing wherever an error is produced.
type Refusal = logging.Refusal

const (
	// RefuseNone means no refusal.
	RefuseNone = logging.RefuseNone
	// RefuseUsage is a bad flag, malformed input, or contradictory modes.
	// Exit status 2.
	RefuseUsage = logging.RefuseUsage
	// RefuseScope is a missing authorization or an unusable scope. Exit
	// status 3.
	RefuseScope = logging.RefuseScope
)

// RefusalKind reports how err should be classified.
func RefusalKind(err error) Refusal { return logging.RefusalOf(err) }

// StatusFor maps an error onto the exit-status contract.
func StatusFor(err error) int { return logging.ExitFor(err) }

// usageErr builds a usage refusal, exit status 2.
func usageErr(format string, a ...any) error { return logging.Usagef(format, a...) }

// scopeErr builds an authorization refusal, exit status 3.
func scopeErr(format string, a ...any) error { return logging.Scopef(format, a...) }

// Options is a parsed command line.
type Options struct {
	// Target selection. At most one of these is set.
	Domain   string
	ListFile string
	IPTarget string
	ASN      string
	Org      string

	ScopeFile      string
	OutOfScopeFile string

	// ScopeRequested records that --scope was given, as opposed to ScopeFile
	// holding the default location that happens to be absent.
	//
	// The distinction decides what a missing file means. No flag and no file is
	// the ordinary case and the run is unrestricted. A flag naming a file that
	// is not there is an instruction that could not be carried out, and quietly
	// running without the boundary it asked for would be worse than refusing.
	ScopeRequested bool
	Output         string
	EnvFile        string
	Resume         string

	// Safety.
	AllowPrivate bool
	AllowAny     bool
	WhyDenied    string
	DryRun       bool

	// Pacing and depth.
	Profile  string
	SkipScan bool
	Fast     bool
	Verbose  bool
	NewOnly  bool
	// Yes answers the confirmation for a wide target without prompting.
	Yes      bool
	Quiet    bool
	Debug    bool
	JSON     bool
	PortSpec string
	Threads  int
	Jobs     int

	// Wordlists, carried so the stages do not have to reach back into config.
	DNSWordlist  string
	DirWordlist  string
	ResolverList string

	// Port scanning limits.
	PortTop     int
	PortRate    int
	PortConc    int
	NmapHostCap int

	// CensysToken is read from the credential file, never from a flag. It is
	// not echoed, not logged, and not written to the manifest.
	CensysToken string

	// HTTP probing.
	RateLimit int
	Timeout   int

	// Crawling.
	KatanaDepth int
	FetchJS     bool

	// NucleiSeverity and NucleiRate bound template scanning.
	NucleiSeverity string
	NucleiRate     int
	NucleiTags     string
	// NucleiNoInteract disables templates that authenticate or submit data.
	NucleiNoInteract bool

	// IPMode marks an address or ASN run, which has no domain to expand.
	IPMode bool

	// Optional stages.
	Brute  bool
	Amass  bool
	Nmap   bool
	Dirs   bool
	Censys bool

	// stages holds the resolved per-stage selection.
	stages map[string]bool

	scope *scope.Scope
}

// boolFlags are the switches. They are listed so that --switch=value can be
// rejected rather than silently reduced to the bare switch, which would turn
// --dry-run=false into --dry-run and run a scan the operator asked to skip.
var boolFlags = map[string]bool{
	"--yes": true, "-y": true, "--allow-private": true, "--allow-any": true,
	"--dry-run": true, "--skip-scan": true, "--fast": true, "--brute": true,
	"--deep": true, "--nmap": true, "--dirs": true, "--censys": true,
	"--verbose": true, "--new": true, "--quiet": true, "--debug": true,
	"--json": true,
}

// Parse reads args into an Options, rejecting anything malformed.
//
// It reports a usage refusal for a bad flag or a contradictory set of targets.
// It does not check authorization or load a scope file; Precheck does that, so
// the two failures stay distinguishable.
func Parse(args ...string) (*Options, error) {
	c := config.New()

	// Pacing fields are deliberately absent. applyProfile fills RateLimit,
	// Timeout, KatanaDepth, PortTop, PortRate, NmapHostCap, NucleiSeverity and
	// NucleiRate further down from the resolved profile, so assigning them here
	// produced values that were overwritten before anything could read them.
	o := &Options{
		ScopeFile:      c.ScopeFile,
		OutOfScopeFile: c.OutOfScopeFile,
		Output:         c.Output,
		EnvFile:        c.EnvFile,
		Profile:        c.Profile,

		DNSWordlist:  c.DNSWordlist,
		DirWordlist:  c.DirWordlist,
		ResolverList: c.ResolverList,

		PortConc: 25,
		Threads:  50,
		Jobs:     10,
	}

	// The resolved stage set starts as everything on.
	o.stages = make(map[string]bool, len(AllStages))
	for _, s := range AllStages {
		o.stages[s] = true
	}

	explicitStages := false

	// inline carries the value from a --flag=value argument, for this iteration
	// only. Go's flag package accepts that spelling and so does every other
	// command line tool, so a form this parser rejects reads as a bug in the
	// tool rather than a rule the operator has to know.
	var inline string
	var hasInline bool

	// valueFlag returns the value belonging to a flag, preferring the attached
	// spelling. A flag at the end of the line with no attached value is a usage
	// error rather than an empty value, because an empty scope path would fail
	// closed with a confusing message instead of naming the typo.
	valueFlag := func(i *int, name string) (string, error) {
		if hasInline {
			return inline, nil
		}
		if *i+1 >= len(args) {
			return "", usageErr("%s requires a value", name)
		}
		*i++
		return args[*i], nil
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		inline, hasInline = "", false

		// Split -flag=value before dispatch, so the switch still sees the flag name
		// it already handles and valueFlag can hand back what followed the equals
		// sign. Single dash included, because that is what the flag package does
		// and a tool that accepts --flag=value but not -f=value reads as broken.
		if strings.HasPrefix(arg, "-") {
			if j := strings.IndexByte(arg, '='); j > 0 {
				arg, inline, hasInline = arg[:j], arg[j+1:], true
			}
		}
		if hasInline && boolFlags[arg] {
			return nil, usageErr("%s is a switch and takes no value", arg)
		}

		// A bare target is accepted as a convenience for -d.
		if !strings.HasPrefix(arg, "-") {
			if o.Domain != "" {
				return nil, usageErr("unexpected extra argument %q; use -l for a list of targets", arg)
			}
			o.Domain = arg
			continue
		}

		switch arg {
		case "-d", "--domain":
			v, err := valueFlag(&i, arg)
			if err != nil {
				return nil, err
			}
			o.Domain = v

		case "-l", "--list":
			v, err := valueFlag(&i, arg)
			if err != nil {
				return nil, err
			}
			o.ListFile = v

		case "-ip", "--ip":
			v, err := valueFlag(&i, arg)
			if err != nil {
				return nil, err
			}
			if _, err := normaliseIPOrCIDR(v); err != nil {
				return nil, err
			}
			o.IPTarget = v

		case "-asn", "--asn":
			v, err := valueFlag(&i, arg)
			if err != nil {
				return nil, err
			}
			norm, err := normaliseASN(v)
			if err != nil {
				return nil, err
			}
			o.ASN = norm

		case "-o", "--org":
			v, err := valueFlag(&i, arg)
			if err != nil {
				return nil, err
			}
			o.Org = v

		case "--scope":
			v, err := valueFlag(&i, arg)
			if err != nil {
				return nil, err
			}
			o.ScopeFile = v
			o.ScopeRequested = true

		case "--exclude", "--out-of-scope":
			v, err := valueFlag(&i, arg)
			if err != nil {
				return nil, err
			}
			o.OutOfScopeFile = v

		case "--output", "-o-out":
			v, err := valueFlag(&i, arg)
			if err != nil {
				return nil, err
			}
			o.Output = v

		case "--env-file":
			v, err := valueFlag(&i, arg)
			if err != nil {
				return nil, err
			}
			o.EnvFile = v

		case "--resume":
			v, err := valueFlag(&i, arg)
			if err != nil {
				return nil, err
			}
			o.Resume = v

		case "--yes", "-y":
			o.Yes = true
		case "--allow-private":
			o.AllowPrivate = true
		case "--allow-any":
			o.AllowAny = true
		case "--dry-run":
			o.DryRun = true
		case "--skip-scan":
			o.SkipScan = true
		case "--fast":
			o.Fast = true
		case "--brute":
			o.Brute = true
		case "--deep":
			o.Amass = true
		case "--nmap":
			o.Nmap = true
		case "--dirs":
			o.Dirs = true
		case "--censys":
			o.Censys = true
		case "--verbose", "-v":
			o.Verbose = true
		case "--new":
			o.NewOnly = true
		case "--quiet", "-q":
			o.Quiet = true
		case "--debug":
			o.Debug = true
		case "--json":
			o.JSON = true

		case "--why-denied":
			v, err := valueFlag(&i, arg)
			if err != nil {
				return nil, err
			}
			o.WhyDenied = v

		case "--profile":
			v, err := valueFlag(&i, arg)
			if err != nil {
				return nil, err
			}
			o.Profile = v

		case "--stages":
			v, err := valueFlag(&i, arg)
			if err != nil {
				return nil, err
			}
			if err := o.setStages(v); err != nil {
				return nil, err
			}
			explicitStages = true

		case "--ports", "--pflag":
			v, err := valueFlag(&i, arg)
			if err != nil {
				return nil, err
			}
			if !util.IsPortOrRange(v) {
				return nil, usageErr("invalid port specification %q", v)
			}
			o.PortSpec = v

		case "--threads":
			v, err := valueFlag(&i, arg)
			if err != nil {
				return nil, err
			}
			n, convErr := strconv.Atoi(v)
			if convErr != nil || n < 1 {
				return nil, usageErr("--threads requires a positive integer, got %q", v)
			}
			o.Threads = n

		case "--jobs":
			v, err := valueFlag(&i, arg)
			if err != nil {
				return nil, err
			}
			n, convErr := strconv.Atoi(v)
			if convErr != nil || n < 1 {
				return nil, usageErr("--jobs requires a positive integer, got %q", v)
			}
			o.Jobs = n

		default:
			// An unrecognised flag must never become a positional target.
			return nil, usageErr("unknown flag %q", arg)
		}
	}

	// --fast is shorthand for --profile fast.
	if o.Fast {
		o.Profile = "fast"
	}
	if !config.ValidProfile(o.Profile) {
		return nil, usageErr("unknown profile %q (expected fast, normal, or exhaustive)", o.Profile)
	}

	// The profile adjusts pacing. It is applied here rather than in a stage, so
	// a dry run shows the values a real run would actually use.
	o.applyProfile(c)

	// An explicit --stages listing wins over --skip-scan, because it is the more
	// specific request.
	if !explicitStages && o.SkipScan {
		o.stages["scan"] = false
	}

	// More than one target flag is contradictory and is caught here rather than
	// in Precheck, because it is a property of the command line alone.
	//
	// Zero targets is not caught here: --why-denied explains a scope decision
	// and names its own target, so it legitimately has none.
	if n := o.targetFlagCount(); n > 1 {
		return nil, usageErr("choose only one of %s", strings.Join(o.targetFlagsSet(), ", "))
	}

	o.IPMode = o.IPTarget != "" || o.ASN != ""

	// IP and ASN runs have no domain to expand, so the domain stages are gated
	// off. The port and http stages stay on: they consume the addresses
	// directly, including non-default ports.
	if o.IPMode {
		for _, s := range []string{"roots", "subs", "resolve", "content"} {
			o.stages[s] = false
		}
		if o.Dirs {
			o.Dirs = false
		}
	}

	return o, nil
}

// setStages applies a comma-separated stage list.
func (o *Options) setStages(csv string) error {
	known := make(map[string]bool, len(AllStages))
	for _, s := range AllStages {
		known[s] = true
	}

	var want []string
	for _, raw := range strings.Split(csv, ",") {
		s := strings.Join(strings.Fields(raw), "")
		if s == "" {
			continue
		}
		if !known[s] {
			return usageErr("unknown stage %q (valid stages: %s)", s, strings.Join(AllStages, ", "))
		}
		want = append(want, s)
	}

	// An empty list leaves every stage on rather than disabling everything, so a
	// stray comma cannot silently turn a scan into a no-op.
	if len(want) == 0 {
		return nil
	}

	for _, s := range AllStages {
		o.stages[s] = false
	}
	for _, s := range want {
		o.stages[s] = true
	}
	return nil
}

// targetFlagsSet lists the target flags that were supplied, in flag order.
func (o *Options) targetFlagsSet() []string {
	var set []string
	for _, t := range []struct {
		name string
		set  bool
	}{
		{"-d", o.Domain != ""},
		{"-l", o.ListFile != ""},
		{"-ip", o.IPTarget != ""},
		{"-asn", o.ASN != ""},
	} {
		if t.set {
			set = append(set, t.name)
		}
	}
	return set
}

// targetFlagCount returns how many target flags were supplied.
func (o *Options) targetFlagCount() int { return len(o.targetFlagsSet()) }

// StageEnabled reports whether stage is part of this run.
func (o *Options) StageEnabled(stage string) bool { return o.stages[stage] }

// Stages returns the enabled stages in pipeline order.
func (o *Options) Stages() []string {
	var out []string
	for _, s := range AllStages {
		if o.stages[s] {
			out = append(out, s)
		}
	}
	return out
}

// Target returns a human label for the run, used for the output directory.
func (o *Options) Target() string {
	switch {
	case o.Domain != "":
		return o.Domain
	case o.ListFile != "":
		return filepath.Base(o.ListFile)
	case o.IPTarget != "":
		return o.IPTarget
	case o.ASN != "":
		return o.ASN
	default:
		return ""
	}
}

// Scope returns the loaded scope, available after Precheck succeeds.
func (o *Options) Scope() *scope.Scope { return o.scope }

// normaliseIPOrCIDR validates an address or prefix and returns its canonical
// form.
func normaliseIPOrCIDR(v string) (string, error) {
	if v == "" {
		return "", usageErr("an IP address or CIDR is required")
	}
	if p, err := netip.ParsePrefix(v); err == nil {
		return p.String(), nil
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return a.String(), nil
	}
	return "", usageErr("not a valid IP address or CIDR: %q", v)
}

// normaliseASN validates an autonomous system number.
func normaliseASN(v string) (string, error) {
	if v == "" {
		return "", usageErr("an ASN is required")
	}
	up := strings.ToUpper(v)
	if !strings.HasPrefix(up, "AS") {
		return "", usageErr("not a valid ASN: %q (expected the form AS12345)", v)
	}
	digits := up[2:]
	if digits == "" {
		return "", usageErr("not a valid ASN: %q (expected the form AS12345)", v)
	}
	n, err := strconv.Atoi(digits)
	if err != nil || n <= 0 || n > 4294967295 {
		return "", usageErr("not a valid ASN: %q", v)
	}
	return up, nil
}
