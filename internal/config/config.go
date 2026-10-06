// Package config holds the defaults and run-time paths for Fal-X.
//
// Precedence for every tunable, highest first:
//
//	command-line flag
//	config/config.local.yaml (optional, gitignored)
//	this file
//	built-in default
//
// This package performs no I/O and never sources user input. Credential files
// are parsed as data by internal/config, never evaluated as shell code.
package config

import (
	"os"
	"path/filepath"
	"time"
)

// Version is set at build time with -ldflags "-X ...config.Version=...".
var Version = "0.2.0-dev"

// Pacing.
const (
	DefaultRateLimit = 150 // httpx requests per second
	DefaultTimeout   = 10  // per-request seconds
)

// Port scanning.
const (
	DefaultPortTop  = 1000
	DefaultPortRate = 1000
)

// DefaultASNPortList is the port set for ASN mode. ASN mode has no DNS to guide
// it, so it defaults to a small web-ish set rather than scanning a thousand
// ports across every announced netblock.
const DefaultASNPortList = "80,443,8080,8443"

// Content discovery.
const (
	DefaultGAUTimeout   = 90
	DefaultURLProbeMax  = 5000
	DefaultKatanaDepth  = 2
	DefaultJSMaxBytes   = 2 << 20 // 2 MiB
	DefaultJSURLLimit   = 500     // distinct JS files fetched per run
	DefaultNmapHostCap  = 200     // hosts sent to nmap -sV
	DefaultRedirsPerHop = 5
)

// Run bounds. These exist so a run cannot run away from its operator.
const (
	DefaultMaxTargets   = 200000
	DefaultMaxURLs      = 500000
	DefaultMaxRuntime   = 4 * time.Hour
	DefaultMaxBodyBytes = 5 << 20 // 5 MiB
)

// Network timeouts.
const (
	DefaultConnectTimeout = 5 * time.Second
	DefaultMaxTime        = 20 * time.Second
)

// Selection defaults. These were spelled out as bare literals in this package
// and again in internal/cli. Two copies of a default is one too many the moment
// either is edited, because nothing would notice them disagreeing.
const (
	DefaultProfile        = "normal"
	DefaultNucleiSeverity = "low,medium,high,critical"
)

// Config is the effective configuration for one run.
type Config struct {
	// Paths.
	Home           string
	Output         string
	EnvFile        string
	ScopeFile      string
	OutOfScopeFile string

	// Wordlists.
	DNSWordlist  string
	DirWordlist  string
	ResolverList string

	// Stage switches.
	DoTargets bool
	DoRoots   bool
	DoSubs    bool
	DoResolve bool
	DoPorts   bool
	DoHTTP    bool
	DoContent bool
	DoScan    bool

	// Optional capabilities.
	Verbose      bool
	NewOnly      bool
	DryRun       bool
	AllowPrivate bool
	AllowAny     bool
	AuthAck      bool
	IPMode       bool

	DoBrute  bool
	DoAmass  bool
	DoNmap   bool
	DoDirs   bool
	DoCensys bool
	DoResume bool

	// Profile is fast, normal or exhaustive.
	Profile string

	// Pacing.
	RateLimit int
	Timeout   int

	// Ports.
	PortTop     int
	PortList    string
	PortRate    int
	ASNPortList string

	// Template scanning.
	NucleiSeverity    string
	NucleiRate        int
	NucleiTags        string
	NucleiNoInteract  bool
	NucleiConcurrency int

	// Content.
	GAUTimeout  int
	URLProbeMax int
	KatanaDepth int
	JSParallel  int
	JSMaxBytes  int64
	JSURLLimit  int
	NmapHostCap int
	MaxRedirs   int

	// Bounds.
	MaxTargets   int
	MaxURLs      int
	MaxRuntime   time.Duration
	MaxBodyBytes int64

	// Network.
	ConnectTimeout time.Duration
	RequestTimeout time.Duration

	// Derived at run time, not user supplied.
	THREADS    int
	JOBS       int
	PortConc   int
	WorkDir    string
	Label      string
	Stamp      string
	RunID      string
	CacheDir   string
	StagesRoot string
	RootsDir   string
	SubsDir    string
	ResolveDir string
	PortsDir   string
	HTTPDir    string
	ContentDir string
	ScanDir    string
}

// New returns the repository defaults.
func New() *Config {
	home := Home()
	return &Config{
		Home:           home,
		Output:         filepath.Join(home, "output"),
		EnvFile:        filepath.Join(home, "config", ".env"),
		ScopeFile:      filepath.Join(home, "config", "scope.txt"),
		OutOfScopeFile: filepath.Join(home, "config", "out-of-scope.txt"),

		DNSWordlist:  filepath.Join(home, "wordlists", "subdomains.txt"),
		DirWordlist:  filepath.Join(home, "wordlists", "content.txt"),
		ResolverList: filepath.Join(home, "wordlists", "resolvers.txt"),

		DoTargets: true,
		DoRoots:   true,
		DoSubs:    true,
		DoResolve: true,
		DoPorts:   true,
		DoHTTP:    true,
		DoContent: true,
		DoScan:    true,

		Profile: DefaultProfile,

		RateLimit: DefaultRateLimit,
		Timeout:   DefaultTimeout,

		PortTop:     DefaultPortTop,
		PortRate:    DefaultPortRate,
		ASNPortList: DefaultASNPortList,

		NucleiSeverity: DefaultNucleiSeverity,
		NucleiRate:     300,

		GAUTimeout:  DefaultGAUTimeout,
		URLProbeMax: DefaultURLProbeMax,
		KatanaDepth: DefaultKatanaDepth,
		JSMaxBytes:  DefaultJSMaxBytes,
		JSURLLimit:  DefaultJSURLLimit,
		NmapHostCap: DefaultNmapHostCap,
		MaxRedirs:   DefaultRedirsPerHop,

		MaxTargets:   DefaultMaxTargets,
		MaxURLs:      DefaultMaxURLs,
		MaxRuntime:   DefaultMaxRuntime,
		MaxBodyBytes: DefaultMaxBodyBytes,

		ConnectTimeout: DefaultConnectTimeout,
		RequestTimeout: DefaultMaxTime,
	}
}

// Home returns the repository root.
//
// FALX_HOME wins when set, which is how the test suite and a container image
// point at a different tree. Otherwise the root is two levels up from this
// file, matching internal/<pkg>/config.go.
func Home() string {
	if h := os.Getenv("FALX_HOME"); h != "" {
		return h
	}
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	// Walk up looking for the marker file. This works from cmd/fal-x, from
	// internal/..., and from a test binary running anywhere in the tree.
	dir := wd
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return wd
}

// DetectResources derives concurrency from the core count.
//
// Every derived value is clamped to at least one so a machine reporting zero
// usable cores still produces a valid configuration.
func (c *Config) DetectResources(cores int) {
	if cores < 1 {
		cores = 1
	}
	c.THREADS = cores * 10
	c.JOBS = cores * 2
	if c.NucleiConcurrency <= 0 {
		c.NucleiConcurrency = cores * 4
	}
	c.PortConc = cores * 8
	if c.JSParallel <= 0 {
		c.JSParallel = c.JOBS
	}
}

// ApplyProfile adjusts pacing for the requested depth.
func (c *Config) ApplyProfile() {
	switch c.Profile {
	case "fast":
		c.PortTop = 100
		c.PortRate = 2000
		c.NucleiTags = "cve,exposure,misconfig,takeover,default-login,tech"
		c.NucleiNoInteract = true
		c.NucleiSeverity = "medium,high,critical"
		c.GAUTimeout = 45
		c.URLProbeMax = 1000
	case "normal":
	case "exhaustive":
		c.PortTop = 65535
		c.DoBrute = true
		c.DoDirs = true
		c.NucleiSeverity = DefaultNucleiSeverity
	default:
		// Left to the caller to reject; see ValidProfile.
	}
}

// ValidProfile reports whether name is a known speed profile.
func ValidProfile(name string) bool {
	switch name {
	case "fast", "normal", "exhaustive":
		return true
	}
	return false
}
