// Package config holds the run defaults, the speed profiles, and where the
// repository's files live.
//
// cli.Parse builds a Config, applies the chosen profile to it, and copies the
// values the stages need onto the parsed options; a flag then overrides the
// result. The package does no I/O beyond looking for the repository root.
package config

import (
	"os"
	"path/filepath"
)

// Version is set at build time with -ldflags "-X ...config.Version=...".
var Version = "0.2.0-dev"

// Defaults for a normal run.
const (
	DefaultProfile        = "normal"
	DefaultRateLimit      = 150 // httpx requests per second
	DefaultTimeout        = 10  // per-request seconds
	DefaultPortTop        = 1000
	DefaultPortRate       = 1000
	DefaultNucleiRate     = 300
	DefaultNucleiSeverity = "low,medium,high,critical"
	DefaultKatanaDepth    = 2
	DefaultNmapHostCap    = 200 // hosts sent to nmap -sV
)

// Config is the effective configuration for one run.
type Config struct {
	Home           string
	Output         string
	EnvFile        string
	ScopeFile      string
	OutOfScopeFile string

	DNSWordlist  string
	DirWordlist  string
	ResolverList string

	// Profile is fast, normal or exhaustive.
	Profile string

	RateLimit int
	Timeout   int

	PortTop  int
	PortRate int

	NucleiSeverity   string
	NucleiRate       int
	NucleiTags       string
	NucleiNoInteract bool

	KatanaDepth int
	NmapHostCap int
}

// New returns the defaults for the repository at Home.
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

		Profile: DefaultProfile,

		RateLimit: DefaultRateLimit,
		Timeout:   DefaultTimeout,

		PortTop:  DefaultPortTop,
		PortRate: DefaultPortRate,

		NucleiSeverity: DefaultNucleiSeverity,
		NucleiRate:     DefaultNucleiRate,

		KatanaDepth: DefaultKatanaDepth,
		NmapHostCap: DefaultNmapHostCap,
	}
}

// Home returns the repository root: FALX_HOME when set, otherwise the nearest
// directory above the working directory that holds go.mod, which works from
// cmd/fal-x, from internal/..., and from a test binary running anywhere in the tree.
func Home() string {
	if h := os.Getenv("FALX_HOME"); h != "" {
		return h
	}
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	dir := wd
	for range 6 {
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

// ApplyProfile adjusts pacing for the profile in c.Profile. An unknown profile is
// left alone; ValidProfile is how a caller rejects it.
//
// A profile changes port coverage and which nuclei templates run. It does not turn
// on the optional stages (brute force, directory discovery, amass, nmap, Censys):
// they generate real traffic against third parties and stay opt-in by flag.
func (c *Config) ApplyProfile() {
	switch c.Profile {
	case "fast":
		c.PortTop = 100
		c.PortRate = 2000
		c.NucleiTags = "cve,exposure,misconfig,takeover,default-login,tech"
		c.NucleiNoInteract = true
		c.NucleiSeverity = "medium,high,critical"
	case "exhaustive":
		c.PortTop = 65535
		c.NucleiSeverity = DefaultNucleiSeverity
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
