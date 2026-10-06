package cli

import (
	"os"

	"github.com/BhargavPalan/Fal-X/internal/config"
	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/util"
)

// applyProfile adjusts pacing for the requested depth.
//
// The values live in config so there is one definition of each default. This
// copies the ones the stages need onto the parsed options, because a stage must
// not reach back into the config package to discover what it was asked to do.
//
// The Config is the one Parse already built rather than a second one. Building
// it twice meant reading the same environment twice to produce the same answer,
// and it made the defaults here and in Parse look like independent sources that
// happened to agree.
func (o *Options) applyProfile(c *config.Config) {
	c.Profile = o.Profile
	c.ApplyProfile()

	o.PortTop = c.PortTop
	o.PortRate = c.PortRate
	o.NucleiSeverity = c.NucleiSeverity
	o.NucleiRate = c.NucleiRate
	o.NucleiNoInteract = c.NucleiNoInteract
	o.NucleiTags = c.NucleiTags
	o.NmapHostCap = c.NmapHostCap
	o.RateLimit = c.RateLimit
	o.Timeout = c.Timeout
	o.KatanaDepth = c.KatanaDepth
}

// LoadCredentials reads the credential file as data and applies the keys the
// tool understands.
//
// The file is parsed, never sourced. Nothing in it is evaluated, and a value
// containing a shell metacharacter is refused rather than stored, so no later
// code path can be handed a payload. Values are never logged or printed.
func (o *Options) LoadCredentials() []error {
	if o.EnvFile == "" {
		return nil
	}
	if _, err := os.Stat(o.EnvFile); err != nil {
		// A missing credential file is normal: most runs need no token.
		return nil
	}

	vars, warns, err := util.EnvFile(o.EnvFile)
	if err != nil {
		return []error{err}
	}
	for _, w := range warns {
		logging.Warn("%s", w.Message)
	}
	for _, w := range util.CheckEnvFilePerms(o.EnvFile) {
		logging.Warn("%s", w.Message)
	}

	o.CensysToken = vars["CENSYS_TOKEN"]

	return nil
}
