package cli

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/scope"
	"github.com/BhargavPalan/Fal-X/internal/util"
)

// Precheck applies the safety preconditions and loads the scope.
//
// It is pure with respect to the network: it decides whether a run may proceed
// and makes no request. That is what lets the authorization decision be reached
// before the first packet, and it is why this is a separate step from Parse.
//
// There is no blanket "I have authorization" flag. The allowlist is already
// mandatory and already fails closed, so an acknowledgement beside it is a
// second gate saying the same thing, and a flag people type reflexively stops
// being a signal. What is not covered by the allowlist is blast radius, and that
// is checked on its own: see checkBulkTarget.
func (o *Options) Precheck() error {
	// Exactly one target. Zero is a usage error rather than a silent no-op,
	// except for --why-denied, which names its own target and explains one
	// decision without needing a scan target at all.
	if err := o.checkTargetSelection(); err != nil {
		return err
	}

	// The allowlist is optional. When one is configured it is authoritative and
	// fails closed, because an operator who wrote a boundary meant it. When none
	// exists the run proceeds the way nmap or httpx would, so a bare target
	// works without ceremony.
	s := scope.New(o.AllowPrivate, o.AllowAny)
	loadErr := s.Load(o.ScopeFile, o.OutOfScopeFile)

	explaining := o.WhyDenied != ""
	planning := o.DryRun

	switch {
	case loadErr == nil:
		// A usable allowlist. It is now the boundary for this run.

	case o.ScopeRequested && !planning:
		// The flag named a file and the file could not be used. Refusing is the
		// honest response, because running without the boundary the operator asked
		// for is the one outcome nobody intended.
		return scopeErr("cannot use the scope allowlist: %v", loadErr)

	default:
		// No usable allowlist was requested, so there is no boundary to honour and
		// the run is unrestricted, the way nmap or httpx behaves. A dry run lands
		// here too when its scope file is temporarily broken: it contacts nothing,
		// and refusing to print a plan would only stop someone diagnosing it.
		s = scope.Unrestricted()
		if o.OutOfScopeFile != "" && fileExists(o.OutOfScopeFile) {
			s = scope.DenylistOnly(o.OutOfScopeFile)
		}
		if o.ScopeRequested {
			// The operator asked for a boundary and did not get one. Say so rather
			// than letting the plan imply a restriction that is not in force.
			logWarnf("scope allowlist unusable, so this %s is not held to one: %v",
				explainWhat(explaining), loadErr)
		}
	}

	o.scope = s
	for _, w := range s.Warnings() {
		logWarn(w)
	}

	// --why-denied explains one decision and a dry run validates a plan. Neither
	// contacts anything, so neither needs a boundary to proceed.
	if explaining || planning {
		return nil
	}

	// Every requested target must be inside the allowlist before anything is
	// contacted. Checking here rather than leaving it to the per-request gate
	// turns an out-of-scope run into an immediate refusal instead of a partial
	// scan that quietly stopped halfway.
	if err := o.checkTargetsInScope(); err != nil {
		return err
	}

	return o.checkBulkTarget()
}

// fileExists reports whether path is present, treating any stat failure as absent.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// explainWhat names the mode for a message, so the wording does not have to be
// repeated at each call site.
func explainWhat(explaining bool) string {
	if explaining {
		return "explanation"
	}
	return "dry run"
}

// bulkTargetHostBits is the host-bit count above which a prefix counts as bulk.
//
// A /22 leaves 1024 addresses, which is where a single command stops being
// something a person scoped by hand. Below that, "192.0.2.0/29" is six machines
// an operator chose individually; above it, it is a range nobody enumerated.
const bulkTargetHostBits = 10

// hostBits returns how many host bits a prefix leaves.
func hostBits(p netip.Prefix) int { return p.Addr().BitLen() - p.Bits() }

// NeedsConfirm is returned when a target's reach is far wider than its name
// suggests and the run needs an explicit go-ahead.
//
// This is the part an allowlist genuinely cannot express. A file naming one
// domain is a decision someone made about one estate. A file naming a wildcard,
// an autonomous system, or a large prefix is a decision whose consequences reach
// far past anything the file spells out.
type NeedsConfirm struct {
	// Reason names what is wide about this target.
	Reason string
	// Prompt is the question shown to an interactive operator.
	Prompt string
}

func (e *NeedsConfirm) Error() string { return e.Reason }

// checkBulkTarget refuses a wide target unless it was confirmed.
//
// A single domain, or a prefix small enough to have been chosen host by host, is
// left alone. That is the common case and it should not be slowed down by a
// ceremony nobody else in this category imposes.
func (o *Options) checkBulkTarget() error {
	if reason := o.bulkReason(); reason != "" {
		if o.Yes {
			logWarnf("confirmed by --yes: %s", reason)
			return nil
		}
		return &NeedsConfirm{
			Reason: reason,
			Prompt: "This target reaches much further than its name suggests.\n  " + reason +
				"\n\nConfirm you have written authorisation for everything in that range.",
		}
	}
	return nil
}

// bulkReason describes why this target is wide, or "" when it is not.
func (o *Options) bulkReason() string {
	if o.ASN != "" {
		return fmt.Sprintf("--asn %s resolves to every netblock the ASN announces, "+
			"which is typically far more than you enumerated", o.ASN)
	}

	if o.IPTarget != "" {
		if p, err := netip.ParsePrefix(o.IPTarget); err == nil {
			if hostBits(p) > bulkTargetHostBits {
				return fmt.Sprintf("%s covers %s addresses, which was not enumerated by hand",
					p, addressCount(p))
			}
		}
	}

	if o.AllowAny {
		return "--allow-any permits a bare wildcard in the scope file, so every " +
			"unmatched target is reachable"
	}

	// A broad allowlist entry, even for a single named target.
	if o.scope != nil && o.scope.Summary().AllowAny {
		return "the allowlist contains a bare wildcard, so every unmatched target is reachable"
	}

	return ""
}

// addressCount returns how many addresses a prefix covers, as a readable string.
func addressCount(p netip.Prefix) string {
	bits := p.Addr().BitLen()
	hostBits := bits - p.Bits()
	if hostBits <= 0 {
		return "1"
	}
	// Exact for small prefixes, approximate beyond that, because "2^32
	// addresses" is more useful than a nine-digit number.
	if hostBits <= 20 {
		return fmt.Sprintf("%d", uint64(1)<<uint(hostBits))
	}
	return fmt.Sprintf("2^%d", hostBits)
}

// checkTargetSelection enforces exactly one target flag.
//
// --why-denied is exempt: it explains a decision about the target it names, so
// requiring a separate scan target would make the diagnostic harder to use
// than the thing it diagnoses.
func (o *Options) checkTargetSelection() error {
	if o.WhyDenied != "" {
		return nil
	}
	if o.targetFlagCount() == 1 {
		return nil
	}
	if o.targetFlagCount() == 0 {
		return usageErr("choose a target with exactly one of -d, -l, -ip, or -asn")
	}
	return usageErr("choose only one of %s", strings.Join(o.targetFlagsSet(), ", "))
}

// checkTargetsInScope refuses the run when a requested target is out of scope.
func (o *Options) checkTargetsInScope() error {
	switch {
	case o.IPTarget != "":
		if !o.scope.Gate(o.IPTarget, "") {
			return scopeErr("IP target is outside the configured scope: %s", o.IPTarget)
		}
		return nil

	case o.ASN != "":
		// An ASN expands into netblocks that do not exist yet, so it cannot be
		// checked here. Every address it produces goes through the gate in the
		// targets stage, which is the only place that decision can be made.
		return nil

	case o.ListFile != "":
		seeds, ok := util.ReadLines(o.ListFile)
		if !ok {
			return usageErr("no readable targets in %s", o.ListFile)
		}
		for _, seed := range seeds {
			if !o.scope.Gate(seed, "") {
				return scopeErr("target is outside the configured scope: %s", seed)
			}
		}
		return nil

	default:
		// A domain may be a comma-separated list, or a path to a file of domains.
		for _, seed := range o.domainSeeds() {
			if !o.scope.Gate(seed, "") {
				return scopeErr("target is outside the configured scope: %s", seed)
			}
		}
		return nil
	}
}

// Seeds returns the individual target seeds this run will operate on.
//
// It is exported so the dry-run plan can show the real target list rather than
// the raw flag value, which may be a comma-separated list or a file.
func (o *Options) Seeds() []string {
	switch {
	case o.IPTarget != "":
		return []string{o.IPTarget}
	case o.ASN != "":
		return []string{o.ASN}
	case o.ListFile != "":
		seeds, _ := util.ReadLines(o.ListFile)
		return seeds
	default:
		return o.domainSeeds()
	}
}

// domainSeeds splits the -d value into individual targets.
func (o *Options) domainSeeds() []string {
	var out []string
	for _, part := range strings.Split(o.Domain, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		// A value naming a readable file is treated as a list, matching the
		// Bash flag documentation.
		if lines, ok := util.ReadLines(p); ok && len(lines) > 0 && util.ValidDomain(lines[0]) {
			out = append(out, lines...)
			continue
		}
		out = append(out, p)
	}
	return out
}

// Explain renders the scope decision for one target, for --why-denied.
func (o *Options) Explain(target string) string {
	if o.scope == nil {
		return "scope is not loaded, so no target can be authorised"
	}
	d := o.scope.Explain(target, "")
	verdict := "DENIED"
	if d.Allowed {
		verdict = "ALLOWED"
	}
	return verdict + ": " + target + "\n  reason: " + d.Reason
}
