// Package recon assembles the recon engine and the set of sources it drives.
//
// It is the one place that knows which sources exist, kept explicit rather than
// built from package init so each source's cost and credential needs are visible
// together.
package recon

import (
	"context"

	"github.com/BhargavPalan/Fal-X/internal/correlate"
	"github.com/BhargavPalan/Fal-X/internal/engine"
	"github.com/BhargavPalan/Fal-X/internal/exposure"
	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/origin"
	"github.com/BhargavPalan/Fal-X/internal/people"
	"github.com/BhargavPalan/Fal-X/internal/sources"
	"github.com/BhargavPalan/Fal-X/internal/sources/native"
	"github.com/BhargavPalan/Fal-X/internal/sources/pdtools"
	"github.com/BhargavPalan/Fal-X/internal/sources/premium"
	"github.com/BhargavPalan/Fal-X/internal/store"
)

// DefaultRegistry registers the available sources, in the order they should run.
func DefaultRegistry() *sources.Registry {
	reg := sources.NewRegistry()
	// Passive subdomain sources (free, no key). Several, so one being down does not
	// blind discovery.
	reg.Register(native.NewCT())              // crt.sh certificate transparency
	reg.Register(native.NewHackerTarget())    // hostsearch
	reg.Register(native.NewOTX())             // AlienVault OTX passive DNS
	reg.Register(native.NewAnubis())          // Anubis subdomain database
	reg.Register(native.NewSubdomainCenter()) // subdomain.center
	reg.Register(native.NewCertSpotter())     // certspotter issuances
	reg.Register(native.NewRapidDNS())        // rapiddns.io records
	reg.Register(native.NewURLScan())         // urlscan.io hosts
	reg.Register(native.NewWayback())         // web.archive.org historical URLs
	reg.Register(native.NewGrepApp())         // grep.app public-code references (repositories)
	reg.Register(native.NewHIBP())            // domain -> known breaches (passive, no key)
	reg.Register(native.NewM365())            // domain -> M365/Entra tenant, federation IdP (passive, no key)

	// Passive domain intelligence.
	reg.Register(native.NewRDAP()) // domain -> registration dates, contact emails

	// Active DNS: resolution, the zone's own records, and generated candidates.
	reg.Register(native.NewDNS())          // host -> addresses, CNAME
	reg.Register(native.NewDNSRecords())   // domain -> NS/MX/TXT/SPF/DMARC/BIMI/MTA-STS/DKIM/SRV, spoofability
	reg.Register(native.NewAXFR())         // domain -> full zone when a nameserver allows transfer
	reg.Register(native.NewNSEC())         // domain -> zone walk via NSEC chain (DNSSEC)
	reg.Register(native.NewPermute())      // domain -> likely subdomains (resolution prunes)
	reg.Register(native.NewDNSBrute())     // domain -> brute-forced subdomains (heavy, wildcard-filtered)
	reg.Register(native.NewRevDNS())       // ip -> PTR hostnames
	reg.Register(native.NewCloudBuckets()) // domain -> object-storage buckets (heavy)

	// Active host and service probing.
	reg.Register(native.NewCDNCheck())     // host -> cdn/waf/cloud verdict
	reg.Register(native.NewTLSCert())      // host -> certificate, SAN hosts, crypto posture
	reg.Register(native.NewHTTPProbe())    // host -> url, server/tech/headers, mined hosts/emails/secrets
	reg.Register(native.NewFavicon())      // host -> favicon mmh3 (sibling-infra pivot)
	reg.Register(native.NewJARM())         // host -> JARM TLS fingerprint (sibling-infra pivot, heavy)
	reg.Register(native.NewWebSurface())   // host -> robots/sitemap/security.txt
	reg.Register(native.NewWebSpec())      // host -> GraphQL introspection, OpenAPI/Swagger specs (heavy)
	reg.Register(native.NewCORS())         // host -> CORS misconfiguration findings
	reg.Register(native.NewExposedFiles()) // host -> exposed .git/.env/backups (heavy)
	reg.Register(native.NewTakeover())     // host -> confirmed subdomain takeover (body-signature)
	reg.Register(native.NewVhost())        // host -> virtual hosts served off DNS (heavy)

	// URL-level analysis.
	reg.Register(native.NewURLParams())  // url -> query parameters (inventory)
	reg.Register(native.NewBypass403())  // url -> access-control bypass findings (heavy)
	reg.Register(native.NewJSAnalysis()) // url -> JS endpoints, exposed source maps (heavy)

	// IP enrichment.
	reg.Register(native.NewASN())        // ip -> netblock, asn, operator (passive)
	reg.Register(native.NewInternetDB()) // ip -> ports, hostnames, CPEs, known CVEs (passive)
	reg.Register(native.NewPortScan())   // ip -> services (heavy, full mode only)

	// Shell-out tools: used when installed, skipped otherwise.
	reg.Register(pdtools.NewSubfinder())    // domain -> subdomains (aggregated passive)
	reg.Register(pdtools.NewGau())          // domain -> historical URLs (passive)
	reg.Register(pdtools.NewDNSx())         // host -> addresses, CNAME
	reg.Register(pdtools.NewHTTPX())        // host -> url, tech-detect, favicon
	reg.Register(pdtools.NewNaabu())        // ip -> open ports (heavy)
	reg.Register(pdtools.NewMasscan())      // ip -> open ports, internet-scale (heavy)
	reg.Register(pdtools.NewNmap())         // ip -> service, product/version (heavy)
	reg.Register(pdtools.NewFingerprintx()) // service -> non-HTTP protocol + banner
	reg.Register(pdtools.NewKatana())       // url -> crawled URLs, endpoints (heavy)
	reg.Register(pdtools.NewNuclei())       // url -> findings (heavy)
	reg.Register(pdtools.NewTrufflehog())   // repository -> verified secrets (heavy)

	// Premium engines: used when a key is present, skipped otherwise.
	reg.Register(premium.NewShodan())         // ip -> services, CPEs, known CVEs (keyed)
	reg.Register(premium.NewCensys())         // ip -> services, certificates (keyed)
	reg.Register(premium.NewSecurityTrails()) // domain -> subdomains (keyed)
	reg.Register(premium.NewVirusTotal())     // domain -> subdomains (keyed)
	reg.Register(premium.NewChaos())          // domain -> subdomains (keyed)
	reg.Register(premium.NewFullHunt())       // domain -> subdomains (keyed)
	reg.Register(premium.NewLeakIX())         // domain -> subdomains (keyed)
	reg.Register(premium.NewNetlas())         // domain -> subdomains (keyed)
	reg.Register(premium.NewZoomEye())        // domain -> subdomains (keyed)
	reg.Register(premium.NewGitHub())         // domain -> repositories via code search (keyed)
	reg.Register(premium.NewHunter())         // domain -> emails, people (keyed)
	return reg
}

// Options configures a run.
type Options struct {
	Seeds       []graph.Seed
	Brake       engine.Brake
	PassiveOnly bool
	// Full enables heavy sources (full port scan, brute force).
	Full bool
	Env  sources.Env
}

// Run builds the engine, drives it against the seeds, then correlates the graph. db
// must already be bound to the organization (via store.DB.WithOrg). Everything is
// written to the entity graph; match, prioritize and report read it directly.
func Run(ctx context.Context, db *store.DB, orgID int64, o Options) (engine.Stats, error) {
	e := &engine.Engine{
		Reg:         DefaultRegistry(),
		Committer:   engine.NewDBCommitter(db, orgID, 0),
		Brake:       o.Brake,
		Env:         o.Env,
		PassiveOnly: o.PassiveOnly,
		Full:        o.Full,
	}
	stats, err := e.Run(ctx, o.Seeds)
	if err != nil {
		return stats, err
	}
	// Correlate before exposure: a sibling edge can carry a takeover signal onto a
	// host the collection sources reached only indirectly.
	if err := correlate.Run(ctx, db, orgID); err != nil {
		return stats, err
	}
	if err := exposure.Run(ctx, db, orgID); err != nil {
		return stats, err
	}
	// People derivation reads the harvested emails and writes contacts; it sends no
	// packet, so it runs in every mode.
	if err := people.Run(ctx, db, orgID); err != nil {
		return stats, err
	}
	// Origin discovery probes the target directly, so it runs only when active sources
	// are permitted.
	if !o.PassiveOnly {
		if err := origin.Run(ctx, db, orgID, origin.NewHTTPProber()); err != nil {
			return stats, err
		}
	}
	return stats, nil
}
