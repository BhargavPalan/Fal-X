# Fal-X

Fal-X is a self-driving attack-surface intelligence platform. You give it a seed —
a domain, a host, an IP — and it recursively discovers, enriches, correlates and
prioritises the exposed estate into a typed entity graph in Postgres: a subdomain
found in a certificate gets resolved, the IP it resolves to gets scanned, the
service it runs gets fingerprinted and matched against vulnerability intelligence,
and the whole thing is ranked by what actually needs attention.

Enumerating an estate is the part anyone with `httpx` and `nuclei` can do. The part
that is hard — and the part Fal-X is built around — is what happens next: resolving
the findings into one graph, correlating hidden infrastructure, confirming exposures,
tracing attack paths to the things worth stealing, and saying, with its working
shown, what to do first.

> Fal-X scans and probes live targets. Only run it against assets you are authorized
> to test. The only bound on recursion is a depth/budget brake, not an allowlist, so
> seed it deliberately.

## How it works

```
 seed ─▶ ENGINE (pub/sub work queue, depth/budget/fan-out brake, entity resolution)
           │  each entity is handed to every source that consumes its type
           ▼
   SOURCES  native (no key) · shell-out tools (when installed) · premium (when keyed)
           │  emit entities, typed edges and facts (one Collect = one transaction)
           ▼
   GRAPH    entity / entity_edge / entity_fact in Postgres, row-level security,
           │  provenance, confidence, corroboration and first/last-seen on every fact
           ▼
   ANALYSIS correlate (sibling infra) · exposure (takeover, leaks, …) · origin
           │  (real server behind a CDN) · people (contacts) · attack-path (entry → jewel)
           ▼
   INTELLIGENCE  CPE/version → CVE match ⨯ KEV/EPSS/NVD/OSV → attributed prioritisation
```

The engine is self-driving: a new entity is fed back in automatically, so one seed
unfolds into the whole reachable estate, bounded only by the brake.

## Quick start

```sh
# 1. Point at a Postgres 16 database and apply the schema.
export FALX_DSN="postgres://falx:falx@127.0.0.1:5432/falx?sslmode=disable"
fal-x migrate up

# 2. Scan a target you are authorized to test.
fal-x scan scanme.nmap.org --mode active --depth 2 --budget 200

# 3. Query what it found.
fal-x assets list                 # the discovered inventory
fal-x match                       # software → CVE matches
fal-x prioritize                  # ranked findings, with the score derived
fal-x paths --explain             # attack paths from a seed to a crown jewel
fal-x report                      # a markdown attack-surface report
```

A second scan of the same target shows what moved: `fal-x diff --since 24h` lists what
is new, gone or changed, and `fal-x monitor <seed…> --interval 6h` re-scans on a
schedule and alerts on each change. `fal-x verify` then re-checks the reported exposures
against the live target, read-only, and records whether each still holds.

## Scan modes

A mode selects which sources may run; the brake bounds how far recursion goes.

- `--mode passive` — no packets to the target. Certificate transparency, RDAP,
  passive DNS, archives, breach data, and keyed internet-scan engines build a graph
  from third-party data alone.
- `--mode active` (default) — passive, plus live DNS resolution, zone records,
  TLS/JARM grab, HTTP fingerprint, favicon, web-surface and exposure probing.
- `--mode full` — active, plus the heavy sources: full port scan, service/version
  detection, crawl, brute force, screenshots and cloud enumeration.

The brake is the only hard bound: `--depth` caps how many hops from a seed an entity
may be, `--budget` caps total work, and `--max-fanout` caps what one source may emit.

## Commands

```
fal-x scan <seed…> [--mode passive|active|full] [--depth N] [--budget N] [--org S]
fal-x assets   list | show <key> | criticality <key> <0-100>
fal-x match                      match the graph against the vulnerability data
fal-x prioritize                 rank stored findings by urgency, showing why
fal-x diff     [--since 24h|<RFC3339>]   new / gone / changed assets since a point
fal-x monitor  <seed…> [--interval 6h] [--webhook url]   re-scan on a schedule and alert
fal-x verify                     re-check reported exposures against the live target
fal-x paths    [--explain] [--chokes] | blast <key>   attack paths and choke points
fal-x report   [--format md|json|sarif]  render the findings
fal-x intel    sync | enrich | status | show <cve> | search <text>
fal-x migrate  up | down | status
fal-x version
```

Run `fal-x <command> --help` for a command's flags. Exit status follows the usual
contract: `0` ok, `1` runtime failure, `2` usage error.

## Sources

Sources are organised by what they need, and selected automatically by the entity
type they consume.

- **Native (no key, pure Go):** certificate transparency and passive-subdomain
  aggregators, Wayback, DNS resolution and full zone records (NS/MX/TXT/SPF/DMARC/
  SRV, mail posture), AXFR zone transfer and NSEC walking, reverse DNS,
  permutations and wordlist brute force, TLS certificate mining and native JARM,
  favicon mmh3, HTTP fingerprint with response/JS mining, GraphQL/OpenAPI discovery,
  CORS and 403-bypass checks, exposed-file probing, cloud-bucket enumeration,
  virtual-host discovery (apps served off DNS), JavaScript endpoint and exposed-
  source-map analysis, ASN/netblock lookup, subdomain-takeover confirmation, HIBP
  breaches, and Microsoft 365 tenant enumeration.
- **Shell-out tools (used when installed, skipped otherwise):** subfinder, gau,
  dnsx, httpx, naabu, masscan, nmap, fingerprintx, katana, nuclei, trufflehog.
- **Premium engines (used when a key is present):** Shodan, Censys, SecurityTrails,
  VirusTotal, Chaos, FullHunt, LeakIX, Netlas, ZoomEye, GitHub code search, Hunter.

Keys are read from the credential file, never from a flag and never logged.

## The graph and the intelligence on it

Everything is one typed graph. On top of it run the analysis passes that make it
more than an inventory:

- **Correlation** links sibling infrastructure by shared certificate, favicon, JARM,
  analytics id or nameserver — rarity-weighted (a value shared by two hosts counts
  for more than one shared by two hundred) and clustered transitively.
- **Exposure** turns facts into findings: subdomain takeover, leaked secrets, open
  buckets, dangling DNS, exposed `.git`/`.env`, weak or expired certificates, CORS
  misconfiguration, open zone transfer, breaches.
- **Origin discovery** finds the real server behind a CDN or WAF and confirms it by
  requesting the candidate IP with the host's own `Host` header.
- **People** turns the emails the sources harvested into contacts: a personal address
  becomes a named person linked to it, each address is classified as a role inbox or a
  person, and each estate domain's email-address format is inferred — all from data
  already in the graph, with no mail-server probing.
- **Attack paths** model the shortest abuse chains from a seed to a crown jewel
  (credentials, buckets, high-value or high-criticality assets), with the choke
  points that sever the most routes.

Confidence on a fact rises when independent sources corroborate it and decays as an
observation goes stale, so a fresh, multiply-sourced fact outweighs an old single
one. Vulnerability matching and prioritisation read the graph directly; every
prioritised score is a sum of named, plain-language reasons.

## Database

Fal-X needs Postgres 16. Every tenant table has row-level security FORCEd and is
scoped by a per-transaction `falx.org_id` setting, so one organisation's data is
never visible to another. `fal-x migrate up` applies the schema; `fal-x migrate
status` shows the ledger and detects out-of-band schema drift.

## Building and testing

```sh
go build ./...
go run ./devtools/verify          # fmt, vet, build, and the tests that need no DB
golangci-lint run --timeout=5m
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

The database-backed tests are skipped unless `FALX_TEST_DSN` points at a Postgres
instance; run them with `go test ./... -race -p 1` against one (they share a
database and serialise on an advisory lock).

## Layout

```
cmd/fal-x            the command line
internal/engine      the self-driving scheduler and brake
internal/sources     native, pdtools (shell-out) and premium source adapters
internal/graph       the typed entity graph and its store
internal/correlate   sibling-infrastructure correlation
internal/exposure    exposure detection
internal/origin      origin-IP-behind-CDN discovery
internal/people      contact and email-format derivation from harvested emails
internal/attackpath  attack-path and choke-point modelling
internal/match       CPE/version → CVE matching
internal/intel       vulnerability intelligence (KEV, EPSS, NVD, OSV)
internal/prioritize  attributed, SSVC-style ranking
internal/store       Postgres, migrations, row-level security, schema fingerprint
```
