# Fal-X

![License: GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg)
![Go 1.27+](https://img.shields.io/badge/Go-1.27%2B-00ADD8?logo=go&logoColor=white)

Fal-X turns what a scan finds into a ranked list of what to fix first. It maps an
authorized estate and enumerates what is exposed on it, which anyone with `nuclei`
and `httpx` can do; the part that is hard is what happens next. A scanner's
"medium" can carry a 99th-percentile exploitation probability, and a wall of
mediums is not a plan. Fal-X keeps every run in a database, joins the findings to
what the world knows about each CVE (CISA's known-exploited list, EPSS, NVD), and
ranks them, showing exactly why each one landed where it did. Reports come out as
Markdown, JSON or SARIF, in a form you can hand to someone else.

It is a security tool. A bare target is scanned directly, the way `nmap` or
`httpx` would. Pass `--scope` when you want a run held to an allowlist instead.

## Status

Under active development. Everything marked shipped below is built and tested;
the rest of the finding lifecycle is specified but not yet built:

| Area | State |
|---|---|
| Reconnaissance (domains, hosts, ports, HTTP, content, scan) | shipped |
| Reports (Markdown, JSON, SARIF) | shipped |
| Asset inventory in Postgres (`fal-x assets`) | shipped |
| Vulnerability intelligence (CISA KEV, EPSS, NVD on demand) | shipped; OSV planned |
| Asset graph and exposure matching | planned |
| Prioritization (`fal-x prioritize`) | first version shipped |
| Verification and gated exploitation | planned |
| Post-exploitation adapters | planned |
| Enterprise controls (multi-tenant API) | planned |

## Authorization and responsible use

Run Fal-X only against systems you own or have explicit written permission to
test. Active reconnaissance sends real traffic to real hosts; unauthorized use
may be illegal in your jurisdiction. You are responsible for staying inside the
scope you were granted.

The tool helps you stay inside it, but it is not a substitute for authorization:

- `--scope <file>` holds a run to an allowlist. When given, it is authoritative
  and fails closed: a named but unreadable file refuses rather than running wide.
- `config/out-of-scope.txt` is a denylist read automatically. A denylist entry
  always wins, including under `--allow-any`.
- Private, loopback, link-local, carrier-NAT and cloud-metadata ranges are
  denied even when an allowlist names them, unless you pass `--allow-private`.
- A target that reaches further than its name suggests (an autonomous system, a
  prefix wider than a `/22`, or a bare `*`) prompts for confirmation before
  anything is contacted. In a non-interactive context it refuses and asks for
  `--yes`.

## Install

Build the `fal-x` binary, then let it install the external tools it drives:

```sh
git clone https://github.com/BhargavPalan/Fal-X
cd Fal-X
go build -o bin/fal-x ./cmd/fal-x    # on Windows: go build -o bin\fal-x.exe .\cmd\fal-x

bin/fal-x install                    # installs the external reconnaissance tools
bin/fal-x install --check            # report what is present and missing
bin/fal-x install --with-opt         # also install the optional-stage tools
bin/fal-x install --setup            # only create the local config files
bin/fal-x wordlists fetch            # download the brute-force wordlists
```

`fal-x install` installs the external tools on every platform with `go
install`, which builds each one for the host operating system and architecture
automatically, so Linux, macOS and Windows on amd64, arm64 and the rest are all
covered by the one command. Tools are installed at their latest release and the
exact versions that land are recorded in `tools.lock`. It needs Go on PATH (1.27
or newer); `fal-x` itself is a standard `go build`.

The tools land in `$(go env GOPATH)/bin` (`~/go/bin`, or `%USERPROFILE%\go\bin` on
Windows), which must be on your PATH. `fal-x install --check` lists what is
present and what is missing. `amass` and `puredns` are optional and installed
only with `--with-opt`.

`naabu`'s fast SYN scan needs [Npcap](https://npcap.com) on Windows; without it
naabu falls back to a slower CONNECT scan. `nmap` (optional, used only with
`--nmap`) is installed separately from <https://nmap.org/download>.

### Wordlists

The brute-force stages (`--brute`, `--dirs`) read wordlists from `wordlists/`.
They are not committed; fetch them once after cloning:

```sh
fal-x wordlists list                 # sources, local entry counts, licences
fal-x wordlists fetch                # download any list that is missing
fal-x wordlists fetch --force        # re-download and replace existing lists
fal-x wordlists fetch subdomains     # one list only (subdomains, content)
```

Both lists come from [SecLists](https://github.com/danielmiessler/SecLists)
(MIT). `fetch` never overwrites an existing file without `--force`, so your own
edits are safe, and it swaps a file in only after the whole download succeeds.
Without a list, a stage that needs it reports so and carries on with less
coverage. See [wordlists/README.md](wordlists/README.md) for details.

## Quick start

```sh
# Scan a target. This is the whole interface.
# (scanme.nmap.org is a host the Nmap project provides for testing.)
fal-x scan scanme.nmap.org

# See what a run would do, and what is missing. Contacts nothing.
fal-x scan scanme.nmap.org --dry-run

# Hold the run to an allowlist.
fal-x scan example.com --scope config/scope.txt

# Ask why a target would be allowed or denied. Contacts nothing.
fal-x scan --scope config/scope.txt --why-denied api.example.com
```

## Reports

`fal-x report` turns a finished run into a document you can hand to someone else.
It only reads files the run already wrote, so it contacts nothing.

```sh
fal-x report                                   # newest run, as Markdown, to stdout
fal-x report --target example.com              # newest run of one target
fal-x report --run output/example.com/<stamp>  # a specific run
fal-x report --format json                     # machine-readable
fal-x report --format sarif --out findings.sarif   # for code-scanning tools
fal-x report --format md,json,sarif --out reports/ # several at once
```

A stage that never ran is reported as "not produced", with the reason from
`stages.json`, which is different from a stage that ran and found nothing.
Text that came from a scanned host (page titles, banners) is escaped, not
rendered.

There is no "I have authorization" flag. You have already named the target, and
a flag people type reflexively stops being a signal.

## Inventory

With a Postgres database, Fal-X keeps what every run finds as an inventory you can
query. Apply the schema once, then point it at the database:

```sh
fal-x migrate up --dsn postgres://user:pass@localhost:5432/falx
export FALX_DSN=postgres://user:pass@localhost:5432/falx

fal-x scan example.com                          # saved automatically when FALX_DSN is set
fal-x assets import --from output/example.com/<stamp>   # or save an earlier run
fal-x assets list --kind url
fal-x assets show example.com:443
```

Everything a run finds is kept: subdomains, resolved hosts, addresses, open
services, live pages with their title, server and technologies, every crawled URL,
and every finding. Importing a run twice changes nothing. Data is separated per
organization (`--org`, or `FALX_ORG`) with row-level security. Only `FALX_DSN`
makes a scan write to the database; `DATABASE_URL` and `PGDSN` are ignored for
that. The explicit commands (`assets`, `intel`, `prioritize`, `migrate`) also fall
back to those two when `--dsn` and `FALX_DSN` are absent. If the database is
unreachable the scan still completes and tells you how to import the run later.

Each organization's rows are hidden from every other by row-level security, which
is set per transaction. The `fal-x` commands do that for you (`--org`, or
`FALX_ORG`, default `default`). If you query the tables directly with `psql`, you
will see nothing until you set the tenant in your session:
`SELECT set_config('falx.org_id', '<org id>', false);`. That is the isolation
working, not a missing import.

## Vulnerability intelligence

Fal-X can hold the public feeds that say which CVEs are actually exploited, so a
finding is read next to what the world knows about it. It needs the same Postgres
database and no account or key:

```sh
fal-x intel sync                       # CISA KEV and EPSS; repeats download nothing if unchanged
fal-x intel enrich                     # CVSS from NVD, for the CVEs in your findings only
fal-x intel status
fal-x intel show CVE-2021-44228        # exploited? how likely? how severe?
fal-x intel search fortinet
fal-x assets show example.com:22       # findings now show their intelligence
```

CISA's Known Exploited Vulnerabilities list is the strongest signal that a CVE is
used in the wild; EPSS is the modelled probability of exploitation in the next 30
days. A scanner's "medium" can carry a 99th-percentile EPSS, which is exactly the
gap this closes. NVD is queried on demand for the CVEs in your findings (set
`NVD_API_KEY` for a higher rate limit); OSV is planned.

## Prioritization

`fal-x prioritize` ranks the findings you have stored, most urgent first, and shows
its working. Every point comes from a named signal and the reasons add up to the
score: the scanner's severity, whether the CVE is on CISA's Known Exploited list,
its EPSS probability, and a rating you give the asset.

```sh
fal-x assets criticality example.com:443 80    # your rating, 0 to 100
fal-x prioritize --explain
fal-x prioritize --format md --out ranked.md   # a document to hand over
```

The decision is Track, Attend or Act, a simplified reading and not CISA's full
decision tree. A known-exploited vulnerability is always Act, however the scanner
rated it. Exposure is not assessed yet, and every derivation says so.

## Targets

Exactly one of `-d`, `-l`, `-ip` or `-asn`:

```
-d example.com       one domain, a comma-separated list, or a file of domains
-l targets.txt       one domain per line
-ip 192.0.2.0/29     addresses or ranges, skipping domain discovery
-asn AS12345         an autonomous system, expanded to its netblocks
```

## Common options

```
--scope <file>       hold the run to an allowlist
--exclude <file>     denylist for this run (default: config/out-of-scope.txt)
--dry-run            validate inputs and print the plan; contacts nothing
--profile <name>     fast, normal or exhaustive
--stages <list>      run a comma-separated subset of the stages
--skip-scan          omit the nuclei vulnerability scanning stage
--ports <spec>       ports to scan, for example 80,443 or 8000-8100
--output <dir>       output root (default ./output)
--yes                answer the wide-target confirmation without prompting
```

Opt-in stages that send extra traffic: `--brute` (DNS brute force), `--dirs`
(directory brute force with ffuf), `--deep` (amass passive enumeration),
`--nmap` (service detection) and `--censys` (passive enrichment, needs a token
in `config/.env`). Run `fal-x scan --help` for the full list.

## Scope and exclusions

The allowlist is optional. Without one, every target you name is reachable.
Pass `--scope` to hold a run to a boundary. Entry syntax:

```
example.com          the domain and its subdomains
*.wild.test          subdomains only, not wild.test itself
192.0.2.0/24         an address range
2001:db8::1          an address
example.com:8443     one port on one host
```

To exclude specific hosts from any run, list them in `config/out-of-scope.txt`
(or point `--exclude` at another file):

```
staging.example.com
*.dev.example.com
```

```sh
fal-x scan example.com     # everything except the two above
```

## Output

```
output/<target>/<timestamp>/
  run.json          the run: target, profile, and the exact scope it was authorized under
  stages.json       per-stage status, duration, inputs, outputs
  1-roots/  ...  7-scan/
```

`stages.json` is the authority. An empty output file means the stage ran and
found nothing; a missing file means it never got that far. Do not delete empty
files to tidy up, because that erases the difference between a clean result and
a crashed stage.

## Exit status

| Status | Meaning |
|---|---|
| 0 | success |
| 1 | a stage or tool failed |
| 2 | bad usage or invalid input |
| 3 | refused: authorization or scope |

Trust the exit status over the word "done" in the log.

## Tools it drives

Fal-X drives established tools rather than reimplementing them: `httpx`,
`naabu`, `nuclei`, `subfinder`, `dnsx`, `amass`, `puredns`, `katana`, `gau`,
`ffuf` and `nmap`. It also queries RIPEstat and Censys directly.

A missing tool fails or skips its stage and is recorded as such. It never passes
unverified names forward as if they were live hosts.

## Configuration

Credentials and optional API tokens live in `config/.env`, parsed as data (never
evaluated). Copy the template and fill in what you have:

```sh
cp config/.env.example config/.env
```

Every value is optional; the tool degrades gracefully when a credential is
absent. `config/.env` is never committed.

## Development

```sh
make verify        # gofmt, go vet, build, tests
make test-race     # the packages with concurrency, under the race detector
```

Integration tests need a PostgreSQL database; set `FALX_TEST_DSN` to run them,
or they skip. `compose.yaml` brings up a suitable local database.

## Design

Four rules hold the authorization boundary in place:

1. `internal/scope` is the only code that decides reachability. No stage matches
   hosts on its own.
2. `internal/net` is the only place a request is issued, so the authorization
   check is unavoidable. Redirects are followed one hop at a time, with the gate
   applied to every hop.
3. Every host that reaches the authorization decision is parsed by
   `internal/util`, and nothing else. `scope` and `net` both reduce a target
   through `util.URLHost`/`util.URLPort`, so a CIDR or a userinfo string cannot
   be read one way by the gate and another by whatever dials it. Packages that
   parse a URL for their own reasons, such as `internal/net` resolving a
   `Location` header, are not making an authorization decision.
4. `internal/tools` is the only place a reconnaissance tool is launched.
   Arguments are a string slice and never reach a shell. The one other place
   that runs a subprocess is `internal/installer`, which shells out to the Go
   toolchain to build and version the tools themselves; it never touches a
   target.

## Releases

Prebuilt binaries for Linux, macOS and Windows (amd64 and arm64) are attached to
each [GitHub Release](https://github.com/BhargavPalan/Fal-X/releases), alongside a
`checksums.txt` and a software bill of materials. Download the archive for your
platform, verify it against the checksum, and extract the binary.

Releases follow semantic versioning and are cut from signed git tags (`vX.Y.Z`).
The version, commit and build time are compiled into the binary; `fal-x version`
reports them:

```
fal-x 0.2.0
commit:   a1b2c3d4...
built:    2026-01-01T00:00:00Z
go:       go1.27.1
platform: linux/amd64
```

## License

GPL-3.0. See [LICENSE](LICENSE).
