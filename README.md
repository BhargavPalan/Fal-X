# Fal-X

![License: GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg)
![Go 1.27+](https://img.shields.io/badge/Go-1.27%2B-00ADD8?logo=go&logoColor=white)

Reconnaissance and attack-surface discovery. Fal-X maps an authorized estate,
enumerates what is exposed on it, and reports the result in a form you can hand
to someone else.

It is a security tool. A bare target is scanned directly, the way `nmap` or
`httpx` would. Pass `--scope` when you want a run held to an allowlist instead.

## Status

Under active development. The reconnaissance pipeline is complete and tested.
The later stages of the finding lifecycle are specified but not yet built:

| Area | State |
|---|---|
| Reconnaissance (domains, hosts, ports, HTTP, content, scan) | shipped |
| Vulnerability intelligence (CVE/KEV correlation) | planned |
| Asset graph and exposure matching | planned |
| Prioritization | planned |
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
```

`fal-x install` installs the external tools on every platform with `go
install`, which builds each one for the host operating system and architecture
automatically, so Linux, macOS and Windows on amd64, arm64 and the rest are all
covered by the one command. Tools are installed at their latest release and the
exact versions that land are recorded in `tools.lock`. It needs Go on PATH (1.27
or newer); `fal-x` itself is a standard `go build`.

`naabu`'s fast SYN scan needs [Npcap](https://npcap.com) on Windows; without it
naabu falls back to a slower CONNECT scan. `nmap` (optional, used only with
`--nmap`) is installed separately from <https://nmap.org/download>.

## Releases

Prebuilt binaries for Linux, macOS and Windows (amd64 and arm64) are attached to
each [GitHub Release](https://github.com/BhargavPalan/Fal-X/releases), alongside a
`checksums.txt` and a software bill of materials. Download the archive for your
platform, verify it against the checksum, and extract the binary.

Releases follow semantic versioning and are cut from signed git tags (`vX.Y.Z`).
The version, commit and build time are compiled into the binary; `fal-x version`
reports them:

```
fal-x 0.3.0
commit:   a1b2c3d4...
built:    2026-01-01T00:00:00Z
go:       go1.27.1
platform: linux/amd64
```

## Quick start

```sh
# Scan a target. This is the whole interface.
fal-x scan scanme.nmap.org

# See what a run would do, and what is missing. Contacts nothing.
fal-x scan scanme.nmap.org --dry-run

# Hold the run to an allowlist.
fal-x scan example.com --scope config/scope.txt

# Ask why a target would be allowed or denied. Contacts nothing.
fal-x scan --scope config/scope.txt --why-denied api.example.com
```

There is no "I have authorization" flag. You have already named the target, and
a flag people type reflexively stops being a signal.

## Targets

Exactly one of `-d`, `-l`, `-ip` or `-asn`:

```
-d example.com       one domain, a comma-separated list, or a file of domains
-l targets.txt       one domain per line
-ip 192.0.2.0/29     addresses or ranges, skipping domain discovery
-asn AS12345         an autonomous system, expanded to its netblocks
```

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
admin.example.com
```

```sh
fal-x scan example.com     # everything except the three above
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
3. `internal/util` owns all parsing. One host and URL parser, so a CIDR cannot
   be read two different ways in two different packages.
4. `internal/tools` is the only place an external binary is launched. Arguments
   are a string slice and never reach a shell.

## License

GPL-3.0. See [LICENSE](LICENSE).
