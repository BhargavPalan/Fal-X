# Wordlists

Files here are data, not code, and they carry their upstream licences.

| File | Entries | Source | Licence |
|---|---|---|---|
| `subdomains.txt` | 200,000 | [n0kovo/Subdomain-Scanner](https://github.com/n0kovo/Subdomain-Scanner) | GPL-3.0 |
| `content.txt` | 47,128 | SecLists `Discovery/Web-Content/common.txt` | MIT |
| `resolvers.txt` | 26 | curated list of well-known public recursive resolvers | factual data |

`resolvers.txt` was written for this project. The addresses are published
operational facts rather than anyone's creative work, so there is nothing to
attribute. It is kept as bare addresses with no comment header because `puredns`
reads it with a plain line reader.

The other two are unmodified apart from line endings, so a diff against upstream
shows only the change this repository made.

## Why GPL-3.0 matters here

Fal-X is GPL-3.0, which is compatible with `subdomains.txt` and therefore with
`content.txt`. Shipping both is fine. It would not be under the MIT licence the
project started with, which is one of the reasons the licence changed.

## Replacing them

None of these files are required. A stage that needs one reports its absence and
continues rather than failing the run, because a missing wordlist means less
coverage, not a wrong answer.

The paths are compiled-in defaults in `internal/config/config.go`. There is
currently no flag to point them elsewhere, so replacing one means replacing the
file in place.

| Stage | Uses |
|---|---|
| `subs`, when `--brute` is set | `subdomains.txt`, and `resolvers.txt` as the puredns resolver list |
| `content`, when `--dirs` is set | `content.txt` |

If `resolvers.txt` is absent, `puredns` falls back to the system resolver, which
is markedly slower and less reliable. The stage warns when it does.