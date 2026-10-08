# Wordlists

Files here are data, not code, and they carry their upstream licences.

| File | Entries | Source | Licence |
|---|---|---|---|
| `subdomains.txt` | 20,000 | SecLists `Discovery/DNS/subdomains-top1million-20000.txt` | MIT |
| `content.txt` | 4,751 | SecLists `Discovery/Web-Content/common.txt` | MIT |
| `resolvers.txt` | 26 | curated list of well-known public recursive resolvers | factual data |

`resolvers.txt` was written for this project. The addresses are published
operational facts rather than anyone's creative work, so there is nothing to
attribute. It is kept as bare addresses with no comment header because `puredns`
reads it with a plain line reader.

The other two are fetched, not committed (`wordlists/*.txt` is gitignored). They
are unmodified apart from line endings, blank lines and duplicates.

## Fetching and updating

```
fal-x wordlists list              # show sources and what is present locally
fal-x wordlists fetch             # download any file that is missing
fal-x wordlists fetch --force     # re-download and replace existing files
fal-x wordlists fetch subdomains  # fetch one list only
```

`fetch` never overwrites an existing file without `--force`, writes to a temporary
file and renames it only after the download succeeds, and never touches
`resolvers.txt`, which is hand-curated.

Both fetched lists are MIT-licensed SecLists files, which is compatible with
Fal-X's GPL-3.0.

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