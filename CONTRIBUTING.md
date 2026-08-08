# Contributing

## Getting set up

```sh
git clone https://github.com/zfouts/secretscrub
cd secretscrub
go test ./...
go build -o secretscrub ./cmd/secretscrub
```

Go 1.24 or newer (the floor is `testing.B.Loop` in the benchmarks). There are
no dependencies, and the only tooling is golangci-lint **v2** — the config is
v2 format and v1 cannot parse it:

```sh
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
golangci-lint config verify   # catches a bad config before CI does
```

## Before you open a PR

```sh
gofmt -l .        # must print nothing
go vet ./...
go test -race ./...
golangci-lint run # needs v2; config in .golangci.yml
```

If you touched the release config, check it builds before pushing a tag. A tag
is the only trigger, and a broken release has to be deleted and re-cut:

```sh
goreleaser check
goreleaser release --snapshot --clean --skip=sign
```

CI runs the same checks on Linux, macOS and Windows against the oldest
supported Go release (1.24) and the current one, plus `govulncheck`.

## What a good change looks like

**One rule, one sample, one commit.** Adding a token format is the most common
contribution and the easiest to review that way. See
[extending](docs/extending.md).

**Say what it changes for existing callers.** The library redacts everything
scoring 0.50 and above. If your change moves something across that line — a new
rule above it, a confidence lowered below it, a new name fragment — say so in
the commit message. That is behaviour change for everybody who imports this.

**Add the test that would have caught the bug.** Not a test that exercises the
code; the one that fails before your fix and passes after.

**Keep coverage above 98%.** CI enforces it. The number is not the point: it is
there so an exported function cannot gain no test at all, which is how
`RedactLabels` once shipped with zero coverage. If a branch genuinely cannot be
reached from a test, say so in a comment rather than writing a test that asserts
nothing.

**Document exported things in godoc style.** A doc comment leads with the
symbol's name and says what it does in a sentence or two; it becomes the public
API documentation on pkg.go.dev. Reasoning about why a branch exists belongs
inside the function, where maintainers read it and consumers do not. `revive`'s
`exported` rule enforces the first half.

**Samples must be synthetic.** Never commit a real credential, not even a
revoked one, and not in a test fixture. Every sample in `rules_test.go` is
shaped like the real thing and is not the real thing.

## Writing style

Comments here explain **why**, not what. The code says what it does; the comment
says what happens if you get it wrong. The existing ones name the concrete
failure — a specific field that came back as `<redacted>`, a signature that
reached an exported archive — because that is what stops the next person
"simplifying" a branch back into a bug.

```go
// Wrong: says what the line already says.
// Check if the name is on the allowlist.

// Right: says why the order matters.
// Checked first, and it short-circuits BOTH the name and value tests. A field
// can be named for a credential while holding a reference to one, and the
// reference is what downstream checks read.
```

Keep it proportional. A one-line helper does not need a paragraph; a tier
ordering does.

## Things to be careful with

**Do not loosen the payload path to fix a text-path problem.** `Redact`,
`RedactTree` and `RedactInline` run against captured API responses, where a
false positive silently destroys a stored field that something downstream reads.
`ScanText` and `RedactText` run against files, where the cost of a maybe is a
line of output. They deliberately use different priors — see `survivesInText` in
`textgate.go`. The existing suite will tell you if the two have been mixed up.

**Do not add a config file or a plugin hook.** The pattern set being one shared
implementation is the property this package exists to have: a gap fixed in one
copy is a gap left open in the others. New rules go in a `rules_*.go` file where they
get reviewed.

**Do not add a dependency.** This is a thing people run over their credentials.
Its supply chain should be readable in an afternoon.

**Do not print secrets.** Reports carry `Finding.Masked()`. `-show-secrets` is
the single deliberate exception, and it applies only to the text format.

## Reporting a false positive

Open an issue with the line that was flagged, the rule ID and the confidence:

```sh
secretscrub -format json path/to/file | head -40
```

Redact the value if it is real — the rule ID and the shape are what's needed.
Most false positives are fixed by a `safeNameFragments` entry or a text-gate
adjustment, and both want a regression test line.

## Reporting a miss

A credential format that gets through is more serious than one that over-fires.
Open an issue with the **format**, not the credential: the provider, the prefix,
the length, the charset, and a link to their docs if there is one. A synthetic
example is ideal.

## Reporting a security issue

Use [private vulnerability reporting](https://github.com/zfouts/secretscrub/security/advisories/new),
not a public issue, and see [SECURITY.md](SECURITY.md) for what qualifies.

Short version: a redaction bypass, a leak through the tooling, or anything that
corrupts a file goes through the private route. A format the detector simply
does not recognise is an ordinary bug — open a
[Missed credential](https://github.com/zfouts/secretscrub/issues/new?template=03-missed-credential.yml)
issue for that.

Never put a real credential in a public issue. Every issue template asks for a
synthetic reproduction instead, and the test suite is built entirely from
fabricated samples.

## Where things live

The package's files sit at the repository root, which is the Go convention for
a single-package library: the import path `github.com/zfouts/secretscrub` maps
to the root directory. Putting them under `pkg/` would make the import path
`github.com/zfouts/secretscrub/pkg/secretscrub`, which stutters and is a layout
the Go project has never endorsed. For comparison, cobra keeps 25 files at its
root and gopkg.in/yaml.v3 keeps 19; this package has 7.

The `_test.go` files sit beside the code for the same reason, except that this
one is a language rule rather than a convention. Go compiles a test file as
part of the package in its own directory, so an internal test can only reach
`classify` or `detectShape` from the root; moved into a `test/` directory it
fails to compile with `undefined: Detect`. Go permits exactly two packages per
directory — `secretscrub` and `secretscrub_test` — and `example_test.go` uses the
second. `encoding/json` keeps 24 test files next to its 15 source files for the
same reason; the standard library has no `test/` directory anywhere in it.

The one test directory the toolchain does recognise is `testdata/`, which holds
fixture *data* and is ignored during builds. There is none here yet.

Subdirectories are for things that are genuinely separate: `cmd/` for the
binary, `docs/` for prose, and `internal/` if we ever need code that must not
be importable.

| File | What it holds |
| --- | --- |
| `doc.go` | The package documentation |
| `classify.go` | **The tiered verdict — read this first.** Everything else feeds it or acts on what it returned |
| `confidence.go` | `Confidence`, the ladder, `Category` |
| `finding.go` | `Finding`, and the stable rule IDs a report keys on |
| `scanner.go` | `Scanner`, `Threshold`, `Meets`, `Detect` |
| `shape.go` | What a value says about itself, and telling `CHANGEME` from a weak password |
| `names.go` | The three fragment lists, the predicates over them, the `{Name, Value}` shape |
| `values.go` | Timestamps, resource paths, opaque runs, entropy |
| `redact.go` | `Redact`, `RedactLabels`, `RedactInline` |
| `redacttree.go` | `RedactTree` — the payload walker |
| `scantext.go` | `ScanText`, `ScanReader`, and finding `NAME = value` on a line |
| `textgate.go` | Why a source file needs a stricter prior than a payload |
| `redacttext.go` | `RedactText` — rewriting a document |
| `rules.go` | The `Rule` type and the composed registry |
| `rules_cloud.go` … | One group per domain: cloud, vcs, messaging, payment, saas, generic |
| `cmd/secretscrub/` | The command |
| `action.yml` | The GitHub Action, a composite that runs the released binary |
| `.pre-commit-hooks.yaml` | The pre-commit hooks |
| `.goreleaser.yaml` | How releases are built and signed |
| `docs/` | [usage](docs/usage.md), [library](docs/library.md), [extending](docs/extending.md), [auditing](docs/auditing.md) |

Every test file is named for the source file it covers.

### Why they are all in one directory

Because Go requires it: a package is a directory, and the import path
`github.com/zfouts/secretscrub` is the repository root. Putting the package
under `pkg/` would make consumers write
`github.com/zfouts/secretscrub/pkg/secretscrub`.

The only real lever is file count against file size, and both extremes are
worse than the middle. Six files meant a 563-line one nobody reads to the end;
twenty-nine meant a 26-line file whose name you had to already know. Twenty
files of 40–280 lines, each named for one job, is the balance. For scale,
spf13/cobra ships 25 files at its root and gopkg.in/yaml.v3 ships 19.

## Licence

By contributing you agree your work is licensed under Apache-2.0, the same as
the rest of the repository. New files carry the two-line header the existing
ones do:

```go
// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0
```
