# Auditing it

This is a thing you point at credentials. You should be able to check what it
does rather than take its word for it. Everything below is runnable.

## Start here

```sh
go run ./cmd/secretscrub -rules          # every pattern, with its confidence
go doc -all github.com/zfouts/secretscrub
go test ./...                           # includes runnable examples
go test -run '^$' -bench . ./...        # the hot paths, with allocations
```

The package is a set of small single-purpose files with no dependencies. The
one to read first is `classify.go`: it is the whole verdict, in about a hundred
lines, and everything else in the package either feeds it or acts on what it
returned.

```sh
wc -l *.go | sort -rn | head   # nothing over ~160 lines
```

`CONTRIBUTING.md` has the file-by-file map. Much of each file is comments
explaining why a branch is there.

```sh
go list -m all                                    # just this module
go list -deps ./... | grep '\.' | grep -v zfouts  # no non-stdlib packages
```

## Read the decision

The whole verdict is `Scanner.classify` in `classify.go`. It is four tiers,
checked in order, and every branch is commented with the case that put it there:

```
0.  Cannot be a credential.
    A timestamp; the RedactedMarker; a name on the allowlist.

1.  The value's OWN key says it is a credential.        → 0.80, or higher
    "password", "api_key". The only tier that catches a weak secret.

2.  The value looks like a credential whatever it is called.
    a. A registry rule claims it.                        → 0.45 - 0.99
    b. Or it decodes to something a rule claims.         → the inner score
    c. Or it is long, opaque and near-random.            → 0.60 - 0.95
    Skipped for identifier names — an account id is not a credential.

3.  A security-related name AND an encoded-looking value. → 0.60
    Neither half is conclusive on its own.
```

`Redact` is then `classify(...).Confidence >= threshold`. That is the entire
decision — one function of one number — which is what lets the command and the
library be guaranteed to agree.

## Check a specific value

```sh
echo 'password=hunter2'          | secretscrub
echo 'AKIAIOSFODNN7EXAMPLE'      | secretscrub -min-confidence 0
echo 'api_key=${FROM_VAULT}'     | secretscrub -min-confidence 0
```

Or in Go, where you also get the reason:

```go
f := secretscrub.Detect("api_key", value)
fmt.Printf("%s %s %.3f %q\n", f.Rule, f.Category, f.Confidence, f.Masked())
```

`Detect` returns findings below the threshold too, so `-min-confidence 0` shows
you everything the detector thought, including what it decided to ignore.

## Measure the false positive rate yourself

Point it at a large repository you know has no live credentials and count by
rule. The Go standard library works well — it is big, it is full of test
vectors, and it contains no real secrets:

```sh
secretscrub -format json /path/to/go/src | python3 -c '
import json, sys, collections
d = json.load(sys.stdin)
print(len(d["findings"]), "findings over", d["scanned_files"], "files")
for rule, n in collections.Counter(f["rule"] for f in d["findings"]).most_common():
    print(f"{n:6d}  {rule}")'
```

At the time of writing that is **215 findings over 10,382 files**, and almost
all of them are genuine credential shapes in test fixtures: Basic auth headers
in `cmd/go/internal/auth`, `http://user:pass@host` URLs in `net/url` tests, hex
test vectors under keys literally named `shared_secret`.

If a rule you added lands near the top of that list, it is matching something
that is not a credential.

## Measure what it misses

The other direction matters more. Take a corpus of known credential formats and
check the detector claims each one:

```sh
go test -run TestEveryRuleMatchesItsOwnFormat -v ./
```

That prints one line per rule. Each subtest asserts the rule matches a synthetic
sample of its own format **and** that the sample is attributed to that rule
rather than to a broader one.

## Effectiveness, measured

The suite plants every rule's sample into seven file contexts — env, shell,
Dockerfile, JSON, YAML, TOML, and bare with no name beside it at all — and
checks each one is still found once written into a file, which is where the text
gate, the assignment grammar and the line scanner all get a say:

```sh
go test -run 'InEveryContext|SurvivesAnEncoding|Lookalikes' -v ./
```

```
452/452 planted credentials found across 7 contexts
265/265 encoded credentials found
19 lookalikes across 4 contexts, none reported
```

Three things make that mean something:

- The name beside each planted value is deliberately uninformative
  (`UPLOADER`), so the name tier cannot do the shape rules' work for them.
- Every finding must also be *removed* by `RedactText`, so a rule that reports
  without redacting fails.
- The lookalikes are what a real repository is full of: git SHAs, sha256
  digests, UUIDs, ARNs, resource paths, image references, TLS policy names,
  timestamps, ULIDs. None may be reported, and none may be rewritten.

These numbers come from the fixed sample set, so they measure the registry
against formats it knows. They say nothing about a format it has never seen,
which by definition cannot be measured this way. For that, the honest figure is
the false-positive count on a real corpus above.

## The invariants the tests pin

The suite is written as a list of things that must stay true, each with the
failure that motivated it in a comment above it. The ones worth knowing:

| Test | Guarantees |
| --- | --- |
| `TestEveryRuleMatchesItsOwnFormat` | Every rule matches its own sample; the `Contains` prefilter agrees with the pattern; no rule is shadowed by a broader one |
| `TestConfidenceIsOrdered` | The ladder is ordered as documented, and everything on it is still redacted |
| `TestConfidenceDecidesRedaction` | The fuzzy tail is below the cut and the certainties are above it |
| `TestRedactionIsIdempotent` | A second pass changes nothing; the marker is not a finding |
| `TestMaskedNeverPrintsTheWholeSecret` | Reports keep a recognizable head, never the whole value, never the length |
| `TestSourceCodeIsNotAWallOfFindings` | Real Go source shapes produce zero findings, and real credentials in the same file still produce two |
| `TestRedactTextRemovesAWholePEMBlock` | A PEM body goes, not just its header |
| `TestRedactTextLeavesTemplateReferencesIntact` | `${VAR}` is reported but not rewritten |
| `TestReportsNeverCarryTheSecret` | No output format prints the credential unless `-show-secrets` |
| `TestScannerCutAppliesToBothHalves` | Findings and rewrites move together when the cut moves |
| `TestRedact_ProviderEnumsSurvive` | `"keySource": "Microsoft.Keyvault"` is not a secret |
| `TestIdentifiersSurviveRedaction` | A 32-hex account id is not a secret |
| `TestRedact_TimestampsAboutCredentialsSurvive` | `PasswordLastUsed` holds a date, not a password |

Coverage is 99% of statements, and CI fails below 98%:

```sh
go test -coverprofile=/tmp/c.out -covermode=atomic ./...
go tool cover -func=/tmp/c.out | tail -1
go tool cover -html=/tmp/c.out          # what is not covered, and why
```

The floor is there to catch an exported function that gains no test, not to
chase the last fraction. What remains uncovered is error handling on operations
that cannot be made to fail in a test: a stat that fails on an already-open
file, a read that fails after its own head read succeeded.

Supply chain, if you want to check that claim:

```sh
go list -m all                                    # just this module
go list -deps ./... | grep '\.' | grep -v zfouts  # no non-stdlib packages
ls go.sum                                         # does not exist
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

## Licence compliance

The project is Apache-2.0. `LICENSE` is the canonical text, identical to
[the published version](https://www.apache.org/licenses/LICENSE-2.0.txt) except
for the copyright line in the appendix; `NOTICE` records the holder; every Go
file carries a `SPDX-License-Identifier: Apache-2.0` header.

There is nothing inbound to be incompatible with, because there are no
third-party dependencies. Nothing but the Go standard library is linked into
the binary, and the standard library is BSD-3-Clause, which is permissive and
combines with Apache-2.0 without conditions. There is no `go.sum`, no `vendor/`
and no `//go:embed`.

The build and CI tooling is not distributed with the product and does not
affect its licence, but for a reviewer who wants the whole picture:

| Tool | Licence | Role |
| --- | --- | --- |
| Go standard library | BSD-3-Clause | The only thing linked into the binary |
| `actions/checkout`, `actions/setup-go` | MIT | CI only |
| `golangci/golangci-lint-action` | MIT | CI only |
| `golangci-lint` | **GPL-3.0** | A linter run over the source in CI |
| `govulncheck` (`golang.org/x/vuln`) | BSD-3-Clause | CI only |

golangci-lint being GPL-3.0 is the one line that tends to catch an eye in a
compliance review. It is a tool, not a dependency: it is never linked, never
redistributed, and reading source code does not make that source a derivative
work of the reader. The same reasoning applies to compiling with GCC. Nothing
GPL-licensed reaches a consumer of this module.

## Verify the two claims that matter

**A rewritten file scans clean.**

```sh
secretscrub -redact -w suspect.env
secretscrub suspect.env && echo "clean"
```

**A report never contains the credential.**

```sh
secretscrub -format json . | grep -F "$KNOWN_SECRET" && echo "LEAK" || echo "clean"
```

Both are also pinned by tests (`TestRedactRewritesInPlace`,
`TestReportsNeverCarryTheSecret`), but they take ten seconds to check by hand
and you should.

## Known limits

Read these as the scope, not as bugs.

- **An unquoted value containing a space is only partly seen.**
  `AUTH_HEADER="Bearer abc…"` is found; `AUTH_HEADER=Bearer abc…` is not,
  because the bare-value grammar stops at the space and the name alone is a
  security word rather than a credential word. Quoted values, and any name
  containing "authorization", are unaffected. Widening the grammar would
  reintroduce the bug where a credential's trailing content gets published
  after a split.
- **Encodings are unwrapped one level.** A credential hidden as base64, hex, a
  character array or `\x` escapes is found; the same credential encoded twice
  is not. The decode is matched against the registry rather than re-analysed,
  which is what keeps the recursion finite.
- **It cannot recognize a format it has never seen.** The entropy fallback
  catches long random-looking values; a short or structured token from an
  unknown provider gets through. Re-scan on receipt rather than trusting the
  scan that produced a payload.
- **It is not a PII detector.** Names, emails and device identifiers are out of
  scope by definition.
- **Certificates are not secrets.** `certificate-pem` scores 0.40, below the
  cut. A certificate is the public half of a key pair.
- **Identifiers are exempt from the value test.** An `id`, `uuid`, `etag` or
  `*_name` field is not shape-checked, because identifiers are high-entropy by
  design. A credential stored under a field literally called `id` would survive
  unless its name or shape gives it away.
- **The text scanner is calibrated to be quiet.** It requires more evidence than
  the payload path — see `survivesInText` in `textgate.go`. A credential written
  into source in an unusual shape may be reported at a lower cut only.
- **Size bounds are real.** `RedactInline` skips strings over 64 KB; the text
  scanner skips lines over 256 KB; the command skips files over `-max-size` and
  files containing NUL in their first 8 KB.
- **Binary formats are not parsed.** A key inside a `.p12`, a database file or a
  compiled object is not found.
- **`-all` is off by default.** `node_modules`, `vendor` and friends are not
  scanned unless you ask.

## Reviewing a change to this repo

- Does it change what is redacted **by default**? Anything crossing 0.50 in
  either direction changes behaviour for every library caller.
- Does a new rule have a sample in `rules_test.go`?
- Does its `Contains` prefilter agree with its pattern?
- Does a text-path gate leak into the payload path? It must not; the existing
  suite will say so.
- Did the false positive count on a large corpus move?
