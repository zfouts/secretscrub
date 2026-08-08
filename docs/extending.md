# Extending it

Four places to change, in the order you'll usually want them.

| I want to… | Edit |
| --- | --- |
| Recognize a new token format | `rules_<domain>.go` — add a `Rule` |
| Treat a new field name as a credential | `names.go` — `credentialNameFragments` |
| Stop a name being redacted | `names.go` — `safeNameFragments` |
| Fix a false positive in source files | `textgate.go` |
| Change the verdict itself | `classify.go` — read it first |
| Teach it a new encoding | `obfuscation.go` — add a decoder |

Everything is a plain Go value. There is no plugin system and no config file:
one detector, reviewed as code, is the property this package exists to have.

## Adding a rule

A `Rule` recognizes one credential format by shape alone. Rules live in one
file per domain — `rules_cloud.go`, `rules_vcs.go`, `rules_saas.go` and so on —
composed into the registry by `rules.go`. Add yours to the file its domain
already lives in.

```go
{
    ID:          "acme-api-key",
    Description: "Acme Corp API key",
    Category:    CategorySaaS,
    Confidence:  0.97,
    Contains:    "acme_",
    Pattern:     regexp.MustCompile(`\bacme_[A-Za-z0-9]{32}\b`),
},
```

| Field | Required | Notes |
| --- | --- | --- |
| `ID` | yes | Stable kebab-case. Reports, baselines and suppressions key on it |
| `Description` | yes | One line, for a human reading the finding |
| `Category` | yes | One of the `Category*` constants |
| `Confidence` | yes | See below |
| `Pattern` | yes | RE2. No backreferences, no lookaround |
| `Contains` | no | Lowercase substring the value must hold before the pattern runs |
| `Secret` | no | Submatch index holding the credential. `0` = whole match |
| `MinEntropy` | no | Floor the matched credential must clear |

### Choosing a confidence

Ask what the format itself proves.

| The format… | Score |
| --- | --- |
| …is a reserved prefix plus a fixed length. Nothing else can hold it | 0.97 – 0.99 |
| …is distinctive but conceivably innocent | 0.88 – 0.95 |
| …is a prefix shared with ordinary identifiers, or bare length-and-charset | 0.70 – 0.85 |
| …is also the shape of something that is not a credential at all | 0.40 – 0.45 |

The last row is the **fuzzy tail**: below `DefaultMinConfidence`, so it is
reported only to someone who lowered the cut, and never redacted by default. Put
a rule there rather than leaving it out — `certificate-pem` and
`hex-private-key-0x` live there.

### Anchor it

The pattern runs against whole values *and* against individual lines of files.
Anchor at both ends when the format allows:

```go
// Wrong in a document. Fires on every line beginning with the word "Basic".
regexp.MustCompile(`(?i)^(?:bearer|basic|token)\s+\S{8,}`)

// Right. Both ends anchored, charset spelled out.
regexp.MustCompile(`(?i)^(?:bearer|basic|token)\s+[A-Za-z0-9+/=_.~-]{8,}$`)
```

Where you need context to be sure, capture just the secret with `Secret`:

```go
{
    ID: "azure-storage-account-key", Confidence: 0.98,
    Contains: "accountkey=",
    Pattern:  regexp.MustCompile(`(?i)AccountKey=([A-Za-z0-9+/=]{60,})`),
    Secret:   1,   // so a rewrite keeps "AccountKey=" and drops only the key
},
```

### The `Contains` prefilter

`Contains` is checked before the pattern, so **it must agree with it or the rule
never fires**. The registry runs against every leaf of every payload, and a
substring search is much cheaper than seventy regexes.

- It is matched against the value **lowercased**, so write it lowercase even
  when the pattern is case-sensitive: `Contains: ":aa"` for `\d{8,10}:AA…`.
- If a pattern has two alternative prefixes with no shared literal, leave it
  empty. A filter covering one alternative silently switches the other off.
- `TestEveryRuleMatchesItsOwnFormat` checks this for you.

### If you add a new group file

A format that grows past a few entries can have its own `rules_<name>.go` with
its own `<name>Rules` slice. Add it to the `slices.Concat` in `rules.go` — and
if you forget, `TestEveryRuleGroupIsRegistered` fails, because a group nobody
concatenates is a group whose every rule silently stops existing.

### Add a sample — this is required

Every rule needs an entry in `samples` in `rules_test.go`:

```go
"acme-api-key": "acme_" + rep("aB3xY9zQ", 4),
```

The test then asserts three things: the prefilter appears in the sample, the
pattern matches its own sample, and `DetectValue` attributes the sample to
**this** rule and not a broader one. A rule with no sample fails the suite.

Samples must be synthetic. They are shaped like the real thing and are not the
real thing.

### Check it doesn't over-match

```sh
go test ./...
go run ./cmd/secretscrub -format json /path/to/a/large/checkout | \
  python3 -c 'import json,sys,collections; d=json.load(sys.stdin); print(collections.Counter(f["rule"] for f in d["findings"]))'
```

If your rule's count jumps out, it is matching something that is not a
credential. See [auditing](auditing.md) for the corpus method.

## Adding an encoding

`obfuscation.go` decodes a value that no rule claimed and runs the registry
against the result, so a credential hidden as base64, hex, a character array or
a run of `\x` escapes is still named. To add another, append to `decoders`:

```go
{EncodingRot13, decodeRot13},
```

A decoder returns the decoded bytes and whether the input was that encoding at
all. Three rules for writing one:

- **Guard it cheaply.** It runs against every leaf of every payload, so the
  answer "not this encoding" has to be reached without a regexp where possible.
  The existing three use hand-written byte loops; the character-array grammar is
  a pattern, gated behind a `strings.IndexByte(s, ',')`.
- **Do not widen it to the entropy tiers.** Only the named provider rules run
  against a decode. Scoring a decode by its entropy would report every base64
  string in every repository, because base64 of anything random decodes to
  something random.
- **Report the encoded text as the secret**, never the plaintext. It is what a
  rewrite has to replace, and printing the decode would publish the thing the
  encoding was hiding.

## Adding a name

Three lists in `names.go`, checked in this order, with the predicates over them
in the same file.

**`safeNameFragments`** — wins over everything. Names that contain a credential
word but describe a non-secret: `key_arn`, `public_key`, `secret_name`,
`ssl_policy`, `http_tokens`. A field that *references* a credential is not one,
and something downstream needs to read it.

**`credentialNameFragments`** — a match redacts on the name alone, whatever the
value looks like. This is the only thing that catches `password: hunter2`. Use
it for words that are credentials: `password`, `token`, `secret`, `apikey`,
`dsn`, `passphrase`.

**`securityNameFragments`** — a match only *lowers the bar* the value has to
clear. Use it for words that mention security without being credentials:
`encrypt`, `cert`, `key`, `session`, `sign`.

Getting the second and third confused is the expensive mistake. Cloud APIs use
security words overwhelmingly for enums and references — `"keySource":
"Microsoft.Keyvault"`, `"KeyState": "Enabled"` — and because `RedactTree` carries
a parent's name down to its leaves, putting `key` on the credential list would
silence everything inside any block named `encryption`.

Fragments are matched **case-insensitively as substrings**, so check what else
they hit. `auth` matches `AUTHOR`; that is why `author_` is on the safe list.

`identityContainer` in `names.go` is a fourth, narrower list: names holding
an identifier (`id`, `uuid`, `etag`, `*_name`). It exempts the value-shape tier
only — identifiers are high-entropy by design and authorize nothing.

## Tuning the text gate

`survivesInText` in `textgate.go` decides whether a classification that holds for a
captured payload also holds for a line of a document. It exists because the
detector's tiers are calibrated for a decoded API response, and applying that
calibration unchanged to source code produced **5,571 findings on the Go
standard library** against 215 today.

The helpers, all in `textgate.go`:

| Helper | Rejects |
| --- | --- |
| `plausibleLiteral` | Values under 6 chars, numbers in any base, `nil`/`true`/`null`, unquoted expression syntax |
| `codeReference` | Unquoted `hs.masterSecret`, `dataSourceName` — identifiers, not data |
| `looksConfigName` | `nextToken`, `MaxTokenSize` — camelCase humps with no separator are variables, not config keys |
| `couldBeEncoded` | Paths, hostnames and mode flags beside a security-worded name |

If you're fixing a false positive, add a line to
`TestSourceCodeIsNotAWallOfFindings` in `textgate_test.go` first. It is a list of real shapes from the
Go standard library and it is the right place for the next one.

Careful: these gates apply **only** to the text path. They must not change what
`Redact` or `RedactTree` do to a payload, and the existing suite will tell you
if they have.

## Changing a confidence

Two things depend on where a score sits:

1. Anything at or above `DefaultMinConfidence` (0.50) is **redacted by default**.
   Moving a rule across that line changes library behaviour for every caller.
2. `ConfidenceHigh` (0.80) is the SARIF `error`/`warning` boundary.

Both directions have a cost. Lowering a score below the cut stops something
being redacted; raising one above it starts redacting something that was
readable. Say which in the commit message.
