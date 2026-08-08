# Using the library

```sh
go get github.com/zfouts/secretscrub
```

No dependencies, no `go.sum` entry to review. Everything below is in one
package; the files it is split across are listed in
[CONTRIBUTING](../CONTRIBUTING.md#where-things-live).

## Pick the entry point

| You have | Use |
| --- | --- |
| A decoded API response (`map[string]any`, `[]any`) | `RedactTree` |
| A file, a script, a log, a support bundle | `RedactText` / `ScanText` |
| A single key and value | `Redact` / `Detect` |
| A string that might contain a secret somewhere inside it | `RedactInline` |
| A tag or label map | `RedactLabels` |
| A stream you don't want to hold in memory | `ScanReader` |

## Redacting

```go
clean := secretscrub.RedactTree("", payload)   // returns a copy; structure preserved
text  := secretscrub.RedactText(contents)      // whole document, line endings intact
v, ok := secretscrub.Redact("DB_PASSWORD", v)  // ok reports whether it was replaced
tags  := secretscrub.RedactLabels(m)           // map[string]string, keys never touched
```

Replaced values become `secretscrub.RedactedMarker` (`"<redacted>"`).

`RedactTree` takes a `key` argument — the name the value arrived under, carried
down so a nested leaf is still judged by it. Pass `""` at the root:

```go
clean := secretscrub.RedactTree("", resp)          // no enclosing name
clean := secretscrub.RedactTree("DescribeX", resp) // name the call, if it helps
```

## Reporting instead of redacting

`Detect` is `Redact` without the redaction — same decision, same tiers, but you
get the score and the reason:

```go
f := secretscrub.Detect("STRIPE_KEY", value)
if f.Found() {
    log.Printf("%s (%s) confidence %.2f: %s", f.Rule, f.Category, f.Confidence, f.Masked())
}
```

```go
type Finding struct {
    Rule         string     // "aws-access-key-id", "credential-name", …
    Category     Category   // "cloud", "vcs", "payment", …
    Confidence   Confidence // 0 to 1
    Description  string     // one line of prose
    Key          string     // the name it arrived under, if there was one
    Path         string     // set by ScanText / ScanReader
    Line, Column int        // 1-based; zero for a key/value Finding
    Secret       string     // the match itself; excluded from JSON
}
```

`Confidence` is a defined `float64` and `Category` a defined `string`, so they
print and marshal as you would expect while staying distinct in a signature.

`Finding.Masked()` gives the head plus a fixed-width tail — safe to log, safe to
put in a ticket. `Finding.Secret` is there so you can hash or fingerprint it;
don't print it.

`Detect` returns findings **below** the threshold too — the score is the answer
it exists to give. The bulk calls (`ScanText`, `ScanReader`) apply the cut for
you. To apply it yourself, use `Meets`:

```go
s := secretscrub.NewScanner(0.9)
if f := s.Detect(key, value); s.Meets(f) {
    // above this scanner's threshold
}
fmt.Println(s.Threshold()) // 0.90
```

## Scanning text

```go
for _, f := range secretscrub.ScanText("deploy/.env", contents) {
    fmt.Printf("%s:%d:%d %s (%.2f)\n", f.Path, f.Line, f.Column, f.Rule, f.Confidence)
}

findings, err := secretscrub.ScanReader("big.log", r)  // same, over a stream
```

`ScanText` applies the threshold and returns findings in position order, at most
one per span. `RedactText` removes exactly what `ScanText` reports, at the same
cut — with one exception, template references (`${VAR}`), which are reported but
not rewritten.

## Choosing a threshold

The package-level functions cut at `DefaultMinConfidence` (0.5). For anything
else, make a `Scanner`:

```go
strict := secretscrub.NewScanner(0.9)   // near-certainties only
loose  := secretscrub.NewScanner(0.4)   // include the fuzzy tail

strict.ScanText(path, text)
strict.RedactTree("", payload)
strict.Redact(key, value)
```

Every package-level function has a `Scanner` method with the same name and
signature. The zero `Scanner` uses the default cut, so `&secretscrub.Scanner{}`
is valid.

Named rungs, if you'd rather not write bare numbers:

```go
secretscrub.ConfidenceCertain    // 0.95
secretscrub.ConfidenceHigh       // 0.80
secretscrub.ConfidenceMedium     // 0.60
secretscrub.ConfidenceLow        // 0.40
secretscrub.DefaultMinConfidence // 0.50
```

## Rules

```go
for _, r := range secretscrub.Rules() {
    fmt.Println(r.ID, r.Category, r.Confidence, r.Description)
}
```

`Rules()` returns a copy. The registry itself cannot be modified — one detector
is the point.

The findings that come from reasoning rather than a pattern have stable IDs too,
so a baseline file or a suppression list can key on them:

```go
secretscrub.RuleCredentialName          // "credential-name"
secretscrub.RulePlaceholder             // "credential-name-placeholder"
secretscrub.RuleSecurityNameOpaqueValue // "security-name-opaque-value"
secretscrub.RuleHighEntropyString       // "high-entropy-string"
secretscrub.RuleHexString               // "hex-string"
```

## Lower-level helpers

Useful when you're writing your own walker rather than using `RedactTree`:

| Function | Does |
| --- | --- |
| `IsSensitiveName(name)` | Name asserts its value is a credential |
| `IsSecurityRelatedName(name)` | Name mentions security — a hint, not a verdict |
| `IsSensitiveValue(value)` | Value looks like a credential, whatever it's called |
| `RedactInherited(key, value)` | Like `Redact`, but the name came from a parent, so it's only a hint |
| `PairLabel(m)` / `IsPairValueKey(k)` | Handle `{"Name": …, "Value": …}` records, where the operator's name is a sibling of the value |

## Worked examples

### Scrub an HTTP response before storing it

```go
var payload any
if err := json.Unmarshal(body, &payload); err != nil {
    return err
}
return store(secretscrub.RedactTree("", payload))
```

### Scrub an error before logging it

```go
log.Println(secretscrub.RedactInline(err.Error()))
```

`RedactInline` is the one for strings that are mostly prose — a transport error,
a shell command, a startup script — where the secret is one `NAME=value` inside
it. It reaches into query strings, so a presigned URL's signature goes.

### Fail a test if a fixture holds a credential

```go
func TestFixturesAreClean(t *testing.T) {
    b, _ := os.ReadFile("testdata/response.json")
    for _, f := range secretscrub.NewScanner(0.8).ScanText("testdata/response.json", string(b)) {
        t.Errorf("%s:%d %s (%.2f)", f.Path, f.Line, f.Rule, f.Confidence)
    }
}
```

### Custom walker

```go
func walk(key string, v any) any {
    switch t := v.(type) {
    case string:
        if secretscrub.IsSensitiveName(key) || secretscrub.IsSensitiveValue(t) {
            return secretscrub.RedactedMarker
        }
        return secretscrub.RedactInline(t)
    case map[string]any:
        for k, nested := range t {
            if shouldDrop(k) {
                delete(t, k)
                continue
            }
            t[k] = walk(k, nested)
        }
    }
    return v
}
```

Use `RedactInherited` rather than `Redact` when the name came from an enclosing
structure — a block named `encryption` should not turn the enum inside it into a
marker.

## Behaviour you can rely on

- **Idempotent.** Redacting twice changes nothing, and `RedactedMarker` is never
  itself reported as a finding. Re-scan on receipt.
- **Structure-preserving.** `RedactTree` only touches leaf strings. `RedactText`
  keeps line endings, quoting and indentation byte for byte.
- **Copy, not mutate.** `RedactTree` and `RedactLabels` return new values.
- **Concurrency-safe.** No mutable package state; a `Scanner` is read-only once
  built. Share one across goroutines.
- **Bounded.** `RedactInline` skips strings over 64 KB; the text scanner skips
  lines over 256 KB. A megabyte-long line is itself the signal.
