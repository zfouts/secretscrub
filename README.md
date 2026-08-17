# secretscrub

[![CI](https://github.com/zfouts/secretscrub/actions/workflows/ci.yml/badge.svg)](https://github.com/zfouts/secretscrub/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/zfouts/secretscrub.svg)](https://pkg.go.dev/github.com/zfouts/secretscrub)
[![Release](https://img.shields.io/github/v/release/zfouts/secretscrub?sort=semver)](https://github.com/zfouts/secretscrub/releases/latest)
[![Go](https://img.shields.io/github/go-mod/go-version/zfouts/secretscrub)](go.mod)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Finds credentials and removes them. A Go library, and a command you point at a
directory.

- **No dependencies.** Standard library only, no `go.sum`, no `vendor/`.
- **One detector.** The command and the library make the same decision from the
  same rules.
- **Scores, not booleans.** Every finding carries a confidence from 0 to 1, so
  you choose how noisy it is.
- **Sees through encodings.** A credential hidden as base64, hex, a character
  array or `\x` escapes is decoded and identified by name.

## Install

```sh
go install github.com/zfouts/secretscrub/cmd/secretscrub@latest
```

Or download a signed binary for Linux, macOS or Windows from the
[latest release](https://github.com/zfouts/secretscrub/releases/latest), or
build from a clone with `go build -o secretscrub ./cmd/secretscrub`.

### In GitHub Actions

```yaml
- uses: zfouts/secretscrub@v0.0.2
```

That fails the build when it finds something. To annotate without blocking, or
to feed code scanning:

```yaml
- uses: zfouts/secretscrub@v0.0.2
  with:
    min-confidence: "0.9"
    fail-on-findings: "false"
    format: sarif
    output: secretscrub.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: secretscrub.sarif
```

### As a pre-commit hook

```yaml
repos:
  - repo: https://github.com/zfouts/secretscrub
    rev: v0.0.2
    hooks:
      - id: secretscrub
```

`secretscrub` scans the staged files. `secretscrub-strict` reports only
self-identifying provider formats, which is the one to start with on a
repository that already has findings. `secretscrub-all` scans the whole tree.

## Use it

```sh
secretscrub .                          # scan a tree; exit 1 if anything is found
secretscrub -min-confidence 0.9 .      # only the near-certainties
secretscrub -format json . > out.json  # or -format sarif for CI annotations
secretscrub -redact -w config/         # rewrite the files with credentials gone
git diff | secretscrub                 # or read stdin
secretscrub -rules                     # everything it looks for
```

```
$ secretscrub deploy/
deploy/.env:2:19
  aws-access-key-id                0.98  cloud
  AKIA************

deploy/.env:3:13
  credential-name                  0.80  generic
  DB_PASSWORD = ************

2 credential(s) in 1 file(s), scanned 2
```

Exit status is `0` clean, `1` credentials found, `2` error.

## Use it as a library

```go
import "github.com/zfouts/secretscrub"

clean := secretscrub.RedactTree("", payload)     // walk a decoded API response
text  := secretscrub.RedactText(fileContents)    // rewrite a document
found := secretscrub.ScanText("app.env", text)   // report with line and column
f     := secretscrub.Detect("DB_PASSWORD", v)    // the verdict, with its score
```

## Confidence

| What was found | Score |
| --- | --- |
| A self-identifying provider format (`AKIA...`, `ghp_...`, a PEM private key) | 0.90 to 0.99 |
| A credential name whose value backs it up | 0.85 to 0.99 |
| A credential name alone, the only thing that catches `password: hunter2` | 0.80 |
| A long opaque value, scored by how random it actually is | 0.65 to 0.95 |
| A security-related name beside an encoded-looking value | 0.60 |
| A credential name holding a placeholder (`CHANGEME`, `${DB_PASSWORD}`) | 0.55 |
| A shape shared with things that are not credentials at all | 0.40 to 0.45 |

Default cut is **0.50**. Raise it with `-min-confidence`, or with
`secretscrub.NewScanner(min)` in code.

## What it looks for

70 formats. Run `secretscrub -rules` to print the list with a confidence for
each.

- **Cloud:** AWS, Azure, GCP, Firebase, Alibaba, DigitalOcean, Cloudflare
- **Forges and registries:** GitHub, GitLab, npm, PyPI, RubyGems, Docker Hub,
  NuGet, JFrog
- **Infrastructure:** Terraform Cloud, HashiCorp Vault, SonarQube
- **Chat and mail:** Slack, Discord, Teams, Telegram, SendGrid, Mailgun,
  Mailchimp, Twilio
- **Payments:** Stripe, Square, Braintree, Shopify
- **SaaS:** Atlassian, Linear, Notion, Asana, Dropbox, Figma, Postman,
  New Relic, Grafana, Databricks, Sentry, Okta
- **Model providers:** Anthropic, OpenAI, Hugging Face, Replicate
- **Key material:** PEM and OpenSSH private keys, PGP blocks, PuTTY keys, age
  keys, kubeconfig client keys, JWTs, authorization headers, connection strings
  with inline passwords, crypt(3) hashes

Plus the three that catch what no list can:

- a **name** that says its value is a credential, which is the only thing that
  finds `password: hunter2`
- a **value** that is long, opaque and near-random
- an **encoding** of any of the above. Base64, hex, character arrays and `\x`
  escapes are decoded and the registry runs against the result, so a key stored
  as `QUtJQUlPU0ZPRE5ON0VYQU1QTEU=` reports as `base64:aws-access-key-id`
  rather than as an anonymous blob.

## What it is not

- **Not a PII detector.** Names, emails and device identifiers are not secrets
  by this definition.
- **Not a certificate hider.** A PEM certificate is public material, so it
  scores below the default cut.
- **Not a guarantee.** It cannot recognize a token format it has never seen.
  Re-scan on receipt rather than trusting the scan that produced a payload.
  Redaction is idempotent, and the marker is not itself a finding.

## Docs

- [Using the command](docs/usage.md): every flag, output formats, CI recipes
- [Using the library](docs/library.md): the Go API, with examples
- [Extending it](docs/extending.md): adding a rule or a name
- [Auditing it](docs/auditing.md): how to check what it actually does
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)

## Licence

Apache-2.0. Copyright 2026 Zachary Fouts. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).

Nothing but the Go standard library is linked into the binary, so there is no
third-party licence to comply with. The build tooling and its licences are
listed under
[licence compliance](docs/auditing.md#licence-compliance).

## AI attribution

`AIA Human-AI blend, Stylistic edits, Human-initiated, Reviewed v1.0`

This work was created with an even blend of human and AI contributions. AI was
used to make stylistic edits, such as changes to structure, wording, and
clarity. AI was prompted for its contributions, or AI assistance was enabled.
AI-generated content was reviewed and approved.

Tags follow the [AI Attribution Toolkit](https://aiattribution.github.io/).
