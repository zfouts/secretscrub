# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is 0 the exported API may change between releases.

## [Unreleased]

### Fixed

- Documentation accuracy, from an audit that checked every claim against the
  code rather than re-reading the prose. Five things were wrong: the README's
  provider list omitted Firebase, PGP and kubeconfig, all of which have rules;
  `CONTRIBUTING`'s file map omitted `obfuscation.go` entirely; the JSON example
  in `docs/usage.md` showed a `key` field on an `aws-access-key-id` finding,
  which the tool cannot produce because that name is on the allowlist; the
  decision walkthrough in `docs/auditing.md` described tier two without the
  decoding step added with obfuscation detection; and `-rules` said the detector
  was "shape rules, plus name-based detection and entropy scoring", which has
  been three of four tiers since decoding was added.

### Fixed

- **An encoded credential after an assignment went unreported.** Base64 padding
  is `=`, so the scanner's candidate pattern allowed `=` anywhere, which let a
  candidate swallow the `NAME=` in front of it. The combined string decodes as
  neither base64 nor hex, so `BLOB=<hex>` reported nothing at all while
  `BLOB="<hex>"` reported correctly. Padding is now matched only as a trailing
  run.

- **`RedactText` could truncate a file.** A PEM `-----BEGIN …-----` marker
  quoted inside a line — in a JSON string, a log message, a test fixture — was
  read as the start of a key block. The rewriter wrote that line out verbatim,
  so the credential on it survived, and then swallowed every following line into
  a single marker while waiting for an `END` that never came. Under
  `-redact -w` that truncated the file. The delimiters are now anchored to the
  whole line, which is where a real PEM file puts them.

### Added

- Tests for the exported surface that had none: `RedactLabels`,
  `IsSensitiveValue`, and the `Scanner` methods for `RedactTree`,
  `RedactInherited` and `DetectValue`. Every package-level function had a test
  and none of its threshold-aware `Scanner` counterpart, so a method that
  ignored its threshold would have failed nothing.
- A coverage floor in CI. Statement coverage is 99% and the build fails below
  98%.
- Context tests. Every rule's sample is planted into seven file contexts and
  must still be found, and must also be removed by `RedactText`; the same for
  each of its encodings; and nineteen lookalikes across four contexts must be
  reported in none of them. 452/452, 265/265, and zero respectively.

### Removed

- A length check in the character-code decoder that could never fire, because
  the grammar it follows already requires twice as many values.

## [0.0.1] - 2026-08-08

First release.

### Detection

- A registry of 70 provider formats, each with a category, a confidence and
  prefilters, in one file per domain. Cloud: AWS, Azure, GCP, Alibaba,
  DigitalOcean, Cloudflare. Forges and registries: GitHub, GitLab, npm, PyPI,
  RubyGems, Docker Hub, NuGet, JFrog. Infrastructure: Terraform Cloud, Vault,
  SonarQube. Chat and mail: Slack, Discord, Teams, Telegram, SendGrid, Mailgun,
  Mailchimp, Twilio. Payments: Stripe, Square, Braintree, Shopify. SaaS:
  Atlassian, Linear, Notion, Asana, Dropbox, Figma, Postman, New Relic, Grafana,
  Databricks, Sentry, Okta. Model providers: Anthropic, OpenAI, Hugging Face,
  Replicate. Plus PEM and OpenSSH private keys, PuTTY and age keys, JWTs,
  authorization headers, connection strings with inline passwords and crypt(3)
  hashes.
- Name-based detection in three lists: names that are a credential, names that
  merely mention security, and an allowlist that beats both. This is the only
  tier that catches a weak password, which no shape test ever will.
- Entropy scoring for what neither claims, so an unknown provider's token is
  still found as a long opaque string.
- **Obfuscation detection.** A value nothing else claims is decoded and the
  registry is run against the result, so a credential hidden as base64, hex, a
  character array or a run of `\x` escapes is found and named, for example
  `base64:aws-access-key-id`. Only the named provider rules run against a
  decode, never the entropy tiers, because base64 of anything random decodes to
  something random. Findings carry the encoded text rather than the plaintext,
  so a report never prints what the encoding was hiding.

### Confidence

- Every verdict is a `Confidence` from 0 to 1 rather than a boolean. A
  self-identifying provider format scores 0.90 to 0.99, a credential name alone
  0.80, a long opaque value 0.65 to 0.95, a placeholder 0.55, and shapes shared
  with non-credentials 0.40 to 0.45.
- Entropy is mapped onto the scale continuously instead of compared against a
  constant, so a value a hundredth of a bit either side of a threshold is no
  longer either certainly a secret or certainly not.
- `Redact` is that score read against a threshold and a `Scanner` is a
  threshold, so what a scan reports and what a redaction removes cannot drift
  apart.

### Redacting and scanning

- `RedactTree` walks a decoded payload; `RedactInline` finds a credential inside
  a larger string and reaches into query parameters, so a presigned signature
  does not survive; `RedactLabels` handles tag maps.
- `ScanText` and `ScanReader` report line and column. `RedactText` rewrites a
  document, preserving line endings, quoting and indentation, and replacing PEM
  blocks whole.
- Documents are judged against a stricter prior than payloads, because "token"
  in source code is a word programs use for plenty of things that are not
  credentials. Without it the Go standard library produced 5,571 findings; with
  it, 215 over 10,382 files.

### Command

- `cmd/secretscrub` scans a tree or stdin and rewrites files with `-redact`.
  Text, JSON and SARIF output, `-min-confidence` to move the cut, `-exclude`
  globs, and parallel walking that skips vendored directories and binaries.
  Exit `0` clean, `1` found, `2` error. Reports carry a masked value, never the
  credential.

### Distribution

- **Release binaries.** Pushing a `v*` tag builds Linux, macOS and Windows
  archives for amd64 and arm64 with GoReleaser, attaches a `checksums.txt`, and
  verifies that the shipped binary runs before publishing. Builds are
  `-trimpath`, `CGO_ENABLED=0` and stamped with the tag.
- **Cosign signing**, keyless, over the checksum file. Skipped automatically
  while the repository is private, because keyless signing writes the repository
  path and tag into Sigstore's public transparency log. GitHub's native
  attestations were the alternative and are unavailable here: on the Free, Pro
  and Team plans they only work on public repositories.
- **A GitHub Action.** `uses: zfouts/secretscrub@v0.0.1` downloads the release
  binary for the runner, verifies its checksum before unpacking, and fails the
  step on a finding. Inputs for the path, version, threshold, format, output
  file, excludes and whether to block; outputs for the finding count and exit
  code.
- **Pre-commit hooks.** `secretscrub` for staged files, `secretscrub-strict`
  for near-certainties only, and `secretscrub-all` for the whole tree.

### Project

- No third-party dependencies: the module graph is empty and only the Go
  standard library is linked in. Apache-2.0, with NOTICE, SPDX headers on every
  file, and a licence compliance audit in `docs/auditing.md`.
- CI runs vet, race tests and gofmt on Linux, macOS and Windows against Go 1.24
  and stable, plus golangci-lint, govulncheck and a self-scan.
- Runnable examples, benchmarks for the hot paths, and documentation covering
  usage, the library API, extending the rule set and auditing the detector.

### Notes

Two deliberate decisions reduce what is redacted, both scored below the default
cut rather than removed:

- A **PEM certificate** is not treated as a secret. It is the public half of a
  key pair, and hiding it costs the chain, the issuer and the expiry while
  protecting nothing.
- An **AWS access key ID** under a name like `access_key_id` is treated as a
  reference rather than a credential; the secret access key beside it is what
  matters. The shape rule still reports the value wherever it appears in a
  document.

[Unreleased]: https://github.com/zfouts/secretscrub/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/zfouts/secretscrub/releases/tag/v0.0.1
