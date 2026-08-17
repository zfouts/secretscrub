# Using the command

```
secretscrub [flags] [path ...]
```

With no paths it reads standard input. Directories are walked. Findings go to
stdout, errors to stderr.

## Exit status

| Code | Meaning |
| --- | --- |
| `0` | Nothing found (or `-exit-zero`) |
| `1` | Credentials found |
| `2` | Something went wrong — bad flag, unreadable path, unknown format |

That is the whole CI interface: `secretscrub .` fails a build when it should.

## Flags

| Flag | Default | What it does |
| --- | --- | --- |
| `-min-confidence` | `0.5` | Report findings at or above this score |
| `-format` | `text` | `text`, `json` or `sarif` |
| `-redact` | off | Rewrite the input with credentials replaced instead of reporting |
| `-w` | off | With `-redact`, edit files in place instead of writing to stdout |
| `-exclude` | — | Skip paths matching a glob. Repeatable |
| `-all` | off | Descend into vendored and version-control directories |
| `-max-size` | `8388608` | Skip files larger than this many bytes |
| `-show-secrets` | off | Print credentials in full instead of masked (text format only) |
| `-quiet` | off | Findings only, no summary line |
| `-exit-zero` | off | Exit `0` even when credentials were found |
| `-rules` | — | Print the rule registry and exit |
| `-version` | — | Print the version and exit |

## What gets skipped

**Directories**, unless `-all`: `.git`, `.hg`, `.svn`, `node_modules`, `vendor`,
`.terraform`, `.venv`, `venv`, `__pycache__`, `.gradle`, `.idea`,
`.mypy_cache`, `.pytest_cache`.

They are skipped because they hold code you don't own. A finding in
`node_modules` is somebody else's to rotate, and burying the ones you can act on
underneath thousands you cannot is how a scanner gets turned off.

**Files**: anything with a NUL byte in its first 8 KB (binaries), anything over
`-max-size`, and any single line over 256 KB (minified bundles).

## Output formats

### text

Three lines per finding, then a summary:

```
path/to/file:LINE:COLUMN
  rule-id                          0.98  category
  KEY = AKIA************
```

The column points at the credential, not at the line, so an editor jump lands in
the right place. The `KEY =` prefix appears only when the finding came from a
named assignment.

### json

```json
{
  "detector": "secretscrub",
  "version": "dev",
  "scanned_files": 231,
  "findings": [
    {
      "path": "deploy/.env",
      "line": 2,
      "column": 19,
      "rule": "aws-access-key-id",
      "category": "cloud",
      "confidence": 0.98,
      "description": "AWS access key id",
      "masked": "AKIA************"
    }
  ]
}
```

`key` is present only when the finding came from a named assignment, which is
why it is absent above: `access_key_id` is on the allowlist, so the name tier
declines to speak and the shape rule answers alone.

### sarif

SARIF 2.1.0, for GitHub code scanning and anything else that annotates a diff.
Findings at `ConfidenceHigh` (0.8) and above are `error`; the rest are
`warning`. The confidence is also carried in `properties.confidence`.

## Reports never carry the secret

`json` and `sarif` emit `masked` — the first four characters and a fixed-width
tail. Enough to recognize which credential to rotate, never enough to use, and
the tail does not reveal the length.

`-show-secrets` is the deliberate exception and only applies to `text`, where a
human is looking at a terminal. A report is a thing people paste into tickets
and chat; a scanner that copies the credential into its own output has moved the
problem rather than found it.

## Redacting

```sh
secretscrub -redact file.env          # to stdout, file untouched
secretscrub -redact -w config/        # rewrite each file in place
cat messy.log | secretscrub -redact   # filter a stream
```

Values are replaced with `<redacted>`. Everything else survives byte for byte —
line endings, quoting, indentation — so the file still parses:

```yaml
# before                          # after
api-key: "AIzaSyD-1234…"          api-key: "<redacted>"
region: us-east-1                 region: us-east-1
```

PEM blocks are replaced as a block, with the `BEGIN` and `END` lines kept so you
can see what was removed:

```
-----BEGIN RSA PRIVATE KEY-----
<redacted>
-----END RSA PRIVATE KEY-----
```

Two things to know:

- **Template references are left alone.** `${DB_PASSWORD}` and
  `{{ .Values.token }}` are reported but not rewritten — replacing them breaks
  the file and protects nothing, because the reference was never the secret.
- **A rewritten file scans clean.** That is the contract, and it is pinned by a
  test. Redaction is also idempotent: running it twice changes nothing.

## Tuning the noise

Start at the default and raise the cut if the output is too long:

```sh
secretscrub -min-confidence 0.6 .   # drops placeholders and templates
secretscrub -min-confidence 0.9 .   # only self-identifying provider formats
secretscrub -min-confidence 0.4 .   # adds the fuzzy tail: certificates, 0x hashes
```

Then exclude what is genuinely noise for your repository:

```sh
secretscrub -exclude 'testdata/*' -exclude '*.min.js' -exclude 'fixtures' .
```

`-exclude` matches with [`filepath.Match`](https://pkg.go.dev/path/filepath#Match)
against both the full path and the base name, so `-exclude '*.pem'` and
`-exclude 'testdata'` both do what you expect.

## Recipes

### Pre-commit

There are three hooks, in [`.pre-commit-hooks.yaml`](../.pre-commit-hooks.yaml):

```yaml
repos:
  - repo: https://github.com/zfouts/secretscrub
    rev: v0.0.2
    hooks:
      - id: secretscrub          # staged files, default cut
      # - id: secretscrub-strict # staged files, near-certainties only
      # - id: secretscrub-all    # the whole tree; suits a pre-push stage
```

pre-commit builds the binary from source with the Go toolchain, so the hook
runs the same detector the library ships rather than a copy of its rules.

Start with `secretscrub-strict` on a repository that already has findings. A
hook that fails on the first commit is a hook people pass `--no-verify` around
forever.

If you would rather not depend on pre-commit, `.git/hooks/pre-commit`:

```sh
#!/bin/sh
git diff --cached --name-only --diff-filter=ACM | while read -r f; do
  [ -f "$f" ] || continue
  secretscrub -quiet "$f" || exit 1
done
```

### GitHub Actions

```yaml
- uses: zfouts/secretscrub@v0.0.2
```

The action downloads the release binary for the runner, verifies its checksum
before unpacking it, and fails the step when it finds something.

| Input | Default | What it does |
| --- | --- | --- |
| `path` | `.` | What to scan |
| `version` | `latest` | Which release to run. Pin it for a scan that cannot change under you |
| `min-confidence` | `0.5` | The cut |
| `format` | `text` | `text`, `json` or `sarif` |
| `output` | — | Write the report to a file instead of the log |
| `exclude` | — | Globs to skip, one per line |
| `all` | `false` | Descend into vendored directories |
| `fail-on-findings` | `true` | Set `false` to annotate without blocking |

Outputs are `findings` and `exit-code`.

Annotating an existing repository without blocking it, and feeding code
scanning:

```yaml
- uses: zfouts/secretscrub@v0.0.2
  with:
    min-confidence: "0.9"
    fail-on-findings: "false"
    format: sarif
    output: secretscrub.sarif
    exclude: |
      testdata/*
      *.min.js
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: secretscrub.sarif
```

### Scan only what changed

```sh
git diff --name-only origin/main... | xargs -r secretscrub
```

### Check one value by hand

```sh
echo 'password=hunter2' | secretscrub
echo 'AKIAIOSFODNN7EXAMPLE' | secretscrub -min-confidence 0
```

### Scrub a log before attaching it

```sh
secretscrub -redact support-bundle.log > support-bundle.clean.log
```

## Releases

Pushing a `v*` tag runs [the release workflow](../.github/workflows/release.yml),
which builds with [GoReleaser](../.goreleaser.yaml) for Linux, macOS and Windows
on amd64 and arm64, and attaches the archives plus a `checksums.txt`.

Verify a download:

```sh
sha256sum --check --ignore-missing checksums.txt
```

Releases from a public repository are also signed with cosign, keylessly, using
the workflow's OIDC identity. When `checksums.txt.pem` and `checksums.txt.sig`
are attached:

```sh
cosign verify-blob checksums.txt \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/zfouts/secretscrub/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Signing is skipped while the repository is private. Keyless signing writes the
repository path and tag into Sigstore's public, append-only Rekor transparency
log, which is fine for a public repository and a disclosure for a private one,
so the workflow decides from the repository's own visibility rather than
leaving it to whoever cuts the tag.

To reproduce a release build locally:

```sh
goreleaser release --snapshot --clean --skip=sign
```

The version is stamped by ldflags and appears in `-version` and in every JSON
and SARIF report, because a scan is only as good as the pattern set that
produced it.
