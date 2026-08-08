# Security policy

## Reporting a vulnerability

Report privately, not as a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/zfouts/secretscrub/security/advisories/new)
on this repository.

Please include what the detector did, what you expected, and a **synthetic**
reproduction. Never send a real credential — the format, prefix, length and
charset are what's needed, and a fabricated example of the same shape is
strictly more useful.

Expect an acknowledgement within a week.

## What counts as a vulnerability here

This package is a control that other software relies on, so the serious bugs
are the ones that make it fail quietly.

**Report privately:**

- A **redaction bypass**: input the library claims to have redacted while the
  credential survives in its output. The dangerous shape of this bug is one
  where the output *reads* as scrubbed.
- A **leak through the tooling**: any path where a report, a log line or an
  error message prints a credential that was not passed `-show-secrets`.
- A **denial of service**: input that makes a pattern take superlinear time or
  memory. The patterns are RE2 and so have no catastrophic backtracking, but a
  pathological input that defeats the size bounds is still worth reporting.
- Anything that makes `-redact -w` **corrupt or truncate** a file rather than
  rewrite it.

**Open a normal issue instead** — these are ordinary bugs, not vulnerabilities:

- A credential format the detector does not recognize. It cannot recognize
  every format, and says so; see the known limits in
  [docs/auditing.md](docs/auditing.md).
- A false positive.
- A finding this package considers out of scope: PII, a public certificate, an
  identifier.

## Supported versions

The latest tagged minor release receives fixes. There is no long-term support
branch.

## What this package promises

- It has **no third-party dependencies**, so its supply chain is the Go
  standard library and this repository.
- It **never writes a credential to its own output** unless explicitly asked
  with `-show-secrets`. Reports carry a masked prefix.
- It **never sends anything anywhere**. There is no network code, no telemetry
  and no update check.
- Redaction is **idempotent**, so re-scanning received data is safe.

## What it does not promise

It is not a guarantee that data is clean. A detector that has never seen a
provider's token format will not recognize it, which is why the pattern set is
versioned and why callers are told to re-scan on receipt rather than trusting
the scan that produced a payload.
