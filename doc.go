// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

/*
Package secretscrub detects credentials and redacts them.

It works on three kinds of input: a decoded API payload, where [RedactTree]
walks the structure; a document such as a config file, log or script, where
[ScanText] reports line and column and [RedactText] rewrites it; and a single
key/value pair, where [Redact] and [Detect] answer directly.

Every verdict carries a confidence from 0 to 1 rather than a yes or no.
[Detect] returns a [Finding] with that score and the rule that produced it,
and [Redact] is the same score compared against a threshold. A [Scanner] is a
threshold:

	clean := secretscrub.RedactTree("", payload)
	for _, f := range secretscrub.NewScanner(0.9).ScanText("app.env", text) {
		fmt.Printf("%s:%d %s (%v)\n", f.Path, f.Line, f.Rule, f.Confidence)
	}

Detection combines four signals. A registry of provider formats recognizes
credentials that identify themselves, such as an AWS access key id or a GitHub
token; see [Rules]. A list of field names recognizes credentials that do not,
which is the only way to catch a weak password. Shannon entropy scores whatever
neither of those claims, so an unknown provider's token is still caught as a
long opaque string. And a value that is none of those is decoded, in case it is
one of them in disguise: base64, hex, character arrays and \x escape runs are
unwrapped and the registry is run against the result, reported as, for example,
"base64:aws-access-key-id".

Redaction replaces values with [RedactedMarker] and preserves everything else:
structure for a payload, and line endings, quoting and indentation for a
document. It is idempotent, so re-scanning received data is safe and is
preferred to trusting the scan that produced it.

The package has no dependencies outside the standard library, and no mutable
package-level state; a [Scanner] is safe for concurrent use.

[Version] is the release this build came from. A consumer that redacts data
before shipping it should record that value alongside the result: redaction is
lossy on purpose and [RedactedMarker] is identical in every release, so nothing
in the output says which rules produced it. That matters the moment a redaction
gap is closed — v0.0.2 fixed a credential in an identity field being published
rather than redacted, and without a version recorded next to the data, artifacts
from before and after that fix are indistinguishable.

# Confidence

The scale is calibrated so the interesting thresholds fall between the rungs:

	0.90 - 0.99  a self-identifying provider format, or PEM key material
	0.85 - 0.99  a credential name whose value corroborates it
	0.80         a credential name alone
	0.65 - 0.95  a long opaque value, scored by measured entropy
	0.60         a security-related name beside encoded-looking material
	0.55         a credential name holding a placeholder, such as CHANGEME
	0.40 - 0.45  a shape shared with things that are not credentials

[DefaultMinConfidence] is 0.5, which keeps everything except the bottom rung.
Raise it for a quieter report, lower it to see what was ruled out.

# Scope

This detects credentials: keys, tokens, passwords, private key material,
connection strings and signatures. It is not a PII detector, and it does not
treat a certificate as a secret, since a certificate is the public half of a
key pair. It cannot recognize a credential format it has never seen, though
the entropy tier catches many of them anyway.

A command built on this package lives in cmd/secretscrub.
*/
package secretscrub
