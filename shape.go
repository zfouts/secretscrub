// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import (
	"regexp"
	"strings"
)

// detectShape: what a value says about itself, with no name to help.

// detectShape reports what a value's shape says, with no name to help.
//
// Every rule that could apply is tried and the most confident wins, rather than
// the first to match. Two rules matching is normal for a nested format — a JWT
// inside a bearer header, a key inside a connection string — and the specific
// one is worth reporting.
func detectShape(value string) Finding {
	if value == "" || value == RedactedMarker {
		return Finding{}
	}
	if looksLikeResourceReference(value) {
		return Finding{}
	}
	if awsReservedSSOName.MatchString(value) {
		return Finding{}
	}

	if best := matchRules(value); best.Found() {
		return best
	}

	// Nothing claimed the value as written, so try it as an encoding of
	// something that would have been claimed. This has to come before the
	// generic tiers below or it never runs: hex-encoded key material is a long
	// hex run, and base64 of anything is high-entropy, so the fallbacks would
	// answer first and answer vaguely — "high-entropy-string" where
	// "base64:aws-access-key-id" was available.
	if f := detectObfuscated(value); f.Found() {
		return f
	}

	// No provider claimed it. Two generic shapes remain, both scored by how
	// random the value actually is rather than by a yes/no threshold — which is
	// the point of scoring them, since "long and opaque" is a spectrum running
	// from a bucket name to a raw key.
	if hexRunPattern.MatchString(value) {
		return Finding{
			Rule:        RuleHexString,
			Category:    CategoryGeneric,
			Confidence:  scaleConfidence(shannonEntropy(value), 3.0, 4.0, ConfidenceMedium, 0.85),
			Description: "long hex run, the shape of raw key bytes or an HMAC secret",
			Secret:      value,
		}
	}
	if opaqueTokenPattern.MatchString(value) && characterClasses(value) >= 3 {
		if h := shannonEntropy(value); h >= 4.0 {
			// Mixed case, digits, 32+ characters, near-random: an encoded key.
			// Real configuration values of that shape — bucket names, region
			// ids, ARNs, paths — fail the charset, the class or the entropy
			// test.
			return Finding{
				Rule:        RuleHighEntropyString,
				Category:    CategoryGeneric,
				Confidence:  scaleConfidence(h, 4.0, 5.5, 0.65, ConfidenceCertain),
				Description: "long opaque high-entropy string",
				Secret:      value,
			}
		}
	}
	return Finding{}
}

// awsReservedSSOName matches the role name AWS Identity Center generates for a
// permission set: AWSReservedSSO_<PermissionSetName>_<16 hex>.
//
// The trailing hex is what earned these an entropy score of 0.77–0.81, and the
// name half of the detector could not save them: identityContainer matches
// "_name" and snake_case, while the AWS SDK spells the field "RoleName". So the
// role name was redacted under RoleName while the identical string survived one
// field over inside its own Arn, which protects nothing and costs the field —
// and it hit precisely the SSO-provisioned roles an access review most needs to
// read.
//
// Exempted here rather than by name because the format is anchored and
// AWS-generated: nothing else can be shaped into it, and a credential cannot be
// hidden in it. A credential NAME still wins, since this only clears the shape
// tier.
var awsReservedSSOName = regexp.MustCompile(
	`^AWSReservedSSO_[A-Za-z0-9+=,.@_-]{1,64}_[0-9a-f]{16}$`)

// Recognising a value nobody has filled in yet, as against one somebody has.

// placeholderPattern matches a value standing in for one nobody has supplied.
// These populate example files, chart values and templates, and a scanner that
// reports them is a scanner whose output gets filtered out wholesale — taking
// the real findings with it.
//
// Anchored at both ends: a value that merely CONTAINS "example" is an ordinary
// value, and a secret is not made safe by being called one.
var placeholderPattern = regexp.MustCompile(`(?i)^(?:` +
	`[x*.\-_?]{3,}|` +
	`(?:your|my|our|the|a|an)[-_ ]?(?:[a-z]+[-_ ]?){0,3}(?:key|token|secret|password|pass|pwd|value|credential|here)s?|` +
	`(?:change|replace|insert|fill|set|put)[-_ ]?(?:me|this|it|in|here)?|` +
	`(?:todo|tbd|fixme|none|null|nil|na|n/a|empty|unset|undefined|example|sample|dummy|fake|test|testing|placeholder|redacted|removed|hidden|secret|password|passwd|pwd|token|apikey|api[-_]key|credentials?|foo|bar|baz|qux|abc123|password123)` +
	`)$`)

// templateMarkers are the interpolation syntaxes a value carries when it will
// be replaced at deploy time. The value in the file is a reference to a secret,
// not one — the same distinction that keeps a Kubernetes secretRef readable.
var templateMarkers = []string{"${", "{{", "<%", "%(", "$(", "#{"}

// looksPlaceholder reports whether a value is a stand-in rather than a secret.
func looksPlaceholder(value string) bool {
	v := strings.TrimSpace(value)
	if v == "" {
		return true
	}
	if placeholderPattern.MatchString(v) {
		return true
	}
	for _, m := range templateMarkers {
		if strings.Contains(v, m) {
			return true
		}
	}
	// A single character repeated carries no information, whatever it is.
	if strings.Count(v, v[:1]) == len(v) {
		return true
	}
	// "<anything>" is the universal spelling of a hole to be filled, and also
	// the spelling of this package's own marker.
	return strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">")
}
