// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import (
	"math"
	"regexp"
)

// opaqueTokenPattern bounds the entropy test to values that could plausibly be
// an encoded key: one run of base64, base64url or hex characters, with no
// whitespace and no punctuation that would appear in an ARN, path or sentence.
var opaqueTokenPattern = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{32,}$`)

// semiOpaquePattern is opaqueTokenPattern with a shorter floor, used only once
// a security-related name has already made the value suspect. Twenty characters
// is below any enum a provider ships.
//
// "/" is excluded where opaqueTokenPattern allows it. At 32 characters a slash
// run is still plausibly base64, but in the 20-31 range it is overwhelmingly a
// resource path — a disk encryption set id, a KMS key ARN — and those are the
// references downstream code follows. Anything genuinely opaque enough to worry
// about clears the 32-character test on its own.
var semiOpaquePattern = regexp.MustCompile(`^[A-Za-z0-9+=_-]{20,}$`)

// hexRunPattern matches a long pure-hex value: raw key bytes, an HMAC secret,
// a digest.
var hexRunPattern = regexp.MustCompile(`^[0-9a-fA-F]{32,}$`)

// timestampPattern matches a machine-formatted date or point in time: a
// calendar date, optionally followed by a time, fractional seconds and a zone.
// That is ISO 8601 as every major provider emits it, with a space accepted in
// place of the "T" for the few APIs that use one.
//
// Anchored at both ends. A value that merely BEGINS with a date is not a
// timestamp, and exempting one would hand an attacker a prefix to hide behind.
var timestampPattern = regexp.MustCompile(
	`^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?\s*(Z|[+-]\d{2}:?\d{2})?)?$`)

// resourceReferencePattern matches a value that names another cloud resource by
// path.
//
// Google writes these constantly — machineType
// "zones/us-central1-a/machineTypes/e2-small", subnetwork
// "projects/p/regions/r/subnetworks/default" — and they are long enough, mixed
// enough and slash-dense enough to clear the opaque-token test. The result was
// arbitrary: "network" survived and "subnetwork" did not, because one happened
// to fall the right side of an entropy threshold.
//
// Anchoring on the leading collection segment is what keeps this narrow. A
// credential does not begin with "projects/" or "zones/", so an AWS secret key
// with slashes in it still redacts.
var resourceReferencePattern = regexp.MustCompile(
	`^(?:projects|zones|regions|global|locations|folders|organizations|billingAccounts)` +
		`/[A-Za-z0-9._\-]+(?:/[A-Za-z0-9._\-]+)*$`)

// looksTimestamp reports whether a value states when something happened.
func looksTimestamp(value string) bool {
	return timestampPattern.MatchString(value)
}

// looksLikeResourceReference reports whether a value is a path naming another
// resource rather than a credential.
func looksLikeResourceReference(value string) bool {
	return resourceReferencePattern.MatchString(value)
}

// looksSemiOpaque reports whether a value could be encoded credential material
// once a name has already made it suspect.
//
// Deliberately stricter on character classes than on length: provider enums run
// long ("EncryptionAtRestWithCustomerKey") but stay inside one or two classes,
// while encoded key material mixes case, digits and padding.
func looksSemiOpaque(value string) bool {
	return semiOpaquePattern.MatchString(value) &&
		characterClasses(value) >= 3 &&
		shannonEntropy(value) >= 3.5
}

// IsSensitiveValue reports whether a value looks like a credential regardless
// of what it is called: a recognized provider format, or an opaque
// high-entropy string.
//
// This is the boolean reading of [DetectValue] at [DefaultMinConfidence]. Use
// [DetectValue] when you want to know which credential it is, or how sure the
// detector was.
func IsSensitiveValue(value string) bool {
	return defaultScanner.Meets(detectShape(value))
}

// The two measurements the generic tiers score against.

// characterClasses counts how many of {lower, upper, digit, symbol} appear in
// s.
func characterClasses(s string) int {
	var lower, upper, digit, symbol bool
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			symbol = true
		}
	}
	n := 0
	for _, present := range []bool{lower, upper, digit, symbol} {
		if present {
			n++
		}
	}
	return n
}

// shannonEntropy returns the per-character entropy of s in bits. A random
// base64 string approaches 6.0; English text and identifiers sit well below 4.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]float64
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	total := float64(len(s))
	entropy := 0.0
	// Ranging over the array by value would copy 2 KB on every call, and this
	// is the hottest function in the package.
	for _, c := range &counts {
		if c == 0 {
			continue
		}
		p := c / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}
