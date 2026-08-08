// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import (
	"regexp"
	"strings"
)

// The gate between a captured payload and a line of a document.
//
// The detector's tiers are calibrated for a decoded API response. A source file
// is not one, and applying that calibration unchanged to the Go standard
// library produced five thousand findings against 215 today.

// survivesInText decides whether a classification that holds for a captured
// payload also holds for a line of a document.
//
// The detector's tiers are calibrated for a decoded API response, where every
// key is a field name a provider chose, every value is data, and the base rate
// of credentials is high enough that over-redacting is the cheaper error. A
// source file is none of those things. "nextToken := s.readHeader()" is an
// assignment by the same syntax as "DB_PASSWORD=hunter2", "token" is a word
// programs use constantly for things that are not credentials, and a repository
// is full of digests, test vectors and base64 fixtures that are random by
// design. Applying the payload calibration to the Go standard library produces
// five thousand findings and no signal.
//
// So the same score is read against a different prior. A provider format still
// identifies itself and is reported wherever it appears; everything the
// detector inferred rather than recognized has to survive two extra questions —
// could this VALUE be a credential as written, and did a person write that NAME
// to label a value rather than to name a variable.
func survivesInText(f Finding, label, name, value string, quoted bool) bool {
	// "tokens: tokens" is a struct literal echoing a field name, not a value.
	if !plausibleLiteral(value, quoted) || (!quoted && (value == name || value == label)) {
		return false
	}
	switch f.Rule {
	case RuleCredentialName, RulePlaceholder:
		// A quoted value is a literal, which is most of what separates
		// `apiKey: "hunter2"` from `nextToken := s.next()`.
		if !quoted && !looksConfigName(label) {
			return false
		}
		if !IsSensitiveName(label) {
			// The name reached this tier through the SECURITY list rather than
			// the credential list — TLS_CERT, GOPRIVATE, SIGNING_MODE. In a
			// payload that promotion is right, because a person who writes
			// PRIVATE_KEY_PEM put a key in it and there is nothing else to look
			// at. In a document there is: the value. And a security-worded name
			// beside a path, a hostname or a mode flag is the overwhelming case.
			return couldBeEncoded(value) || looksPlaceholder(value)
		}
		return true
	case RuleHighEntropyString, RuleHexString:
		// Randomness alone means very little in a document. A blob nothing
		// names is a digest, a test vector or a chunk of minified output far
		// more often than it is a key, so the name has to corroborate.
		return looksConfigName(label) &&
			(IsSensitiveName(label) || IsSecurityRelatedName(label))
	case RuleSecurityNameOpaqueValue:
		return looksConfigName(label)
	}
	return true
}

// codeLiterals are values that are syntax rather than data.
var codeLiterals = map[string]bool{
	"nil": true, "null": true, "none": true, "true": true, "false": true,
	"undefined": true, "self": true, "this": true, "err": true, "nan": true,
	"void": true, "empty": true, "default": true,
}

// numericValue matches a value that is a number and therefore not a credential,
// in the bases a source file writes them in.
//
// The hex arm requires its 0x, which is the whole reason it is spelled out
// separately: a bare run of [0-9a-f] is a number in no language and a digest,
// an HMAC or a request signature in every one of them.
var numericValue = regexp.MustCompile(
	`^[-+]?(?:[0-9][0-9_]*(?:\.[0-9]+)?|0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+)$`)

// codeReference matches an unquoted value that is a program expression naming
// something else — "hs.masterSecret", "w.d.tokens", "dataSourceName".
//
// The camelCase arm is bounded in length because the two populations only
// diverge while they are short. "dataSourceName" is an identifier; a forty
// character run of mixed case is an encoded credential, and the shape alone
// stops telling them apart somewhere in between.
var codeReference = regexp.MustCompile(
	`^(?:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+|[a-z][a-z0-9_]*[A-Z][A-Za-z0-9_]{0,20})$`)

// plausibleLiteral reports whether a value could be a credential as written.
func plausibleLiteral(value string, quoted bool) bool {
	if len(value) < 6 {
		// Shorter than any credential worth reporting, and the length at which
		// ordinary code — flags, indices, single words — dominates entirely.
		return false
	}
	if codeLiterals[strings.ToLower(value)] || numericValue.MatchString(value) {
		return false
	}
	if quoted {
		return true
	}
	// Unquoted, so this line is as likely to be code as configuration, and a
	// value that is either expression syntax or a reference to something
	// elsewhere in the program is code.
	//
	// "&" and "|" are deliberately absent from that list even though "&&" and
	// "||" are operators. A bare value carrying an ampersand is a query string
	// far more often than it is a boolean expression, and excluding it would
	// cut "PASSWORD=abc?def&ghi" in half and publish the tail — the exact
	// failure the two-pass scan exists to prevent.
	return !strings.ContainsAny(value, "()[]{}<>!^%*") && !codeReference.MatchString(value)
}

// encodedValue matches a value with nothing in it but the characters an
// encoding uses. It is looser than looksSemiOpaque on length and on character
// classes, and stricter on charset — no dots, no spaces, no slashes — because
// what it has to separate is not "encoded" from "short" but "encoded" from the
// things a security-worded setting actually holds: a path, a hostname, a
// version, a mode. GOPRIVATE=vcs-test.golang.org/private and
// TLS_CERT=/etc/ssl/certs/ca.pem both die on the dot.
var encodedValue = regexp.MustCompile(`^[A-Za-z0-9+=_-]{12,}$`)

// couldBeEncoded reports whether a value might be encoded credential material.
func couldBeEncoded(value string) bool {
	return encodedValue.MatchString(value) && characterClasses(value) >= 2
}

// looksConfigName reports whether a name was written by a person to label a
// value rather than by a programmer to name a variable.
//
// The signal is casing, the same one looksOperatorAuthored uses and for the
// same reason: the two populations do not share a convention. Configuration
// keys are SCREAMING_SNAKE, kebab-case, snake_case or a single lowercase word —
// DB_PASSWORD, api-key, client_secret, password. Program identifiers in every
// language this is likely to meet are camelCase or PascalCase with no
// separator — nextToken, maxTokenSize, ErrFinalToken — and a hump with no
// separator is what tells them apart.
//
// Only the last dotted segment is judged, because "auth.token" and "s.token"
// are the same shape and the segment is what carries the meaning.
func looksConfigName(name string) bool {
	last := name[strings.LastIndexByte(name, '.')+1:]
	switch {
	case last == "":
		return false
	case strings.ContainsAny(last, "_-"):
		return true
	default:
		return last == strings.ToUpper(last) || last == strings.ToLower(last)
	}
}
