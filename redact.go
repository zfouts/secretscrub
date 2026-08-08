// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import (
	"regexp"
	"strings"
)

// RedactedMarker replaces a value that looks like a credential.
//
// It is deliberately fixed and obviously synthetic. A redacted value is read
// downstream by things that were not told a redaction happened — a report, an
// export, an index, a diff — and every one of them has to be able to tell a
// removed value from a real one at a glance rather than by convention.
const RedactedMarker = "<redacted>"

// Redact returns the value to store for a key/value pair, and whether it was
// replaced with [RedactedMarker].
//
// The key is treated as naming the value directly. For a name inherited from an
// enclosing structure, which is only a hint, use [RedactInherited] or let
// [RedactTree] handle it.
func Redact(key, value string) (string, bool) {
	return defaultScanner.redact(key, false, value)
}

// Redact is [Redact] at this scanner's threshold.
func (s *Scanner) Redact(key, value string) (string, bool) {
	return s.redact(key, false, value)
}

// RedactInherited is [Redact] for a value whose name came from an enclosing
// structure rather than from its own key, so the name is treated as a hint and
// the value's shape decides.
//
// Most callers want [RedactTree], which applies this automatically. Use it
// directly when you are writing your own walker — one that interleaves its own
// pruning with the walk, say — and so need to redact a leaf at a time.
func RedactInherited(key, value string) (string, bool) {
	return defaultScanner.redact(key, true, value)
}

// RedactInherited is [RedactInherited] at this scanner's threshold.
func (s *Scanner) RedactInherited(key, value string) (string, bool) {
	return s.redact(key, true, value)
}

// redact applies the verdict from classify: at or above the threshold becomes
// the marker, below it is kept.
//
// The decision itself lives in classify. This is deliberately nothing but the
// threshold, so that what a scan reports and what a redaction removes can never
// drift apart — they are the same score read at the same cut.
func (s *Scanner) redact(key string, inherited bool, value string) (string, bool) {
	if s.Meets(s.classify(key, inherited, value)) {
		return RedactedMarker, true
	}
	return value, false
}

// RedactLabels returns a copy of an operator-authored string map — cloud tags,
// labels, annotations — with each value redacted under its own key. Keys are
// never redacted.
//
// Tags are the payload every provider carries and the easiest to forget,
// because they usually arrive alongside the response body rather than inside
// it. They are also written by people rather than by a schema, which makes them
// a first-class credential location: "db_password", a webhook URL pasted into
// "notify", a license key in "licence". A secret scrubbed out of a response and
// published in the tag beside it is the most misleading outcome available.
//
// Keys survive because the tag name is what people search and group by, and
// hiding it costs the whole point of having tags.
func RedactLabels(m map[string]string) map[string]string {
	return defaultScanner.RedactLabels(m)
}

// RedactLabels is [RedactLabels] at this scanner's threshold.
func (s *Scanner) RedactLabels(m map[string]string) map[string]string {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k], _ = s.redact(k, false, v)
	}
	return out
}

// Finding a credential inside a larger string: a script, an error message, a
// URL with a signature in its query.

// maxInlineScan bounds [RedactInline]. Scripts are usually a few KB; a
// megabyte-long blob is pathological, and scanning it on every value is not
// worth the cost.
const maxInlineScan = 64 << 10

// inlineAssignRe matches the NAME=value and NAME: value forms a credential
// takes inside a script or a config blob. The value stops at whitespace or a
// quote so only the secret is replaced.
//
// The name deliberately admits no "-", which is why a hyphenated query
// parameter is matched on its last segment: "X-Amz-Signature" is read as
// "Signature", and that is the half carrying the meaning.
var inlineAssignRe = regexp.MustCompile(
	`([A-Za-z_][A-Za-z0-9_]{2,63})(\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s;,)]+)`)

// RedactInline replaces credential assignments embedded inside a larger string,
// such as a startup script, an environment block or an error message. Only the
// value is replaced, so the surrounding text stays readable.
//
// Name and shape matching both work on a whole value, so neither catches a
// secret that is one line of a script. Strings longer than 64 KB are returned
// unchanged.
//
// For a whole document, where line and column matter and a bare credential may
// appear with no assignment around it, use [RedactText].
func RedactInline(text string) string { return defaultScanner.RedactInline(text) }

// RedactInline is [RedactInline] at this scanner's threshold.
//
// # Why two passes
//
// A URL hides an assignment from a single pass. The scan meets "https:" first,
// takes the entire remainder as that name's value, and because the match is
// consumed nothing after it is ever examined again — so a presigned request's
// X-Amz-Signature goes through untouched. That is not hypothetical: a signed
// URL inside a transport error gets stored, exported, and then emailed or
// attached to a ticket, and a presigned URL is bearer-equivalent.
//
// Splitting the string at the query separators puts each parameter in front of
// the detector on its own. The order of the two passes is easy to get backwards
// and expensive to get wrong: the WHOLE string is scanned first, so a credential
// whose value legitimately contains "?" or "&" ("PASSWORD=abc?def") is replaced
// as one value before any split can cut it in half and publish the tail. Only
// then is the result split and each segment rescanned. Rejoining on the same
// separator bytes makes the pass lossless, and because redaction is idempotent
// the second pass can never degrade what the first got right.
func (s *Scanner) RedactInline(text string) string {
	if len(text) > maxInlineScan {
		// A very large blob is not worth a full scan; the size is itself the
		// signal that it should not have been captured.
		return text
	}
	text = s.redactAssignments(text)

	var b strings.Builder
	b.Grow(len(text))
	start := 0
	for i := 0; i < len(text); i++ {
		if text[i] != '?' && text[i] != '&' {
			continue
		}
		b.WriteString(s.redactAssignments(text[start:i]))
		b.WriteByte(text[i])
		start = i + 1
	}
	if start == 0 {
		// No separators, so the segment pass would rescan the whole string to
		// reach the answer the first pass already gave.
		return text
	}
	b.WriteString(s.redactAssignments(text[start:]))
	return b.String()
}

// redactAssignments is one scan for NAME=value pairs, run by both of
// RedactInline's passes.
func (s *Scanner) redactAssignments(text string) string {
	return inlineAssignRe.ReplaceAllStringFunc(text, func(m string) string {
		loc := inlineAssignRe.FindStringSubmatch(m)
		// Security-related names count here where they would not on a
		// structured field. "ENCRYPTION_KEY=..." inside a startup script is an
		// assignment of key material, not an API returning an enum: the
		// NAME=value syntax is itself the evidence a structured payload does
		// not provide.
		if len(loc) < 4 || (!IsSensitiveName(loc[1]) && !IsSecurityRelatedName(loc[1])) {
			return m
		}
		return loc[1] + loc[2] + RedactedMarker
	})
}
