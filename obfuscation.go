// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
)

// Credentials that were encoded rather than written out.
//
// Every rule in the registry matches a credential as its provider prints it,
// which is exactly what somebody hiding one from a scanner will avoid. An AWS
// key base64-encoded is 28 characters that match nothing, and one written as a
// character array is not even a single token. Neither is meaningfully harder to
// use than the original: a decode is one line of the program that reads it.
//
// So a value that could be an encoding is decoded and the registry is run
// against the result.

const (
	// minEncodedLen is the shortest input worth decoding. Below it there is no
	// room for a credential on the other side.
	minEncodedLen = 16

	// maxEncodedLen bounds the work. A megabyte blob is pathological and
	// decoding it on every leaf of every payload is not worth the cost.
	maxEncodedLen = 8 << 10

	// minPlaintextLen is the shortest decode worth testing. Anything shorter
	// cannot clear a rule's own length floor.
	minPlaintextLen = 8
)

// Encoding names, used as the prefix of an obfuscated finding's rule id:
// "base64:aws-access-key-id" says both what was found and how it was hidden,
// which is what a reader needs to know to go and fix it.
const (
	EncodingBase64    = "base64"
	EncodingHex       = "hex"
	EncodingCharCodes = "charcodes"
	EncodingEscapes   = "escapes"
)

// charCodeList matches a list of numeric byte values, in the spellings a
// source file writes one: [65, 75, 73], {0x41, 0x4b}, (65,75,73).
//
// The other three encodings are recognised by hand-written byte loops rather
// than by a pattern. This runs against every leaf of every payload, and a
// regexp costs a few hundred nanoseconds where a loop over twenty bytes costs
// a few: the overwhelmingly common answer is "not an encoding", and it should
// be cheap to reach.
var charCodeList = regexp.MustCompile(
	`^[\[{(]?\s*(?:0[xX])?[0-9a-fA-F]{1,3}(?:\s*,\s*(?:0[xX])?[0-9a-fA-F]{1,3}){15,}\s*[\]})]?$`)

// base64Alphabet classifies a value as base64 and reports which alphabet it
// used, so the decoder makes one attempt rather than four.
func base64Alphabet(s string) (*base64.Encoding, bool) {
	var padded, standard, urlSafe bool
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+', c == '/':
			standard = true
		case c == '-', c == '_':
			urlSafe = true
		case c == '=':
			padded = true
		default:
			return nil, false
		}
	}
	if standard && urlSafe {
		// No alphabet has both, so this is neither.
		return nil, false
	}
	switch {
	case urlSafe && padded:
		return base64.URLEncoding, true
	case urlSafe:
		return base64.RawURLEncoding, true
	case padded:
		return base64.StdEncoding, true
	default:
		return base64.RawStdEncoding, true
	}
}

// isHexRun reports whether s is an even-length run of hex digits.
func isHexRun(s string) bool {
	if len(s)%2 != 0 || len(s) < minPlaintextLen*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c|0x20 < 'a' || c|0x20 > 'f') {
			return false
		}
	}
	return true
}

// decoders are tried in order. Each returns the decoded bytes and whether the
// input was that encoding at all.
var decoders = []struct {
	name   string
	decode func(string) ([]byte, bool)
}{
	{EncodingBase64, decodeBase64},
	{EncodingHex, decodeHex},
	{EncodingCharCodes, decodeCharCodes},
	{EncodingEscapes, decodeEscapes},
}

// detectObfuscated reports a credential recovered by decoding value.
//
// Only the named registry rules are run against the plaintext, never the
// entropy tiers. That is a deliberate limit rather than an oversight: base64 of
// anything random decodes to something random, so scoring a decode by its
// entropy would report every encoded blob in every repository. A decode that
// produces "AKIA" followed by sixteen uppercase characters is a different
// matter, because random bytes do not do that.
//
// Running only the registry also makes the recursion finite: the decoded value
// is matched, not re-analysed, so an encoding of an encoding is found one level
// deep and no further.
func detectObfuscated(value string) Finding {
	if len(value) < minEncodedLen || len(value) > maxEncodedLen {
		return Finding{}
	}
	for _, d := range decoders {
		plain, ok := d.decode(value)
		if !ok || !plausiblePlaintext(plain) {
			continue
		}
		inner := matchRules(string(plain))
		if !inner.Found() {
			continue
		}
		return Finding{
			Rule:     d.name + ":" + inner.Rule,
			Category: inner.Category,
			// The encoding neither strengthens nor weakens what was found. A
			// provider prefix surviving a decode is as much proof as one
			// written out, and the caller still has the same credential to
			// rotate.
			Confidence:  inner.Confidence,
			Description: inner.Description + ", " + d.name + "-encoded",
			// The ENCODED text, not the plaintext: it is what appears in the
			// file, what a rewrite has to replace, and what a masked report
			// should show. Reporting the decoded secret would print in full
			// the thing the encoding was hiding.
			Secret: value,
		}
	}
	return Finding{}
}

// decodeBase64 decodes s under whichever base64 alphabet it is written in.
func decodeBase64(s string) ([]byte, bool) {
	enc, ok := base64Alphabet(s)
	if !ok {
		return nil, false
	}
	b, err := enc.DecodeString(s)
	return b, err == nil && len(b) >= minPlaintextLen
}

func decodeHex(s string) ([]byte, bool) {
	if !isHexRun(s) {
		return nil, false
	}
	b, err := hex.DecodeString(s)
	return b, err == nil && len(b) >= minPlaintextLen
}

// decodeCharCodes parses a list of numeric byte values. A bare number is
// decimal and an 0x-prefixed one is hex, which is how source files write them.
func decodeCharCodes(s string) ([]byte, bool) {
	// A list has commas. Checking for one before running the grammar keeps the
	// expensive pattern off every value that is not a list at all.
	if strings.IndexByte(s, ',') < 0 || !charCodeList.MatchString(s) {
		return nil, false
	}
	// No length check: charCodeList already requires sixteen values, which is
	// twice minPlaintextLen.
	fields := strings.Split(strings.Trim(strings.TrimSpace(s), "[]{}()"), ",")
	out := make([]byte, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		base, digits := 10, f
		if len(f) > 2 && (f[1] == 'x' || f[1] == 'X') {
			base, digits = 16, f[2:]
		}
		n, err := strconv.ParseUint(digits, base, 16)
		if err != nil || n > 255 {
			return nil, false
		}
		out = append(out, byte(n))
	}
	return out, true
}

// decodeEscapes reads a run of \xHH escapes.
func decodeEscapes(s string) ([]byte, bool) {
	// Every escape starts the same way, and almost nothing else does.
	if !strings.Contains(s, `\x`) {
		return nil, false
	}
	var out []byte
	for i := 0; i+3 < len(s)+1; {
		if i+4 <= len(s) && s[i] == '\\' && (s[i+1] == 'x' || s[i+1] == 'X') {
			n, err := strconv.ParseUint(s[i+2:i+4], 16, 8)
			if err != nil {
				return nil, false
			}
			out = append(out, byte(n))
			i += 4
			continue
		}
		return nil, false
	}
	return out, len(out) >= minPlaintextLen
}

// plausiblePlaintext reports whether decoded bytes could be a credential as
// written rather than the binary noise a wrong guess produces.
//
// Newline and tab are allowed because PEM key material carries them.
func plausiblePlaintext(b []byte) bool {
	if len(b) < minPlaintextLen {
		return false
	}
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// encodedCandidate finds the spans of a line that could be an encoding.
//
// The value-level tier only sees what an assignment hands it, and an encoded
// credential often is not the right-hand side of one: a character array is not
// a single token, and `const k = "QUtJQQ…"` has a name too short for the
// assignment grammar. A line-level pass is what makes the tier work on source.
var encodedCandidate = regexp.MustCompile(
	// A base64 or hex run. Padding is matched only as a trailing run, because
	// that is the only place base64 puts it — and allowing "=" anywhere let a
	// candidate swallow the "NAME=" in front of it, which is the commonest way
	// an encoded credential appears. The combined string decodes as neither
	// base64 nor hex, so the whole line went unreported.
	`[A-Za-z0-9+/_-]{16,}={0,2}` +
		// A run of \xHH escapes.
		`|(?:\\x[0-9a-fA-F]{2}){16,}` +
		// A bracketed list of numeric byte values.
		`|[\[{(]\s*(?:0[xX])?[0-9a-fA-F]{1,3}(?:\s*,\s*(?:0[xX])?[0-9a-fA-F]{1,3}){15,}\s*[\]})]`)

// obfuscatedSpans returns every encoded credential on a line, with its span.
func obfuscatedSpans(line string) []locatedFinding {
	var out []locatedFinding
	for _, m := range encodedCandidate.FindAllStringIndex(line, -1) {
		f := detectObfuscated(line[m[0]:m[1]])
		if !f.Found() {
			continue
		}
		out = append(out, locatedFinding{Finding: f, start: m[0], end: m[1]})
	}
	return out
}
