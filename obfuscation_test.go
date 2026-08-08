// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// encodings returns every way this package knows how to hide s.
func encodings(s string) map[string]string {
	var codes []string
	var esc strings.Builder
	for _, b := range []byte(s) {
		codes = append(codes, fmt.Sprintf("%d", b))
		fmt.Fprintf(&esc, `\x%02x`, b)
	}
	return map[string]string{
		EncodingBase64:    base64.StdEncoding.EncodeToString([]byte(s)),
		"base64-rawurl":   base64.RawURLEncoding.EncodeToString([]byte(s)),
		EncodingHex:       hex.EncodeToString([]byte(s)),
		EncodingCharCodes: "[" + strings.Join(codes, ", ") + "]",
		EncodingEscapes:   esc.String(),
	}
}

// A credential that has been encoded is not a credential that has been
// protected: whoever reads it decodes it in one line. Every rule in the
// registry matches a credential as its provider prints it, which is exactly
// what somebody hiding one will avoid.
func TestEncodedCredentialsAreFound(t *testing.T) {
	for _, secret := range []string{
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_1234567890abcdefghijklmnopqrstuvwx",
		"sk_live_4eC39HqLyjWDarjtT1zdp7dc",
		"xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx",
	} {
		plain := DetectValue(secret)
		if !plain.Found() {
			t.Fatalf("%q is not detected even in the clear", secret)
		}
		for encoding, encoded := range encodings(secret) {
			t.Run(encoding+"/"+plain.Rule, func(t *testing.T) {
				got := DetectValue(encoded)
				if !got.Found() {
					t.Fatalf("%s-encoded %s was missed entirely", encoding, plain.Rule)
				}
				// The report has to name the credential, not just say
				// "something encoded": the reader's next step is to rotate a
				// specific key at a specific provider.
				if !strings.HasSuffix(got.Rule, ":"+plain.Rule) {
					t.Errorf("reported as %q, want an encoding of %q", got.Rule, plain.Rule)
				}
				if got.Category != plain.Category {
					t.Errorf("category %q, want %q", got.Category, plain.Category)
				}
				if got.Confidence != plain.Confidence {
					t.Errorf("confidence %v, want the inner rule's %v", got.Confidence, plain.Confidence)
				}
			})
		}
	}
}

// The finding carries the encoded text, not the plaintext. Reporting the decode
// would print in full the thing the encoding was hiding, which is the one
// output this package must never produce.
func TestAnEncodedFindingNeverCarriesThePlaintext(t *testing.T) {
	const secret = "AKIAIOSFODNN7EXAMPLE"
	for encoding, encoded := range encodings(secret) {
		f := DetectValue(encoded)
		if f.Secret != encoded {
			t.Errorf("%s: Secret is %q, want the encoded text", encoding, f.Secret)
		}
		if strings.Contains(f.Secret, secret) || strings.Contains(f.Masked(), secret) {
			t.Errorf("%s: the decoded credential leaked into the finding", encoding)
		}
	}
}

// Only the named registry rules run against a decode, never the entropy tiers.
// Base64 of anything random decodes to something random, so scoring a decode by
// its entropy would report every encoded blob in every repository.
func TestDecodingDoesNotResurrectTheEntropyTiers(t *testing.T) {
	for _, plaintext := range []string{
		"hello world, this is an ordinary configuration value",
		"the quick brown fox jumped over the lazy dog twice",
		strings.Repeat("data", 20),
	} {
		for encoding, encoded := range encodings(plaintext) {
			f := DetectValue(encoded)
			if strings.Contains(f.Rule, ":") {
				t.Errorf("%s of %q was reported as an encoded credential: %s",
					encoding, plaintext[:16], f.Rule)
			}
		}
	}
	// A bare list of small numbers is a list of small numbers.
	if f := DetectValue("[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]"); f.Found() {
		t.Errorf("an ordinary integer array was reported as %q", f.Rule)
	}
}

// The tier is one level deep by construction: the decode is matched against the
// registry rather than re-analysed. Pinned so the limit is a decision somebody
// made rather than a surprise somebody finds.
func TestDoubleEncodingIsOutOfScope(t *testing.T) {
	once := base64.StdEncoding.EncodeToString([]byte("AKIAIOSFODNN7EXAMPLE"))
	twice := base64.StdEncoding.EncodeToString([]byte(once))
	if !DetectValue(once).Found() {
		t.Fatal("single encoding should be found")
	}
	if f := DetectValue(twice); strings.Contains(f.Rule, ":") {
		t.Errorf("double encoding was decoded twice, which the tier does not promise: %s", f.Rule)
	}
}

// Finding an encoded credential is worth little if it then survives redaction.
func TestEncodedCredentialsAreRedacted(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("AKIAIOSFODNN7EXAMPLE"))

	if got, redacted := Redact("blob", encoded); !redacted {
		t.Errorf("Redact left it in place: %q", got)
	}

	tree := RedactTree("", map[string]any{"payload": encoded}).(map[string]any)
	if tree["payload"] != RedactedMarker {
		t.Errorf("RedactTree left it in place: %v", tree["payload"])
	}

	line := "const key = \"" + encoded + "\"\n"
	found := ScanText("app.go", line)
	if len(found) != 1 || !strings.HasPrefix(found[0].Rule, EncodingBase64+":") {
		t.Fatalf("ScanText got %d findings: %+v", len(found), found)
	}
	if clean := RedactText(line); strings.Contains(clean, encoded) {
		t.Errorf("RedactText left it in place: %q", clean)
	}
}

// A character array spans an assignment rather than sitting inside quotes, so
// it is worth pinning that the whole literal is claimed.
func TestCharacterArrayInSource(t *testing.T) {
	var codes []string
	for _, b := range []byte("AKIAIOSFODNN7EXAMPLE") {
		codes = append(codes, fmt.Sprintf("%d", b))
	}
	value := "[" + strings.Join(codes, ", ") + "]"

	f := DetectValue(value)
	if !strings.HasPrefix(f.Rule, EncodingCharCodes+":") {
		t.Fatalf("character array reported as %q", f.Rule)
	}
	// Hex spellings too, which is how a C or Go source file usually writes one.
	var hexCodes []string
	for _, b := range []byte("AKIAIOSFODNN7EXAMPLE") {
		hexCodes = append(hexCodes, fmt.Sprintf("0x%02x", b))
	}
	if f := DetectValue("{" + strings.Join(hexCodes, ", ") + "}"); !strings.HasPrefix(f.Rule, EncodingCharCodes+":") {
		t.Errorf("hex character array reported as %q", f.Rule)
	}
}

// Decoding runs on every leaf of every payload, so the bounds matter.
func TestDecodingIsBounded(t *testing.T) {
	if f := DetectValue(strings.Repeat("QUtJQQ", 4000)); f.Found() && strings.Contains(f.Rule, ":") {
		t.Error("a blob past maxEncodedLen was decoded anyway")
	}
	if f := DetectValue("QUtJQQ=="); strings.Contains(f.Rule, ":") {
		t.Error("an input below minEncodedLen was decoded anyway")
	}
}

// The value-level tier only sees what an assignment hands it, and an encoded
// credential in source often is not the right-hand side of one. Both of these
// were missed until a line-level pass was added, and both passed a unit test
// written against ScanText with a longer variable name, which is why they are
// pinned as source lines rather than as values.
func TestEncodedCredentialsInSourceLines(t *testing.T) {
	for _, line := range []string{
		// A name too short for the assignment grammar.
		`const k = "QUtJQUlPU0ZPRE5ON0VYQU1QTEU="`,
		// A character array is not one token, and the bare-value grammar stops
		// at the first comma.
		`const h = [65, 75, 73, 65, 73, 79, 83, 70, 79, 68, 78, 78, 55, 69, 88, 65, 77, 80, 76, 69]`,
		// No assignment at all.
		`// see 414b49414 note: QUtJQUlPU0ZPRE5ON0VYQU1QTEU= was rotated`,
	} {
		found := ScanText("app.go", line)
		if len(found) == 0 {
			t.Errorf("missed the encoded credential in:\n  %s", line)
			continue
		}
		if !strings.HasSuffix(found[0].Rule, ":aws-access-key-id") {
			t.Errorf("reported as %q:\n  %s", found[0].Rule, line)
		}
		if clean := RedactText(line); strings.Contains(clean, "QUtJQUlPU0ZPRE5ON0VYQU1QTEU=") {
			t.Errorf("RedactText left it in place: %q", clean)
		}
	}
}

// Ordinary source is full of long identifiers and hashes that sit inside the
// base64 alphabet. None of them decode to a credential, and the line pass must
// not start reporting them.
func TestTheLinePassIsQuietOnOrdinarySource(t *testing.T) {
	code := strings.Join([]string{
		`func TestEncodedCredentialsAreFoundAndReported(t *testing.T) {`,
		`	const sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"`,
		`	buf := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18}`,
		`	url := "https://example.com/a/very/long/path/segment/here/ok"`,
		`}`,
	}, "\n")
	for _, f := range ScanText("x.go", code) {
		if strings.Contains(f.Rule, ":") {
			t.Errorf("ordinary source reported as encoded: %s at line %d", f.Rule, f.Line)
		}
	}
}

// An encoded credential most often appears as the right-hand side of an
// assignment, and the candidate scanner has to stop at the separator.
//
// Base64 padding is "=", so the candidate class allowed "=" anywhere, which let
// a candidate swallow the "NAME=" in front of it. The combined string decoded
// as neither base64 nor hex, so nothing was reported at all. Padding only ever
// appears at the end of base64, so the class now allows it only there.
func TestAnEncodedValueIsFoundAfterAnAssignment(t *testing.T) {
	// This plaintext hex-encodes to a string of decimal digits only, which the
	// text gate reads as a number. The line pass is what saves it.
	const secret = "dapi0123456789abcdef0123456789abcdef"
	for name, encoded := range encodings(secret) {
		for _, line := range []string{
			"BLOB=" + encoded,
			`BLOB="` + encoded + `"`,
			"  blob: " + encoded,
			encoded,
		} {
			got := ScanText("f", line)
			if len(got) == 0 {
				t.Errorf("%s encoding missed in %q", name, trim(line))
				continue
			}
			if !strings.HasSuffix(got[0].Rule, ":databricks-token") {
				t.Errorf("%s in %q reported as %q", name, trim(line), got[0].Rule)
			}
			if clean := RedactText(line); strings.Contains(clean, encoded) {
				t.Errorf("%s in %q survived redaction", name, trim(line))
			}
		}
	}
}

func trim(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}
