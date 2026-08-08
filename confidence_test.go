// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import "testing"

// The score has to be ordered the way the ladder claims, or "confidence" is a
// number in a report rather than something a caller can threshold against.
// These are the comparisons a user actually makes when they raise or lower
// -min-confidence, pinned in the order they expect.
func TestConfidenceIsOrdered(t *testing.T) {
	selfIdentifying := Detect("uploader", "AKIAIOSFODNN7EXAMPLE")
	nameAndShape := Detect("aws_secret_access_key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	nameOnly := Detect("db_password", "hunter2")
	placeholder := Detect("db_password", "changeme")
	securityName := Detect("encryptionKey", "aGVsbG8gd29ybGQxMjM0NTY3ODkw")

	ordered := []struct {
		name string
		f    Finding
	}{
		{"self-identifying provider format", selfIdentifying},
		{"credential name backed by shape", nameAndShape},
		{"credential name alone", nameOnly},
		{"security name plus opaque value", securityName},
		{"credential name holding a placeholder", placeholder},
	}
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1].f.Confidence <= ordered[i].f.Confidence {
			t.Errorf("%s (%.2f) does not outrank %s (%.2f)",
				ordered[i-1].name, ordered[i-1].f.Confidence,
				ordered[i].name, ordered[i].f.Confidence)
		}
	}
	// Every one of them is still a finding the library redacts: the ladder
	// grades certainty, it does not create a class of secret that leaks.
	for _, o := range ordered {
		if !defaultScanner.Meets(o.f) {
			t.Errorf("%s scored %.2f, below the default cut", o.name, o.f.Confidence)
		}
	}
	// And the reason survives the score, so a report can say which it was.
	if selfIdentifying.Rule != "aws-access-key-id" {
		t.Errorf("rule = %q, want aws-access-key-id", selfIdentifying.Rule)
	}
	if nameOnly.Rule != RuleCredentialName || nameOnly.Key != "db_password" {
		t.Errorf("weak secret reported as %q under %q", nameOnly.Rule, nameOnly.Key)
	}
	if placeholder.Rule != RulePlaceholder {
		t.Errorf("placeholder reported as %q", placeholder.Rule)
	}
}

// Entropy is a continuous measurement, and comparing it to a constant made a
// value one hundredth of a bit either side of the line either certainly a
// secret or certainly not. Neither was true. Scoring it is the fix, so more
// random has to mean more confident.
func TestEntropyScoresContinuously(t *testing.T) {
	// Both clear the opaque test; one is far closer to random than the other.
	repetitive := Detect("blob", "Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1")
	random := Detect("blob", "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MEFCQ0RFRkdI")
	if !repetitive.Found() || !random.Found() {
		t.Fatalf("expected both to be findings: %+v %+v", repetitive, random)
	}
	if random.Confidence <= repetitive.Confidence {
		t.Errorf("the more random value scored %.2f, no higher than %.2f",
			random.Confidence, repetitive.Confidence)
	}
}

// A caller that raises the bar gets fewer redactions, and one that lowers it
// gets more. Without this the score is decorative.
func TestScannerThresholdChangesTheVerdict(t *testing.T) {
	const key, value = "db_password", "changeme"
	if _, redacted := NewScanner(0.9).Redact(key, value); redacted {
		t.Error("a placeholder was redacted by a scanner asking for near-certainty")
	}
	if _, redacted := NewScanner(DefaultMinConfidence).Redact(key, value); !redacted {
		t.Error("a placeholder survived the default cut")
	}
	// The cut moves the line, it does not move the ceiling: a real credential
	// is redacted at every setting.
	for _, min := range []Confidence{0.1, DefaultMinConfidence, 0.9} {
		if _, redacted := NewScanner(min).Redact("x", "AKIAIOSFODNN7EXAMPLE"); !redacted {
			t.Errorf("an AWS key survived at min-confidence %.2f", min)
		}
	}
	// The zero Scanner is the useful one.
	if got := (&Scanner{}).Threshold(); got != DefaultMinConfidence {
		t.Errorf("zero Scanner threshold = %.2f, want the default", got)
	}
}

// Re-scanning is what this package tells its consumers to do — trust the scan
// you ran, not the one that produced the payload. A marker left by an earlier
// pass therefore has to read as ordinary input, or every re-scan of a clean
// payload reports a fresh leak that is not there.
func TestRedactionIsIdempotent(t *testing.T) {
	in := map[string]any{
		"password": "hunter2",
		"note":     "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",
	}
	once := RedactTree("", in)
	twice := RedactTree("", once)

	first, _ := once.(map[string]any)
	second, _ := twice.(map[string]any)
	for k := range first {
		if first[k] != second[k] {
			t.Errorf("%s changed on the second pass: %q then %q", k, first[k], second[k])
		}
	}
	if f := Detect("password", RedactedMarker); f.Found() {
		t.Errorf("the marker itself was reported as a finding: %+v", f)
	}
}

// The masked form is what goes into reports, tickets and chat. It has to say
// enough to identify the credential and never enough to use it.
func TestMaskedNeverPrintsTheWholeSecret(t *testing.T) {
	for _, secret := range []string{
		"AKIAIOSFODNN7EXAMPLE",
		"hunter2",
		"a",
		"ghp_1234567890abcdefghijklmnopqrstuvwx",
	} {
		masked := Finding{Secret: secret}.Masked()
		if masked == secret {
			t.Errorf("%q was printed verbatim", secret)
		}
		if len(secret) > 8 && masked[:4] != secret[:4] {
			t.Errorf("%q lost the head that identifies it: %q", secret, masked)
		}
		if len(secret) > 8 && len(masked) >= len(secret) {
			t.Errorf("%q masked to %q, which leaks its length", secret, masked)
		}
	}
}

// Placeholders are what a template repository is made of. Scoring them just
// above the cut keeps the library redacting them — harmless — while letting a
// scan run at ConfidenceMedium stop reporting a repository's own examples.
func TestPlaceholdersAreRecognized(t *testing.T) {
	for _, v := range []string{
		"changeme", "CHANGEME", "your-api-key-here", "xxxxxxxx", "TODO",
		"${DB_PASSWORD}", "{{ .Values.password }}", "<your token>", "placeholder",
	} {
		if !looksPlaceholder(v) {
			t.Errorf("%q was not recognized as a placeholder", v)
		}
		if f := Detect("password", v); f.Rule != RulePlaceholder {
			t.Errorf("password=%q reported as %q at %.2f", v, f.Rule, f.Confidence)
		}
	}
	// A weak credential is not a placeholder. This is the distinction the whole
	// tier turns on, and getting it wrong would quietly downgrade real findings.
	for _, v := range []string{"hunter2", "s3cr3t-value", "p@ssw0rd"} {
		if looksPlaceholder(v) {
			t.Errorf("%q was treated as a placeholder", v)
		}
		if f := Detect("password", v); f.Rule != RuleCredentialName {
			t.Errorf("password=%q reported as %q", v, f.Rule)
		}
	}
}

// A shape rule below the cut must not be able to hide a more confident tier
// behind it just by being consulted first.
func TestALowScoringShapeDoesNotMaskAHigherTier(t *testing.T) {
	// "cert" is on the security list, and the value is a PEM certificate, which
	// scores below the cut on its own. The name still has to promote it.
	f := Detect("TLS_CERT", "-----BEGIN CERTIFICATE-----")
	if !defaultScanner.Meets(f) {
		t.Errorf("TLS_CERT holding a certificate scored %.2f under rule %q", f.Confidence, f.Rule)
	}
}
