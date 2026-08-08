// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import "testing"

// Every package-level function has a Scanner method beside it, and the method
// is the whole reason the type exists: it is what a caller uses to apply a
// threshold other than the default. Testing only the package-level halves
// leaves the useful ones unexercised, so a method that ignored its threshold
// would fail nothing.
func TestEveryScannerMethodHonoursItsThreshold(t *testing.T) {
	// A placeholder scores 0.55, so it is above the default cut and below 0.9.
	// That makes it the value that tells the two scanners apart.
	const key, value = "db_password", "changeme"

	loose := NewScanner(DefaultMinConfidence)
	strict := NewScanner(0.9)

	t.Run("Redact", func(t *testing.T) {
		if _, redacted := loose.Redact(key, value); !redacted {
			t.Error("loose scanner kept it")
		}
		if _, redacted := strict.Redact(key, value); redacted {
			t.Error("strict scanner redacted it")
		}
	})

	t.Run("RedactInherited", func(t *testing.T) {
		// An inherited name is a hint, so the value has to carry itself. A real
		// credential is redacted under either scanner; the threshold still has
		// to be the thing that decides.
		const shaped = "AKIAIOSFODNN7EXAMPLE"
		if _, redacted := loose.RedactInherited("blob", shaped); !redacted {
			t.Error("loose scanner kept an AWS key")
		}
		if _, redacted := loose.RedactInherited("blob", "hunter2"); redacted {
			t.Error("an inherited name redacted a weak value on the name alone")
		}
		if _, redacted := NewScanner(0.999).RedactInherited("blob", shaped); redacted {
			t.Error("a threshold above every rule still redacted")
		}
	})

	t.Run("RedactLabels", func(t *testing.T) {
		in := map[string]string{key: value}
		if got := loose.RedactLabels(in); got[key] != RedactedMarker {
			t.Errorf("loose scanner kept %q", got[key])
		}
		if got := strict.RedactLabels(in); got[key] != value {
			t.Errorf("strict scanner redacted %q", got[key])
		}
	})

	t.Run("RedactTree", func(t *testing.T) {
		in := map[string]any{key: value}
		if got := loose.RedactTree("", in).(map[string]any); got[key] != RedactedMarker {
			t.Errorf("loose scanner kept %v", got[key])
		}
		if got := strict.RedactTree("", in).(map[string]any); got[key] != value {
			t.Errorf("strict scanner redacted %v", got[key])
		}
	})

	t.Run("RedactInline", func(t *testing.T) {
		const line = "export DB_PASSWORD=changeme"
		if got := loose.RedactInline(line); got == line {
			t.Errorf("loose scanner kept %q", got)
		}
	})

	t.Run("RedactText", func(t *testing.T) {
		// Not the placeholder here: a rewrite deliberately leaves those alone,
		// so it would not distinguish the two scanners. hunter2 scores 0.80,
		// which is above the default cut and below the strict one.
		const doc = "db_password: \"hunter2\"\n"
		if got := loose.RedactText(doc); got == doc {
			t.Errorf("loose scanner kept %q", got)
		}
		if got := strict.RedactText(doc); got != doc {
			t.Errorf("strict scanner rewrote %q", got)
		}
	})

	t.Run("Detect and DetectValue", func(t *testing.T) {
		// These two deliberately do NOT apply the threshold: the score is the
		// answer they exist to give. Meets is how a caller applies the cut.
		f := strict.Detect(key, value)
		if !f.Found() {
			t.Fatal("Detect returned nothing for a scored value")
		}
		if strict.Meets(f) {
			t.Error("Meets accepted a 0.55 finding at a 0.9 threshold")
		}
		if !loose.Meets(f) {
			t.Error("Meets rejected a 0.55 finding at the default threshold")
		}

		v := strict.DetectValue("AKIAIOSFODNN7EXAMPLE")
		if v.Rule != "aws-access-key-id" {
			t.Errorf("Scanner.DetectValue reported %q", v.Rule)
		}
		if v.Key != "" {
			t.Errorf("DetectValue invented a key: %q", v.Key)
		}
	})
}

// The zero Scanner and a nil Scanner both have to behave, because the zero
// value is documented as usable and a nil receiver is what a caller gets from
// an uninitialised field.
func TestZeroAndNilScanner(t *testing.T) {
	var zero Scanner
	if got := zero.Threshold(); got != DefaultMinConfidence {
		t.Errorf("zero Scanner threshold = %v", got)
	}
	if _, redacted := zero.Redact("password", "hunter2"); !redacted {
		t.Error("the zero Scanner did not redact")
	}

	var nilScanner *Scanner
	if got := nilScanner.Threshold(); got != DefaultMinConfidence {
		t.Errorf("nil Scanner threshold = %v", got)
	}
	if nilScanner.Meets(Finding{}) {
		t.Error("nil Scanner accepted the zero Finding")
	}
}

// Meets is false for the zero Finding whatever the threshold, because "nothing
// was found" is not a finding below the cut.
func TestMeetsRejectsTheZeroFinding(t *testing.T) {
	for _, min := range []Confidence{0.01, DefaultMinConfidence, 0.99} {
		if NewScanner(min).Meets(Finding{}) {
			t.Errorf("the zero Finding was accepted at %v", min)
		}
	}
}
