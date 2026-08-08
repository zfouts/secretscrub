// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

// Scanner: the one setting the detector has, and the entry points that read
// the score without acting on it.

// A Scanner holds the one setting the detector has: the confidence at which a
// finding counts.
//
// Everything else is deliberately not configurable. The pattern set being a
// single shared implementation is the reason this package exists — a gap fixed
// in one copy is a gap left open in the others — so a Scanner tunes sensitivity
// and nothing else.
//
// The zero Scanner is valid and uses [DefaultMinConfidence]. A Scanner is
// read-only once built and safe for concurrent use.
type Scanner struct {
	// MinConfidence is the score at or above which a finding counts. Zero
	// means DefaultMinConfidence.
	MinConfidence Confidence
}

// defaultScanner backs the package-level functions. Unexported so it cannot be
// mutated out from under a concurrent caller; use [NewScanner] for a different
// threshold.
var defaultScanner = &Scanner{MinConfidence: DefaultMinConfidence}

// NewScanner returns a Scanner reporting findings at or above minConfidence.
// Pass 0 for [DefaultMinConfidence].
func NewScanner(minConfidence Confidence) *Scanner {
	return &Scanner{MinConfidence: minConfidence}
}

// Threshold returns the confidence at or above which this scanner counts a
// finding, resolving the zero value to [DefaultMinConfidence].
func (s *Scanner) Threshold() Confidence {
	if s == nil || s.MinConfidence <= 0 {
		return DefaultMinConfidence
	}
	return s.MinConfidence
}

// Meets reports whether f is a finding at or above this scanner's threshold.
//
// [Detect] and [DetectValue] deliberately return their verdict whatever it
// scores, because the score is the answer they exist to give; the bulk
// reporting calls such as [Scanner.ScanText] apply the cut for you. Use this to
// apply the same cut to a Detect result.
func (s *Scanner) Meets(f Finding) bool {
	return f.Found() && f.Confidence >= s.Threshold()
}

// Detect reports what the detector concludes about a key/value pair, treating
// the key as naming the value directly.
//
// This is [Redact] without the redaction: the same decision, but the caller
// gets the score and the reason instead of a marker. The finding is returned
// whatever it scores — filter it with [Scanner.Meets] if you want the cut
// applied.
func Detect(key, value string) Finding { return defaultScanner.Detect(key, value) }

// Detect is [Detect] for this scanner. The threshold is not applied; see
// [Scanner.Meets].
func (s *Scanner) Detect(key, value string) Finding {
	return s.classify(key, false, value)
}

// DetectValue is [Detect] for a value with no name attached, so shape evidence
// alone decides.
func DetectValue(value string) Finding { return detectShape(value) }

// DetectValue is [DetectValue] for this scanner. The threshold is not applied;
// see [Scanner.Meets].
func (s *Scanner) DetectValue(value string) Finding { return detectShape(value) }
