// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import "strconv"

// Confidence and the ladder the rest of the package scores against.

// Confidence is how sure the detector is that a value is a credential, from 0
// to 1.
//
// A boolean detector has to pick one threshold and live with it, and there is
// no threshold that is right for both callers this package has. Code redacting
// a captured payload wants everything that could be a credential gone, because
// one over-redacted stored field is cheap and a stored live key is not.
// Somebody scanning a working tree wants the opposite: a wall of maybes is a
// wall nobody reads, and the finding that mattered is in the middle of it.
//
// A score serves both. The decision is still one function of one number, so
// there is still exactly one detector; what changes is where the caller cuts.
type Confidence float64

// The confidence ladder. The rungs are spaced so the interesting cuts —
// self-identifying credentials only, everything the library would redact, show
// me the maybes — fall between them rather than inside them.
const (
	// ConfidenceCertain is a credential that identifies itself: a provider
	// prefix nothing else can hold, or key material announcing its own format.
	ConfidenceCertain Confidence = 0.95

	// ConfidenceHigh is a strong signal with a conceivable innocent reading,
	// such as a JWT in a fixture or a field named "password" holding a
	// real-looking value.
	ConfidenceHigh Confidence = 0.8

	// ConfidenceMedium is a value that looks like encoded material under a name
	// that makes that plausible. Most true findings that are not
	// self-identifying land here.
	ConfidenceMedium Confidence = 0.6

	// ConfidenceLow is a shape shared with things that are not credentials at
	// all. Reported only to a caller that lowered its threshold to ask.
	ConfidenceLow Confidence = 0.4

	// DefaultMinConfidence is the threshold the package-level functions use. It
	// sits below ConfidenceMedium deliberately: the standing bias is that
	// over-redaction is cheap and a stored credential is not, so the default
	// keeps the fuzzy middle and drops only the bottom rung.
	DefaultMinConfidence Confidence = 0.5
)

// String formats a confidence to two decimal places.
func (c Confidence) String() string {
	return strconv.FormatFloat(float64(c), 'f', 2, 64)
}

// scaleConfidence maps a measurement onto a confidence range, linearly between
// lo and hi and flat outside them.
//
// This is where "fuzzy" stops being a figure of speech. Entropy is a continuous
// measurement and the obvious implementation compares it to a constant, so a
// value one hundredth of a bit either side of the line is either certainly a
// secret or certainly not. Neither answer is true, and the arbitrariness shows
// up as the same field surviving on one row and vanishing on the next.
func scaleConfidence(measured, lo, hi float64, floor, ceiling Confidence) Confidence {
	if hi <= lo {
		return floor
	}
	return clamp(floor+Confidence((measured-lo)/(hi-lo))*(ceiling-floor), floor, ceiling)
}

// clamp bounds v to [lo, hi].
func clamp(v, lo, hi Confidence) Confidence {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// Categories, which group a rule by what the credential it finds unlocks.

// Category groups a rule by what the credential it finds unlocks. Nothing in
// the decision depends on a category; it exists because "which of these is a
// cloud key and which is a chat webhook" is the first question anyone triaging
// a scan asks.
type Category string

// The categories a [Rule] can carry.
const (
	CategoryCloud      Category = "cloud"       // provider control-plane credentials
	CategoryVCS        Category = "vcs"         // source forges and package registries
	CategoryCI         Category = "ci"          // build, deploy and infrastructure tooling
	CategorySaaS       Category = "saas"        // application platforms and APIs
	CategoryAI         Category = "ai"          // model provider keys
	CategoryPayment    Category = "payment"     // money movement
	CategoryMessaging  Category = "messaging"   // chat and mail, including webhooks
	CategoryDatabase   Category = "database"    // connection strings and datastore auth
	CategoryPrivateKey Category = "private-key" // asymmetric key material
	CategoryGeneric    Category = "generic"     // no provider attribution
)
