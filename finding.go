// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

// Finding: what the detector concluded about one value, and the stable rule
// identifiers a report or a suppression list keys on.

// Rule identifiers for findings that come from reasoning rather than from the
// pattern registry. They are stable, so a report, a baseline file or a
// suppression list can key on them exactly as it keys on a provider rule.
const (
	// RuleCredentialName is a name asserting its value is a credential. The
	// only tier that catches a weak secret, because no shape test ever will.
	RuleCredentialName = "credential-name"

	// RulePlaceholder is a credential name holding something nobody has filled
	// in: CHANGEME, ${DB_PASSWORD}, xxxxxxxx. Scored just above the default
	// cut, so the library still redacts it — harmless — while a scan run at
	// ConfidenceMedium or above stops reporting a repository's own templates.
	RulePlaceholder = "credential-name-placeholder"

	// RuleSecurityNameOpaqueValue is the tier where neither half is
	// conclusive: a name that relates to security, and a value that could be
	// encoded material rather than the enum such names usually hold.
	RuleSecurityNameOpaqueValue = "security-name-opaque-value"

	// RuleHighEntropyString is a long opaque near-random run with no name
	// signal at all — the catch-all for a provider whose token format this
	// package has never seen.
	RuleHighEntropyString = "high-entropy-string"

	// RuleHexString is the same idea for a pure hex run: raw key bytes, an
	// HMAC secret, a digest.
	RuleHexString = "hex-string"
)

// A Finding is what the detector concluded about one value.
//
// The zero Finding means "nothing here". Use [Finding.Found] to ask, rather
// than comparing Confidence against a threshold you have to keep in sync with
// the scanner's.
type Finding struct {
	// Rule is the pattern or reasoning that fired, as a stable identifier.
	Rule string `json:"rule"`

	// Category groups the rule by what the credential unlocks.
	Category Category `json:"category"`

	// Confidence is how sure the detector is, from 0 to 1.
	Confidence Confidence `json:"confidence"`

	// Description is one line of prose about the rule, for a human.
	Description string `json:"description,omitempty"`

	// Key is the field, variable or parameter name the value arrived under,
	// when there was one.
	Key string `json:"key,omitempty"`

	// Path, Line and Column locate a finding produced by scanning text. They
	// are zero for a finding produced from a key/value pair, which has no
	// position. Line and Column are 1-based.
	Path   string `json:"path,omitempty"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`

	// Secret is the matched credential, so a caller can hash or fingerprint
	// it. It is excluded from JSON, and anything rendering a finding for a
	// human should print [Finding.Masked] instead.
	Secret string `json:"-"`
}

// Found reports whether the detector concluded anything at all.
func (f Finding) Found() bool { return f.Rule != "" }

// Masked renders the secret with its tail removed: enough of the head to
// recognize which credential it is when you go to rotate it, never enough to
// use. A short secret is replaced entirely.
//
// The tail is a fixed width rather than the length of what it replaced. A
// report is a thing people paste into tickets and chat, and the length of a
// credential is not information the reader needs but is information an
// attacker can use to narrow a search.
func (f Finding) Masked() string {
	const (
		keep = 4
		tail = "************"
	)
	if len(f.Secret) <= keep*2 {
		return tail
	}
	return f.Secret[:keep] + tail
}
