// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import (
	"regexp"
	"slices"
	"strings"
)

// A Rule recognizes one credential format by shape alone.
//
// Shape rules are what catch the secrets nobody names "password" — the majority
// of real findings. A provider that gives its tokens a distinctive prefix has
// done the detector's work for it: "ghp_" followed by 36 base62 characters is a
// GitHub token and cannot plausibly be anything else, which is why these carry
// the highest confidence in the package.
type Rule struct {
	// ID names the rule in a report and is stable: it is what a suppression
	// comment, a CI baseline or a triage spreadsheet keys on.
	ID string

	// Description is one line of prose for a human reading the finding.
	Description string

	// Category is one of the Category constants above.
	Category Category

	// Confidence is how sure a match makes the detector, from 0 to 1. See the
	// ladder documented on Finding: a self-identifying provider prefix sits at
	// 0.9 and above, while a rule that can plausibly fire on an identifier is
	// deliberately parked below DefaultMinConfidence so it is reported only to
	// a caller that asked for the fuzzy tail.
	Confidence Confidence

	// Pattern matches the credential. Anchored or bounded wherever the format
	// allows, so a log line that merely mentions a token does not fire.
	Pattern *regexp.Regexp

	// Secret is the submatch index holding the credential itself. Zero means
	// the whole match. It is non-zero for rules that need surrounding context
	// to be sure ("AccountKey=..."), where replacing the whole match would
	// destroy the very context that identified it.
	Secret int

	// MinEntropy, when non-zero, is a floor the matched credential must clear.
	// It exists for the formats whose prefix is not distinctive enough on its
	// own: "sk-" followed by a hyphenated cluster name matches the shape of an
	// OpenAI key and is not one.
	MinEntropy float64

	// Contains is a lowercase substring the value must hold for the pattern to
	// be worth running. It is a prefilter, not part of the rule's meaning: the
	// registry is large and RedactTree runs it against every leaf of every
	// captured payload, so the common case has to be a substring search rather
	// than seventy regex evaluations.
	Contains string

	// MinLen is the shortest value the pattern could possibly match, and is a
	// second prefilter for the handful of formats with no usable literal. It
	// must be no greater than the true minimum, or the rule silently stops
	// firing on short matches.
	MinLen int
}

// find returns the span of the credential inside s, if the rule matches.
func (r *Rule) find(s string) (start, end int, ok bool) {
	loc := r.Pattern.FindStringSubmatchIndex(s)
	if loc == nil {
		return 0, 0, false
	}
	return r.span(s, loc)
}

// findAll returns every credential span in s. Used by the text scanner, where
// one line can carry more than one secret.
func (r *Rule) findAll(s string) [][2]int {
	locs := r.Pattern.FindAllStringSubmatchIndex(s, -1)
	if locs == nil {
		return nil
	}
	spans := make([][2]int, 0, len(locs))
	for _, loc := range locs {
		if start, end, ok := r.span(s, loc); ok {
			spans = append(spans, [2]int{start, end})
		}
	}
	return spans
}

// span narrows a raw submatch to the credential and applies the entropy floor.
func (r *Rule) span(s string, loc []int) (start, end int, ok bool) {
	i := 2 * r.Secret
	if i+1 >= len(loc) || loc[i] < 0 {
		i = 0
	}
	start, end = loc[i], loc[i+1]
	if r.MinEntropy > 0 && shannonEntropy(s[start:end]) < r.MinEntropy {
		return 0, 0, false
	}
	return start, end, true
}

// applies reports whether the rule's prefilters admit a value. lower is the
// value lowercased, computed once by the caller.
func (r *Rule) applies(lower string) bool {
	if len(lower) < r.MinLen {
		return false
	}
	return r.Contains == "" || strings.Contains(lower, r.Contains)
}

// Rules returns the pattern set, in registry order. It is exported so a caller
// can print what the detector knows — a scanner that cannot tell you what it
// looks for is one you have to trust rather than review — and so a consumer can
// record which rule set produced a redaction.
//
// The returned slice is a copy; the registry itself is not modifiable, because
// the whole reason this package exists is that there is exactly one detector.
func Rules() []Rule {
	out := make([]Rule, len(rules))
	copy(out, rules)
	return out
}

// rules is the shape registry: every group, in a stable order.
//
// The groups live in rules_*.go, one per domain, because a single literal of
// seventy entries is a file nobody reads to the end and a file every change
// conflicts in. Adding a provider means editing the small file its domain
// already lives in; a format that grows past a few entries can take a file of
// its own and be appended here.
//
// A file per provider was the other option and is what some scanners do. With
// fifty-eight providers it would mean fifty-eight files averaging eight lines,
// which trades one file that is too long for a directory that is too wide.
//
// Order is fixed rather than incidental: Rules reports it, and a registry
// assembled by init functions would make the set depend on which files happen
// to be compiled, which is the opposite of what a security control wants.
var rules = slices.Concat(
	keyMaterialRules,
	genericRules,
	cloudRules,
	vcsRules,
	messagingRules,
	paymentRules,
	saasRules,
	aiRules,
)

// matchRules returns the most confident registry rule that claims value, or
// the zero Finding.
//
// Every rule that could apply is tried and the best score wins, rather than the
// first to match. Two rules matching is normal for a nested format — a JWT
// inside a bearer header, a key inside a connection string — and the specific
// one is worth reporting.
//
// Separate from detectShape because the obfuscation tier needs the registry
// without the tiers around it: scoring a decoded blob by its entropy would
// report every base64 string in every repository.
func matchRules(value string) Finding {
	lower := strings.ToLower(value)
	best := Finding{}
	for i := range rules {
		r := &rules[i]
		if !r.applies(lower) || r.Confidence <= best.Confidence {
			continue
		}
		start, end, ok := r.find(value)
		if !ok {
			continue
		}
		best = Finding{
			Rule:        r.ID,
			Category:    r.Category,
			Confidence:  r.Confidence,
			Description: r.Description,
			Secret:      value[start:end],
		}
	}
	return best
}
