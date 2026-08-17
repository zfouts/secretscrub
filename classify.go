// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

// classify is the whole decision, in tiers of decreasing name authority.
//
// inherited says the name came from an enclosing structure rather than from the
// value's own key. An inherited name is only ever a hint: "password" naming a
// leaf means that leaf is a credential, but a block named "password" whose
// members are {policy, minLength} does not make "strict" or "12" secrets.
func (s *Scanner) classify(key string, inherited bool, value string) Finding {
	if value == "" {
		return Finding{}
	}
	// Re-scanning is not just permitted, it is what this package tells its
	// callers to do — trust the scan you ran, not the one that produced the
	// data. A marker left by an earlier pass is therefore ordinary input, and
	// reporting it would make every re-scan of a clean payload look like a
	// fresh leak.
	if value == RedactedMarker {
		return Finding{}
	}

	// Tier 0: the value cannot be a credential. Two ways to establish that.
	//
	// The first is the value itself: a date is a fact, not a secret. Names
	// carrying a credential word overwhelmingly often name a fact ABOUT one
	// rather than the credential — PasswordLastUsed, AccessKeyLastUsed,
	// SecretLastRotated — and tier 1 fires on the name alone, so every one of
	// those scored as a secret. A check for a dormant account or an unrotated
	// key reads exactly those fields, so the rules meant to catch a stale
	// credential were grading "<redacted>". The exemption is safe because the
	// format is anchored and fully specified: no credential can be shaped into
	// a calendar date.
	if looksTimestamp(value) {
		return Finding{}
	}
	// The second is the allowlist, and only the field's OWN key can establish
	// it — an allowlisted parent says nothing about what its children hold.
	if !inherited && isSafeName(key) {
		return Finding{}
	}

	// Shape evidence, computed once. It stands alone at tier 2 and sharpens the
	// name verdict at tier 1.
	shape := detectShape(value)

	// Tier 1: the value's own key says it is a credential. Enough on its own,
	// and the only tier that catches a weak secret a shape test would pass
	// over. An operator-authored name gets this strength from a security word
	// too: AUTH_HEADER and TLS_CERT hold what they say they hold.
	if !inherited && (IsSensitiveName(key) ||
		(IsSecurityRelatedName(key) && looksOperatorAuthored(key))) {
		return nameFinding(key, value, shape)
	}

	// Tier 2: the value looks like a credential whatever it is called. This is
	// what catches the secrets nobody names "password".
	//
	// Identity blocks are exempt from the two GENERIC fallbacks. An S3
	// canonical user id is 64 hex characters, so the hex rule silenced the Owner
	// and Grantee ids on every bucket ACL — and "which account is this bucket
	// granted to" is the cross-account exposure question an ACL exists to
	// answer.
	//
	// The exemption stops there, because those two rules are the only ones it
	// has any standing to overrule. They are guesses from randomness, and an
	// identifier is random by construction, so the name is better evidence than
	// the measurement. A provider format is not a guess: a PEM header, an AKIA
	// prefix, a ghp_ prefix and a JWT's three dotted segments each identify what
	// the value IS, and no field name makes that reading wrong. Before this
	// split, "Name" or "id" published an RSA private key verbatim.
	best := Finding{}
	if shape.Found() && (!isGenericShapeFallback(shape.Rule) || !identityContainer(key)) {
		shape.Key = key
		best = shape
	}

	// Tier 3: a security-related name — its own, or one inherited from a
	// parent — lowers the bar, but the value still has to look like encoded
	// material rather than an enum a provider ships.
	//
	// Tier 2 does not short-circuit this. A shape rule can score below the
	// default cut — the fuzzy tail at the bottom of the registry does — and a
	// tier that fires must not be able to hide a more confident one behind it
	// just by being consulted first.
	if (IsSensitiveName(key) || IsSecurityRelatedName(key)) && looksSemiOpaque(value) {
		named := Finding{
			Rule:        RuleSecurityNameOpaqueValue,
			Category:    CategoryGeneric,
			Confidence:  ConfidenceMedium,
			Description: "encoded-looking value under a security-related name",
			Key:         key,
			Secret:      value,
		}
		if named.Confidence > best.Confidence {
			best = named
		}
	}
	return best
}

// isGenericShapeFallback reports whether a rule concluded only that a value
// looks random, with nothing in it naming what it is.
//
// These are the two rules an identifier name may overrule, and the test is on
// the rule rather than on the Category: the "jwt" rule is filed under
// [CategoryGeneric] because a JWT is nobody's proprietary format, but its three
// dotted base64 segments are as self-identifying as an AKIA prefix.
func isGenericShapeFallback(rule string) bool {
	return rule == RuleHighEntropyString || rule == RuleHexString
}

// nameFinding scores a value whose own name asserts it is a credential.
//
// The name alone is already enough to redact, so this only decides how loudly
// to say so. A value that ALSO matches a provider format is as certain as this
// package gets — the two halves agree and neither had to be trusted alone. A
// value nobody has filled in yet is the opposite: a template repository is
// mostly such lines, and reporting each one is how a scanner teaches its users
// to ignore it.
func nameFinding(key, value string, shape Finding) Finding {
	f := Finding{
		Rule:        RuleCredentialName,
		Category:    CategoryGeneric,
		Confidence:  ConfidenceHigh,
		Description: "value under a name that asserts it is a credential",
		Key:         key,
		Secret:      value,
	}
	switch {
	case shape.Found():
		// The shape identifies which credential it is, so report that rule and
		// keep whichever score is higher. The agreement is worth a nudge, but
		// not past what a self-identifying format earns on its own.
		f.Rule, f.Category, f.Description = shape.Rule, shape.Category, shape.Description
		f.Confidence = clamp(max(shape.Confidence, ConfidenceHigh)+0.05, 0, 0.99)
	case looksPlaceholder(value):
		f.Rule = RulePlaceholder
		f.Description = "credential name holding a placeholder rather than a value"
		f.Confidence = DefaultMinConfidence + 0.05
	case looksSemiOpaque(value):
		// The name says credential and the value does not contradict it.
		f.Confidence = 0.9
	}
	return f
}
