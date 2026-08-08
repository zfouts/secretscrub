// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

// Walking a decoded payload.

// RedactTree walks a decoded payload and returns a copy with anything that
// looks like a credential replaced, whether it is identified by field name, by
// a sibling label or by the value's own shape.
//
// It handles map[string]any, map[string]string, []any and string; any other
// type is returned unchanged. Only leaf strings are examined, so a nested
// configuration block keeps its shape and only the offending value changes.
//
// key is the name the value arrived under, carried down so a name-based match
// still applies to a nested leaf: a value under "Password" is a credential
// whether it sits at the top level or three structures deep. Pass "" at the
// root.
func RedactTree(key string, v any) any {
	return defaultScanner.redactTree(key, false, v)
}

// RedactTree is [RedactTree] at this scanner's threshold.
func (s *Scanner) RedactTree(key string, v any) any {
	return s.redactTree(key, false, v)
}

// redactTree carries the inherited flag down the walk. A name picked up from an
// enclosing structure is a hint about its leaves, not a verdict on them: naming
// a block "encryption" must not silence the enum inside it, and a
// "tokenRequests" list must not turn its "audience" entries into markers.
func (s *Scanner) redactTree(key string, inherited bool, v any) any {
	switch t := v.(type) {
	case string:
		redacted, was := s.redact(key, inherited, t)
		if was {
			return redacted
		}
		// Not a credential as a whole; it may still contain one.
		return s.RedactInline(redacted)

	case map[string]any:
		// Providers return operator-supplied strings in two shapes, and only
		// one puts the operator's name where a walker can see it. See
		// PairLabel for why borrowing the sibling matters.
		label := PairLabel(t)
		out := make(map[string]any, len(t))
		for k, nested := range t {
			// The LABEL half of a recognized pair is a name, not a secret, and
			// must survive. Several label fields ("key", "name") match the
			// sensitive-name list on their own, so without this the walker
			// scrubs the label and publishes the value beside it — a record
			// that reads as redacted while carrying the credential. Checked
			// first for that reason.
			if label != "" && isPairLabelKey(k) {
				out[k] = nested
				continue
			}
			switch {
			case label != "" && IsPairValueKey(k):
				// The operator's own name for this value, read off a sibling.
				// It names the value as directly as the key would, so it keeps
				// full authority.
				out[k] = s.redactTree(label, false, nested)
			case IsSensitiveName(k) || IsSecurityRelatedName(k):
				// The key names this value itself.
				out[k] = s.redactTree(k, false, nested)
			case identityContainer(k):
				// An identity block names WHO, and its members are
				// identifiers. It has to carry its own name down, because the
				// default arm propagates the enclosing name and the members
				// are called things like "ID" that say nothing alone — which
				// is how an S3 Owner.ID came to be judged under the enclosing
				// call name and silenced by the hex rule.
				out[k] = s.redactTree(k, true, nested)
			default:
				// Nothing here names the value, so carry the enclosing name
				// down as a hint and let the leaf's shape decide.
				out[k] = s.redactTree(key, true, nested)
			}
		}
		return out

	case []any:
		// A list element inherits whatever named the list; its position tells
		// us nothing the list's name did not.
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = s.redactTree(key, inherited, e)
		}
		return out

	case map[string]string:
		out := make(map[string]string, len(t))
		for k, leaf := range t {
			if IsSensitiveName(k) || IsSecurityRelatedName(k) {
				out[k], _ = s.redact(k, false, leaf)
				continue
			}
			out[k], _ = s.redact(key, true, leaf)
		}
		return out
	}
	return v
}
