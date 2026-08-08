// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import (
	"regexp"
	"sort"
	"strings"
)

// Rewriting a whole document, removing exactly what a scan of it would report.

// pemBeginRe and pemEndRe bracket key material that spans lines.
//
// Both are anchored to the WHOLE line, and that anchoring is load-bearing. In a
// real PEM file the delimiter is alone on its line; a BEGIN marker with other
// content around it is a marker quoted inside something else — a JSON string, a
// log message, a test fixture — and there is no block after it to skip.
//
// Matching it loosely was a data-destruction bug rather than a missed finding:
// the line was written out verbatim, so the credential on it survived, and
// every line after it was swallowed into a single marker while the rewriter
// waited for an END that never came. Under -redact -w that truncated the file.
var (
	pemBeginRe = regexp.MustCompile(`^\s*-----BEGIN [A-Z0-9 ]+-----\s*$`)
	pemEndRe   = regexp.MustCompile(`^\s*-----END [A-Z0-9 ]+-----\s*$`)
)

// RedactText rewrites a whole document with its credentials replaced, keeping
// everything else — including line endings and quoting — byte for byte.
//
// It replaces exactly what ScanText reports, at the same cut, so a file that
// scans clean is a file this leaves alone and a file this rewrites is one the
// scan explained first. Two things a document needs that a captured string does
// not:
//
// A bare credential on a line of its own is not an assignment. "AKIA…" pasted
// into a README has no name beside it, so the shape rules are applied to the
// line directly rather than only to the right-hand side of an "=".
//
// A PEM block is redacted as a block. The line that announces a private key is
// not the secret, the twenty lines of base64 after it are, and replacing only
// the header produces a file that reads as scrubbed while still holding the
// key. The BEGIN and END lines are kept so the shape of the file survives and a
// reader can see what was removed.
func RedactText(text string) string { return defaultScanner.RedactText(text) }

// RedactText is RedactText at this scanner's confidence cut.
func (s *Scanner) RedactText(text string) string {
	var b strings.Builder
	b.Grow(len(text))
	inPEM, wroteBody := false, false
	for rest := text; ; {
		nl := strings.IndexByte(rest, '\n')
		line := rest
		if nl >= 0 {
			line = rest[:nl]
		}
		out, emit := line, true
		switch {
		case inPEM && pemEndRe.MatchString(line):
			inPEM = false
		case inPEM:
			// One marker stands for the whole body, and the lines it replaces
			// go with it. Writing one marker per line would say nothing extra
			// and would leak how long the key was.
			if wroteBody || strings.TrimSpace(line) == "" {
				emit = false
			} else {
				wroteBody, out = true, RedactedMarker
			}
		case pemBeginRe.MatchString(line) && !pemEndRe.MatchString(line):
			inPEM, wroteBody = true, false
		default:
			out = s.redactLine(line)
		}
		if emit {
			b.WriteString(out)
			if nl >= 0 {
				b.WriteByte('\n')
			}
		}
		if nl < 0 {
			break
		}
		rest = rest[nl+1:]
	}
	return b.String()
}

// redactLine replaces every credential span on one line with the marker.
func (s *Scanner) redactLine(line string) string {
	if line == "" || len(line) > maxLineScan {
		return line
	}
	spans := s.credentialSpans(line)
	if len(spans) == 0 {
		return line
	}
	var b strings.Builder
	b.Grow(len(line))
	prev := 0
	for _, sp := range spans {
		b.WriteString(line[prev:sp[0]])
		b.WriteString(RedactedMarker)
		prev = sp[1]
	}
	b.WriteString(line[prev:])
	return b.String()
}

// credentialSpans returns the non-overlapping spans on a line that hold a
// credential the scanner would report, in order.
//
// Both halves of the scan contribute, because both find things the other
// cannot: a shape rule finds a token with no name beside it, and an assignment
// finds a weak password no shape rule will ever recognize. The union is taken
// rather than the winner, which is the one place this differs from ScanText —
// a report wants one line per finding, and a rewrite wants every byte of every
// credential gone.
func (s *Scanner) credentialSpans(line string) [][2]int {
	lower := strings.ToLower(line)
	var spans [][2]int
	for i := range rules {
		r := &rules[i]
		// A rule the scanner would not report is not one it should silently
		// delete either.
		if r.Confidence < s.Threshold() || !r.applies(lower) {
			continue
		}
		spans = append(spans, r.findAll(line)...)
	}
	obfuscated := obfuscatedSpans(line)
	for i := range obfuscated {
		if o := &obfuscated[i]; s.Meets(o.Finding) {
			spans = append(spans, [2]int{o.start, o.end})
		}
	}
	assignments := s.assignments(line)
	for i := range assignments {
		a := &assignments[i]
		// The one place a rewrite reports more than it removes. A placeholder
		// is worth telling somebody about — a committed CHANGEME is a real
		// finding — but replacing "${DB_PASSWORD}" with the marker breaks the
		// file it appears in and protects nothing, because the reference was
		// never the secret.
		if s.Meets(a.Finding) && a.Rule != RulePlaceholder {
			spans = append(spans, [2]int{a.start, a.end})
		}
	}
	return mergeSpans(spans)
}

// mergeSpans sorts spans and unions the ones that touch.
func mergeSpans(spans [][2]int) [][2]int {
	if len(spans) < 2 {
		return spans
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i][0] != spans[j][0] {
			return spans[i][0] < spans[j][0]
		}
		return spans[i][1] > spans[j][1]
	})
	merged := spans[:1]
	for _, sp := range spans[1:] {
		last := &merged[len(merged)-1]
		if sp[0] <= last[1] {
			if sp[1] > last[1] {
				last[1] = sp[1]
			}
			continue
		}
		merged = append(merged, sp)
	}
	return merged
}
