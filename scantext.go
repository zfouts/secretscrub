// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import (
	"bufio"
	"io"
	"regexp"
	"sort"
	"strings"
)

// maxLineScan bounds one line. A minified bundle or an embedded base64 asset
// arrives as a single megabyte-long line, and running the registry over it
// costs more than the finding is worth. The size is itself the signal: a
// credential does not need a megabyte of company.
const maxLineScan = 256 << 10

// 6: bare

// ScanText finds credentials in free text and reports where they are.
//
// This is the half of the package a tree walk cannot do. RedactTree knows the
// name a value arrived under because a decoded payload has names; a source
// file, a .env, a Terraform variables file or a CI configuration is just bytes,
// and the only structure available is the one the text itself carries. So the
// scan looks for two things on every line: a value that identifies itself as a
// credential by shape, and an assignment whose left-hand side says the
// right-hand side is one.
//
// Findings are reported at or above the scanner's confidence cut, ordered by
// position, and never more than one per span — where two rules claim the same
// bytes, the more confident one is the one worth reading.
//
// path is recorded on each finding and is otherwise unused; pass "" if the text
// did not come from a file.
func ScanText(path, text string) []Finding { return defaultScanner.ScanText(path, text) }

// ScanText is ScanText at this scanner's confidence cut.
func (s *Scanner) ScanText(path, text string) []Finding {
	var out []Finding
	line := 1
	for rest := text; ; line++ {
		nl := strings.IndexByte(rest, '\n')
		segment := rest
		if nl >= 0 {
			segment = rest[:nl]
		}
		out = append(out, s.scanLine(path, line, strings.TrimSuffix(segment, "\r"))...)
		if nl < 0 {
			break
		}
		rest = rest[nl+1:]
	}
	return out
}

// ScanReader is ScanText over a stream, for input that need not be held whole.
//
// A line longer than maxLineScan ends the scan and is returned as an error
// alongside every finding made up to that point. That is the same line ScanText
// skips, reported rather than passed over, because a stream gives the caller no
// other way to know the scan stopped early.
func ScanReader(path string, r io.Reader) ([]Finding, error) {
	return defaultScanner.ScanReader(path, r)
}

// ScanReader is ScanReader at this scanner's confidence cut.
func (s *Scanner) ScanReader(path string, r io.Reader) ([]Finding, error) {
	var out []Finding
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineScan)
	line := 0
	for sc.Scan() {
		line++
		out = append(out, s.scanLine(path, line, strings.TrimSuffix(sc.Text(), "\r"))...)
	}
	// A line past the buffer is the pathological case maxLineScan exists for.
	// Everything scanned up to it stands, so the findings are returned
	// alongside the error rather than discarded.
	return out, sc.Err()
}

// scanLine is the unit of the text scan: shape rules over the whole line, then
// assignments, then a merge that keeps the most confident claim on any span.
func (s *Scanner) scanLine(path string, line int, text string) []Finding {
	if text == "" || len(text) > maxLineScan {
		// Skipped rather than truncated, and skipped on the same test
		// redactLine uses. A report that names a credential a rewrite will not
		// remove is worse than no report: it says the file was handled.
		return nil
	}

	var cands []locatedFinding

	lower := strings.ToLower(text)
	for i := range rules {
		r := &rules[i]
		if !r.applies(lower) {
			continue
		}
		for _, span := range r.findAll(text) {
			cands = append(cands, locatedFinding{
				Finding: Finding{
					Rule:        r.ID,
					Category:    r.Category,
					Confidence:  r.Confidence,
					Description: r.Description,
					Secret:      text[span[0]:span[1]],
				},
				start: span[0], end: span[1],
			})
		}
	}

	cands = append(cands, s.assignments(text)...)
	cands = append(cands, obfuscatedSpans(text)...)

	// Most confident first, so the greedy pass below keeps the best claim on
	// each span. Ties break on the longer match — given "Bearer eyJ…", the rule
	// that saw the whole header knows more than the one that saw the token —
	// and then on having read a name, because "AWS_SECRET_ACCESS_KEY = …" tells
	// whoever has to rotate it something the bare match does not.
	sort.SliceStable(cands, func(i, j int) bool {
		switch {
		case cands[i].Confidence != cands[j].Confidence:
			return cands[i].Confidence > cands[j].Confidence
		case cands[i].end-cands[i].start != cands[j].end-cands[j].start:
			return cands[i].end-cands[i].start > cands[j].end-cands[j].start
		default:
			return cands[i].Key != "" && cands[j].Key == ""
		}
	})

	var kept []locatedFinding
	for i := range cands {
		c := &cands[i]
		if !s.Meets(c.Finding) {
			continue
		}
		overlaps := false
		for j := range kept {
			if c.start < kept[j].end && kept[j].start < c.end {
				overlaps = true
				break
			}
		}
		if !overlaps {
			kept = append(kept, *c)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].start < kept[j].start })

	out := make([]Finding, 0, len(kept))
	for i := range kept {
		f := kept[i].Finding
		f.Path, f.Line, f.Column = path, line, kept[i].start+1
		out = append(out, f)
	}
	return out
}

// Finding NAME = value on a line, in the spellings a config file, a script, an
// env file, a YAML document and a JSON object all use.

// textAssignRe matches NAME = value in the spellings a configuration file, a
// script, an env file, a YAML document and a JSON object all use.
//
// It is deliberately more permissive than inlineAssignRe, which serves
// RedactInline and has to stay conservative because it runs against captured
// provider payloads, where a false positive destroys a stored field. Here
// the input is a file somebody asked to have scanned, hyphenated and dotted
// keys are ordinary ("api-key:", "auth.token ="), and the cost of a maybe is a
// line of output rather than a hole in the data.
var textAssignRe = regexp.MustCompile(
	`([A-Za-z_][A-Za-z0-9_.\-]{1,64})` + // 1: name
		// The optional quote closes a JSON or quoted-YAML key. Without it the
		// most common configuration format there is — `"private_key": "…"` —
		// matches nothing, and the only thing left to find a credential in a
		// .json file is a shape rule, which knows the format but not the name.
		`["']?\s*(?::=|=>|[:=])\s*` + // separator, including the := and => forms
		"(?:\"([^\"\\n]{1,1000})\"" + // 2: double-quoted
		`|'([^'\n]{1,1000})'` + // 3: single-quoted
		"|`([^`\\n]{1,1000})`" + // 4: backquoted
		`|(\$\{[^}\n]{0,200}\}|\{\{[^}\n]{0,200}\}\})` + // 5: interpolated
		`|([^\s,;)\]}]{1,1000}))`)

// valueGroups are the submatch indices of textAssignRe's value alternatives, in
// the order the pattern tries them.
//
// The interpolated form has to be listed before the bare one and matched by the
// pattern before it, because a bare value stops at "}" — it has to, or every
// JSON and HCL value would swallow its closing brace — and "${DB_PASSWORD}"
// would otherwise be read as "${DB_PASSWORD", leaving a stray brace behind
// after a rewrite.
var valueGroups = []int{2, 3, 4, 5, 6}

// valueSpan returns the span of whichever value alternative matched, and
// whether that alternative was a quoted literal.
func valueSpan(m []int) (start, end int, quoted bool) {
	for _, g := range valueGroups {
		if 2*g+1 < len(m) && m[2*g] >= 0 {
			// Everything but the bare form is a literal: quoted, or an
			// interpolation, which is a literal reference to a value elsewhere.
			return m[2*g], m[2*g+1], g < 6
		}
	}
	return -1, -1, false
}

// locatedFinding is a finding with the span of the value it was drawn from.
type locatedFinding struct {
	Finding
	start, end int
}

// assignments finds every NAME = value on a line whose value the detector has
// something to say about.
//
// It runs twice, exactly as RedactInline does and for the same reason: a URL
// hides an assignment from a single pass. The scan meets "https:" first, takes
// the whole remainder as that name's value, and because the match is consumed
// nothing after it is examined again — so a presigned request's X-Amz-Signature
// goes through untouched.
//
// The order is the part that is easy to get backwards and expensive to get
// wrong. The whole line is scanned first, so a credential whose value
// legitimately contains "?" or "&" ("PASSWORD=abc?def") is claimed as one value
// before any split can cut it in half and publish the tail. Only then is the
// line split at the query separators and each parameter put in front of the
// detector on its own.
func (s *Scanner) assignments(text string) []locatedFinding {
	var out []locatedFinding
	out = s.appendAssignments(out, text, 0)

	start := 0
	for i := 0; i < len(text); i++ {
		if text[i] != '?' && text[i] != '&' {
			continue
		}
		out = s.appendAssignments(out, text[start:i], start)
		start = i + 1
	}
	if start != 0 {
		out = s.appendAssignments(out, text[start:], start)
	}
	return out
}

// appendAssignments is one assignment pass over a segment, with offset added to
// every span so the result is addressed in the enclosing line's coordinates.
func (s *Scanner) appendAssignments(out []locatedFinding, text string, offset int) []locatedFinding {
	for _, m := range textAssignRe.FindAllStringSubmatchIndex(text, -1) {
		vs, ve, quoted := valueSpan(m)
		if vs < 0 {
			continue
		}
		name, value := text[m[2]:m[3]], text[vs:ve]
		// Only the last dotted segment is judged. "auth.token" and "token.ADD"
		// are the same shape, and the segment is the half that says what the
		// value is: the first is a credential and the second is a map keyed by
		// an operator constant, which is what put four hundred findings in
		// go/types by way of the word "token".
		label := name[strings.LastIndexByte(name, '.')+1:]
		f := s.classify(label, false, value)
		if !f.Found() {
			continue
		}
		f.Key = name
		if !survivesInText(f, label, name, value, quoted) {
			continue
		}
		out = append(out, locatedFinding{Finding: f, start: vs + offset, end: ve + offset})
	}
	return out
}
