// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import (
	"regexp"
	"strings"
	"testing"
)

// The guards and fallthroughs. Each of these is a branch that only fires on
// input the ordinary tests never produce: an empty string, a value past a size
// bound, a decoder handed something that is not its encoding. They are cheap to
// get wrong and silent when they are, because the wrong answer is "no finding".

func TestRedactLabelsKeepsKeysAndJudgesEachValue(t *testing.T) {
	in := map[string]string{
		"db_password": "hunter2",
		"env":         "prod",
		"uploader":    "AKIAIOSFODNN7EXAMPLE",
		"owner":       "platform-team",
	}
	got := RedactLabels(in)

	// The tag name is what people search and group by. Hiding it costs the
	// whole point of having tags.
	for k := range in {
		if _, ok := got[k]; !ok {
			t.Errorf("key %q disappeared", k)
		}
	}
	if got["db_password"] != RedactedMarker {
		t.Errorf("a credential-named tag survived: %q", got["db_password"])
	}
	if got["uploader"] != RedactedMarker {
		t.Errorf("an AWS key under an innocuous tag survived: %q", got["uploader"])
	}
	if got["env"] != "prod" || got["owner"] != "platform-team" {
		t.Errorf("an ordinary tag was redacted: %v", got)
	}
	// The input is not modified.
	if in["db_password"] != "hunter2" {
		t.Error("RedactLabels mutated its argument")
	}
	// An empty map comes back as it went in, without an allocation.
	empty := map[string]string{}
	if got := RedactLabels(empty); len(got) != 0 {
		t.Errorf("empty map became %v", got)
	}
	if got := RedactLabels(nil); got != nil {
		t.Errorf("nil map became %v", got)
	}
}

func TestIsSensitiveValue(t *testing.T) {
	for _, v := range []string{
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_1234567890abcdefghijklmnopqrstuvwx",
		"postgres://app:s3cr3tpassword@db.internal:5432/app",
	} {
		if !IsSensitiveValue(v) {
			t.Errorf("%q was not recognised", v)
		}
	}
	for _, v := range []string{
		"", "prod-eu-west-1-assets", "us-east-1", RedactedMarker,
		// Below the default cut, so the boolean reading says no.
		"-----BEGIN CERTIFICATE-----",
	} {
		if IsSensitiveValue(v) {
			t.Errorf("%q was reported as sensitive", v)
		}
	}
}

// A walker meets types it was not built for, and has to hand them back rather
// than drop them.
func TestRedactTreeHandlesEveryShapeItClaims(t *testing.T) {
	in := map[string]any{
		"strings": map[string]string{
			"password":  "hunter2",
			"log_level": "info",
			"uploader":  "AKIAIOSFODNN7EXAMPLE",
		},
		"count":   42,
		"enabled": true,
		"nothing": nil,
		"nested":  []any{map[string]any{"token": "hunter2"}},
	}
	out := RedactTree("", in).(map[string]any)

	strs := out["strings"].(map[string]string)
	if strs["password"] != RedactedMarker {
		t.Errorf("map[string]string credential survived: %q", strs["password"])
	}
	if strs["uploader"] != RedactedMarker {
		t.Errorf("map[string]string shape match survived: %q", strs["uploader"])
	}
	if strs["log_level"] != "info" {
		t.Errorf("map[string]string ordinary value was redacted: %q", strs["log_level"])
	}
	// Types the walker does not examine come back unchanged rather than lost.
	if out["count"] != 42 || out["enabled"] != true || out["nothing"] != nil {
		t.Errorf("a non-string leaf was altered: %v", out)
	}
	if got := out["nested"].([]any)[0].(map[string]any)["token"]; got != RedactedMarker {
		t.Errorf("a credential inside a list survived: %v", got)
	}
	// A bare value that is not a container is returned as-is.
	if got := RedactTree("", 7); got != 7 {
		t.Errorf("RedactTree(7) = %v", got)
	}
}

// A blob past the bound is returned untouched, and the size is itself the
// signal that it should not have been captured.
func TestSizeBoundsAreRespected(t *testing.T) {
	huge := "export DB_PASSWORD=hunter2 " + strings.Repeat("x", maxInlineScan)
	if got := RedactInline(huge); got != huge {
		t.Error("RedactInline scanned a blob past maxInlineScan")
	}
	longLine := "db_password=hunter2 " + strings.Repeat("y", maxLineScan)
	if got := ScanText("big.txt", longLine); len(got) != 0 {
		t.Errorf("ScanText scanned a line past maxLineScan: %+v", got)
	}
	if got := RedactText(longLine); got != longLine {
		t.Error("RedactText rewrote a line past maxLineScan")
	}
}

func TestNameFindingScoresASemiOpaqueValueHigher(t *testing.T) {
	// A credential name whose value looks like encoded material, but which no
	// provider rule claims: the name and the value agree without either being
	// conclusive alone.
	f := Detect("password", "aGVsbG8gd29ybGQxMjM0NTY3ODkw")
	if f.Rule != RuleCredentialName {
		t.Fatalf("reported as %q", f.Rule)
	}
	if f.Confidence != 0.9 {
		t.Errorf("confidence %v, want 0.90 for a name backed by an opaque value", f.Confidence)
	}
	// The same name over an ordinary value scores lower.
	if plain := Detect("password", "hunter2"); plain.Confidence >= f.Confidence {
		t.Errorf("a plain value scored %v, no lower than an opaque one at %v",
			plain.Confidence, f.Confidence)
	}
}

func TestScaleConfidenceHandlesADegenerateRange(t *testing.T) {
	// lo == hi has no gradient to map onto, so the floor is the only honest
	// answer. Guarded because a future rule could pass an empty range.
	if got := scaleConfidence(5, 4, 4, ConfidenceMedium, ConfidenceCertain); got != ConfidenceMedium {
		t.Errorf("degenerate range gave %v, want the floor", got)
	}
	if got := scaleConfidence(0, 4, 2, ConfidenceLow, ConfidenceHigh); got != ConfidenceLow {
		t.Errorf("inverted range gave %v, want the floor", got)
	}
	// Outside the range it is flat, not extrapolated.
	if got := scaleConfidence(99, 4, 5, ConfidenceMedium, ConfidenceHigh); got != ConfidenceHigh {
		t.Errorf("above the range gave %v, want the ceiling", got)
	}
}

func TestPairHelpers(t *testing.T) {
	if IsPairValueKey("description") {
		t.Error("an ordinary key was treated as the value half of a pair")
	}
	if !IsPairValueKey("TagValue") {
		t.Error("TagValue was not recognised")
	}
	// A record with a name but no value half is not a pair.
	if got := PairLabel(map[string]any{"Name": "DB_PASSWORD"}); got != "" {
		t.Errorf("a lone name produced the label %q", got)
	}
	// Nor is one whose name is not a string.
	if got := PairLabel(map[string]any{"Name": 7, "Value": "x"}); got != "" {
		t.Errorf("a non-string name produced the label %q", got)
	}
}

func TestEntropyAndPlaceholderEdges(t *testing.T) {
	if got := shannonEntropy(""); got != 0 {
		t.Errorf("entropy of the empty string = %v", got)
	}
	if !looksPlaceholder("") {
		t.Error("the empty string is not a value anybody supplied")
	}
	if !looksPlaceholder("aaaaaaaaaaaa") {
		t.Error("a single repeated character carries no information")
	}
	if looksPlaceholder("hunter2") {
		t.Error("a weak credential was treated as a placeholder")
	}
}

func TestDetectShapeGuards(t *testing.T) {
	if f := DetectValue(""); f.Found() {
		t.Errorf("the empty value produced %q", f.Rule)
	}
	if f := DetectValue(RedactedMarker); f.Found() {
		t.Errorf("the marker produced %q", f.Rule)
	}
	// A resource path is long, mixed and slash-dense, and is not a credential.
	if f := DetectValue("projects/acme-prod/regions/us-central1/subnetworks/default"); f.Found() {
		t.Errorf("a resource reference produced %q", f.Rule)
	}
}

// Each decoder has to reject what is not its encoding, or the tier reports
// nonsense recovered from arbitrary bytes.
func TestDecodersRejectWhatIsNotTheirEncoding(t *testing.T) {
	cases := map[string]string{
		"mixed base64 alphabets":  "QUtJQUlPU0Z-RE5ON0V+QU1QTEU/",
		"odd-length hex":          "414b4941494f53464f444e4e3745584",
		"char codes out of range": "[65, 75, 73, 999, 73, 79, 83, 70, 79, 68, 78, 78, 55, 69, 88, 65, 77]",
		"char codes too few":      "[65, 75, 73]",
		"broken escape run":       `\x41\x4b\x49\xZZ\x49\x4f\x53\x46\x4f\x44\x4e\x4e\x37\x45\x58\x41\x4d`,
		"escapes with a tail":     `\x41\x4b\x49\x41\x49\x4f\x53\x46\x4f\x44\x4e\x4e\x37\x45\x58\x41\x4dtail`,
	}
	for name, v := range cases {
		if f := DetectValue(v); strings.Contains(f.Rule, ":") {
			t.Errorf("%s was decoded anyway: %s", name, f.Rule)
		}
	}

	// Decoded bytes that are not printable are not a credential as written.
	if plausiblePlaintext([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}) {
		t.Error("binary noise was accepted as plaintext")
	}
	if plausiblePlaintext([]byte("short")) {
		t.Error("a decode shorter than any credential was accepted")
	}
	// PEM key material carries newlines and tabs, so those are allowed.
	if !plausiblePlaintext([]byte("-----BEGIN RSA PRIVATE KEY-----\n\tMIIE\r\n")) {
		t.Error("PEM whitespace was rejected")
	}
}

func TestMergeSpansUnionsOverlaps(t *testing.T) {
	got := mergeSpans([][2]int{{10, 20}, {0, 5}, {15, 30}, {3, 8}})
	want := [][2]int{{0, 8}, {10, 30}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if got := mergeSpans(nil); got != nil {
		t.Errorf("mergeSpans(nil) = %v", got)
	}
}

// A rule's entropy floor exists for prefixes that are not distinctive on their
// own. It has to actually reject.
func TestRuleEntropyFloorRejects(t *testing.T) {
	var okta *Rule
	for i := range rules {
		if rules[i].ID == "okta-token" {
			okta = &rules[i]
		}
	}
	if okta == nil || okta.MinEntropy == 0 {
		t.Skip("okta-token no longer carries an entropy floor")
	}
	// Right shape, no entropy: forty repeated characters after the prefix.
	low := "00" + strings.Repeat("ab", 20)
	if _, _, ok := okta.find(low); ok {
		t.Error("a zero-entropy value cleared the entropy floor")
	}
	if f := DetectValue(low); f.Rule == "okta-token" {
		t.Error("detectShape reported it anyway")
	}
}

// The text gate rejects on the name as well as on the value, and both arms
// matter: without the name arm every camelCase assignment in a Go file becomes
// a finding.
func TestTextGateRejectsOnBothHalves(t *testing.T) {
	// A credential word in a camelCase identifier, unquoted: a variable, not a
	// configuration key.
	if got := ScanText("x.go", `nextPassword = someOtherValue`); len(got) != 0 {
		t.Errorf("a camelCase identifier was reported: %+v", got)
	}
	// A security-worded name beside a path is a setting, not key material.
	if got := ScanText("x.env", `TLS_CERT=/etc/ssl/certs/ca.pem`); len(got) != 0 {
		t.Errorf("a certificate path was reported: %+v", got)
	}
	// Numbers in any base are not credentials.
	for _, line := range []string{
		`PASSWORD_ROTATION_DAYS=90`,
		`SIOCSLIFTOKEN = -0x7ffb9698`,
		`token_budget = 0b1010101010101010`,
	} {
		if got := ScanText("x.go", line); len(got) != 0 {
			t.Errorf("%q was reported: %+v", line, got)
		}
	}
	// A dotted name whose last segment is empty cannot be judged.
	if looksConfigName("auth.") {
		t.Error("a trailing dot was treated as a config name")
	}
}

// The submatch fallback: a rule whose Secret index does not participate in the
// match falls back to the whole match rather than panicking on a -1 offset.
func TestRuleSecretIndexFallsBackToTheWholeMatch(t *testing.T) {
	r := Rule{
		ID: "test-optional-group", Category: CategoryGeneric, Confidence: ConfidenceHigh,
		Description: "a group that need not participate",
		Pattern:     regexp.MustCompile(`AKIA(?:(NEVER))?[A-Z0-9]{16}`),
		Secret:      1, // the group is optional and will not match
	}
	start, end, ok := r.find("AKIAIOSFODNN7EXAMPLE")
	if !ok {
		t.Fatal("the rule did not match at all")
	}
	if got := "AKIAIOSFODNN7EXAMPLE"[start:end]; got != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("span = %q, want the whole match", got)
	}
	// An index past the end of the submatch list falls back the same way.
	r.Secret = 9
	if start, end, ok = r.find("AKIAIOSFODNN7EXAMPLE"); !ok || start != 0 || end != 20 {
		t.Errorf("out-of-range Secret gave (%d,%d,%v)", start, end, ok)
	}
}

// valueSpan is handed a submatch slice in which exactly one value alternative
// participates. It reports "none" rather than returning a negative offset that
// would slice out of range.
func TestValueSpanReportsNoMatch(t *testing.T) {
	none := []int{0, 4, 0, 4, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1}
	if s, e, _ := valueSpan(none); s != -1 || e != -1 {
		t.Errorf("valueSpan with no participating group = (%d,%d)", s, e)
	}
	// A short slice, as a defensive caller might produce.
	if s, _, _ := valueSpan([]int{0, 4}); s != -1 {
		t.Errorf("valueSpan of a truncated slice = %d", s)
	}
}

// Two credentials on one line have to come back in position order, which is
// the only reason the findings are sorted at all.
func TestTwoFindingsOnOneLineAreOrdered(t *testing.T) {
	line := `a="AKIAIOSFODNN7EXAMPLE" b="ghp_1234567890abcdefghijklmnopqrstuvwx"`
	got := ScanText("x.go", line)
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(got), got)
	}
	if got[0].Column >= got[1].Column {
		t.Errorf("findings are not in position order: %d then %d", got[0].Column, got[1].Column)
	}
	if got[0].Rule != "aws-access-key-id" || got[1].Rule != "github-token" {
		t.Errorf("wrong order: %s then %s", got[0].Rule, got[1].Rule)
	}
}

// The two text-gate arms that reject on the NAME rather than the value.
func TestTextGateNameArms(t *testing.T) {
	// A credential word inside a camelCase identifier, unquoted. In a payload
	// this is a credential; in source it is a variable.
	if got := ScanText("x.go", `myPassword=hunter2xyz`); len(got) != 0 {
		t.Errorf("an unquoted camelCase name was accepted: %+v", got)
	}
	// Quoting it makes it a literal, and then it counts.
	if got := ScanText("x.go", `myPassword="hunter2xyz"`); len(got) != 1 {
		t.Errorf("a quoted literal under the same name was rejected: %+v", got)
	}
	// A schema-style security name beside encoded-looking material: tier three,
	// which in a document needs the name to look like configuration.
	if got := ScanText("x.json", `keySource: "aGVsbG8gd29ybGQxMjM0NTY3ODkw"`); len(got) != 0 {
		t.Errorf("a camelCase security name was accepted: %+v", got)
	}
	if got := ScanText("x.env", `KEY_SOURCE="aGVsbG8gd29ybGQxMjM0NTY3ODkw"`); len(got) != 1 {
		t.Errorf("the same value under a configuration name was rejected: %+v", got)
	}
}
