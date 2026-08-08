// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import (
	"fmt"
	"strings"
	"testing"
)

// A credential is not one shape in one place. The same key appears in a .env,
// in JSON, in YAML, quoted and bare, with a name beside it and with none at
// all, and a rule that only fires in one of those is a rule that mostly does
// not fire.
//
// TestEveryRuleMatchesItsOwnFormat proves each pattern matches a value. This
// proves each value is still found once it is written into a file, which is
// where the text gate, the assignment grammar and the line scanner all get a
// say. It is the property an external harness was measuring; it belongs here,
// where it runs on every commit and needs no generator.
func TestEveryRuleIsFoundInEveryContext(t *testing.T) {
	contexts := []struct {
		name  string
		line  func(key, val string) string
		bare  bool // no name beside the value: only the shape can save it
		space bool // can hold a value containing a space
	}{
		{name: "env", line: func(k, v string) string { return k + "=" + v }},
		{name: "shell", line: func(k, v string) string { return "export " + k + "=" + v }},
		{name: "dockerfile", line: func(k, v string) string { return "ENV " + k + "=" + v }},
		{name: "json", space: true, line: func(k, v string) string { return fmt.Sprintf("  %q: %q,", k, v) }},
		{name: "yaml", space: true, line: func(k, v string) string { return fmt.Sprintf("  %s: %q", k, v) }},
		{name: "toml", space: true, line: func(k, v string) string { return fmt.Sprintf("%s = %q", k, v) }},
		{name: "bare", bare: true, line: func(_, v string) string { return "request failed: " + v }},
	}

	// A deliberately uninformative name, so the NAME cannot do the shape rules'
	// work for them. This measures the registry, not the word list.
	const key = "UPLOADER"

	var planted, found int
	misses := map[string][]string{}

	for _, r := range Rules() {
		if r.Confidence < DefaultMinConfidence {
			continue // the fuzzy tail is below the cut on purpose
		}
		sample, ok := samples[r.ID]
		if !ok {
			continue // TestEveryRuleMatchesItsOwnFormat already fails for this
		}
		for _, ctx := range contexts {
			if strings.ContainsAny(sample, " \t") && !ctx.space {
				// An unquoted value cannot hold a space. See the known limits
				// in docs/auditing.md.
				continue
			}
			if strings.ContainsAny(sample, "\"\\") && ctx.space {
				continue // nor can a quoted one hold a quote
			}
			line := ctx.line(key, sample)
			planted++
			hits := ScanText("f", line)
			if len(hits) > 0 {
				found++
				// Whatever claimed it, the rewrite has to remove it.
				if clean := RedactText(line); strings.Contains(clean, sample) {
					t.Errorf("%s in %s: reported as %q but survived redaction\n  %s",
						r.ID, ctx.name, hits[0].Rule, line)
				}
				continue
			}
			misses[r.ID] = append(misses[r.ID], ctx.name)
		}
	}

	if planted == 0 {
		t.Fatal("nothing was planted; this test has stopped testing anything")
	}
	// Every miss is listed rather than counted, so a regression names itself.
	for id, ctxs := range misses {
		t.Errorf("%s was not found in: %s", id, strings.Join(ctxs, ", "))
	}
	t.Logf("%d/%d planted credentials found across %d contexts", found, planted, len(contexts))
}

// The same credentials, encoded. A rule that only fires on the plaintext is
// half a rule once somebody base64s the value into a config file.
func TestEveryRuleSurvivesAnEncoding(t *testing.T) {
	var planted, found int
	for _, r := range Rules() {
		if r.Confidence < DefaultMinConfidence {
			continue
		}
		sample, ok := samples[r.ID]
		if !ok || !strings.Contains(r.Pattern.String(), `\b`) {
			// A pattern that needs surrounding context does not survive an
			// encode, because the context is not part of the credential.
			continue
		}
		for name, encoded := range encodings(sample) {
			planted++
			line := "BLOB=" + encoded
			if hits := ScanText("f", line); len(hits) > 0 {
				found++
				if !strings.HasSuffix(hits[0].Rule, ":"+r.ID) {
					t.Errorf("%s encoded as %s was attributed to %q", r.ID, name, hits[0].Rule)
				}
				continue
			}
			t.Errorf("%s encoded as %s was not found", r.ID, name)
		}
	}
	if planted == 0 {
		t.Fatal("nothing was planted")
	}
	t.Logf("%d/%d encoded credentials found", found, planted)
}

// The lookalikes. Everything here is something a real repository is full of,
// and none of it is a credential. A scanner that reports these is one people
// turn off.
func TestLookalikesAreNotReported(t *testing.T) {
	lookalikes := []string{
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", // sha256
		"e83c5163316f89bfbde7d9ab23ca2e25604af290",                         // git sha
		"4d87c09dd243c73c6fce67bdae31018f",                                 // 32-hex id
		"sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", // UUID
		"arn:aws:lambda:us-east-1:123456789012:function:checkout-worker",
		"arn:aws:iam::123456789012:role/service-role/lambda-execution",
		"projects/acme-prod/regions/us-central1/subnetworks/default",
		"zones/us-central1-a/machineTypes/e2-standard-4",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/checkout:1.14.2-alpine",
		"ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
		"EncryptionAtRestWithPlatformAndCustomerKeys",
		"2026-07-01T00:00:00Z",
		"pages-worker--6305616-production",
		"prod-eu-west-1-assets-replica",
		"application/vnd.docker.distribution.manifest.v2+json",
		"01HQ8X7Z9K4M2N6P8R0T3V5W7Y", // ULID
		"v1.28.4-eks-2d98532",
		"127.0.0.1:8080",
	}
	contexts := []func(v string) string{
		func(v string) string { return "UPLOADER=" + v },
		func(v string) string { return fmt.Sprintf("  %q: %q,", "UPLOADER", v) },
		func(v string) string { return "  uploader: " + v },
		func(v string) string { return "request completed: " + v },
	}
	var checked int
	for _, v := range lookalikes {
		for _, ctx := range contexts {
			line := ctx(v)
			checked++
			if hits := ScanText("f", line); len(hits) > 0 {
				t.Errorf("%q reported as %s (%v)\n  %s", v, hits[0].Rule, hits[0].Confidence, line)
			}
			// And a rewrite leaves it exactly as it was.
			if clean := RedactText(line); clean != line {
				t.Errorf("%q was rewritten:\n  got  %s\n  want %s", v, clean, line)
			}
		}
	}
	t.Logf("%d lookalikes across %d contexts, none reported", len(lookalikes), len(contexts))
}
