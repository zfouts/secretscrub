// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every value below is synthetic. They are shaped like the real thing and are
// not the real thing, which is the only way to test a shape detector.
func rep(s string, n int) string { return strings.Repeat(s, n) }

// TestEveryRuleMatchesItsOwnFormat is the registry's regression test, and it
// earns its length twice over.
//
// The obvious half is that a pattern typed wrong finds nothing, silently and
// forever: a scanner that misses a format reports "no credentials found" in
// exactly the same words as one that checked. The less obvious half is the
// Contains prefilter. It is an optimisation the detector consults BEFORE the
// pattern, so a prefilter that disagrees with its own pattern — a lowercase
// literal that the regex spells with a case-sensitive uppercase, a prefix
// mistyped by one character — disables the rule completely while leaving a
// perfectly good regex sitting in the file for a reader to be reassured by.
//
// Asserting the rule ID rather than "something matched" is deliberate too. Two
// rules claiming the same string is how a specific format gets reported as a
// generic one, and the caller loses the single most useful thing in the
// finding: which provider to go and rotate.
// samples is one synthetic credential per rule, shaped like the real thing and
// not the real thing. Shared with the context tests, which plant these into
// files rather than testing them as bare values.
var samples = map[string]string{
	// Key material.
	"private-key-pem":       "-----BEGIN RSA PRIVATE KEY-----",
	"pgp-message":           "-----BEGIN PGP MESSAGE-----",
	"certificate-pem":       "-----BEGIN CERTIFICATE-----",
	"putty-private-key":     "PuTTY-User-Key-File-2: ssh-rsa",
	"age-secret-key":        "AGE-SECRET-KEY-1" + rep("QZRFR8", 9),
	"kubeconfig-client-key": "client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQoxMjM0NTY3",

	// Generic bearer shapes.
	"jwt":                         "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	"authorization-header":        "Bearer abcdefgh12345678",
	"authorization-header-inline": "Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l",
	"url-embedded-credentials":    "postgres://app:s3cr3tpassword@db.internal:5432/app",
	"jdbc-password":               "jdbc:mysql://db.internal:3306/app?user=app&password=s3cr3tpassword",
	"unix-password-hash":          "$2b$12$KIXQJ0m0e2n3o4p5q6r7s8",

	// AWS.
	"aws-access-key-id": "AKIAIOSFODNN7EXAMPLE",
	"aws-mws-token":     "amzn.mws.4ea38b7b-f563-7709-4bae-87aea1234567",

	// Azure.
	"azure-storage-account-key": "AccountKey=" + rep("YWJjZGVmZ2hpams", 5) + "==",
	"azure-shared-access-key":   "SharedAccessKey=abcdefghij0123456789ABCDEF=",
	"azure-sas-signature":       "?sig=" + rep("aB3xY9zQ", 6),
	"azure-ad-client-secret":    "aB18Q~xY9zAbCdEfGhIjKlMnOpQrStUvWxYz1234",

	// GCP.
	"google-api-key":               "AIzaSyD-1234567890abcdefghijklmnopqrstuv",
	"google-oauth-refresh-token":   "1//0gLm" + rep("aB3xY9zQ", 5),
	"firebase-cloud-messaging-key": "AAAAaB3xY9z:APA91b" + rep("aB3xY9zQ", 14),

	// Other clouds and infrastructure tooling.
	"alibaba-access-key-id":    "LTAI5tABCDEFGHIJKLMN",
	"digitalocean-token":       "dop_v1_" + rep("0123456789abcdef", 4),
	"cloudflare-origin-ca-key": "v1.0-" + rep("0123456789ab", 2) + "-" + rep("aB3xY9zQ", 18),
	"hashicorp-vault-token":    "hvs.CAESIJ" + rep("aB3xY9zQ", 3),
	"terraform-cloud-token":    "abcdefgh123456.atlasv1." + rep("aB3xY9zQ", 3),

	// Forges and package registries.
	"github-token":            "ghp_1234567890abcdefghijklmnopqrstuvwx",
	"github-fine-grained-pat": "github_pat_11ABCDEFG0" + rep("aB3xY9zQ", 3),
	"gitlab-token":            "glpat-" + rep("aB3xY9zQ", 3),
	"npm-token":               "npm_" + rep("aB3xY9zQ", 4) + "aB3x",
	"pypi-token":              "pypi-AgEIcHlwaS5vcmc" + rep("aB3xY9zQ", 7),
	"rubygems-token":          "rubygems_" + rep("0123456789ab", 4),
	"docker-hub-pat":          "dckr_pat_" + rep("aB3xY9zQ", 3),
	"nuget-api-key":           "oy2" + rep("abcdefghijk", 3) + "abcdefghij",
	"jfrog-token":             "AKCp" + rep("aB3xY9zQ", 7),
	"sonarqube-token":         "sqp_" + rep("0123456789", 4),

	// Chat, mail and paging.
	"slack-token":        "xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx",
	"slack-app-token":    "xapp-1-A01234567-1234567890123-" + rep("aB3xY9zQ", 3),
	"slack-webhook":      "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
	"discord-webhook":    "https://discord.com/api/webhooks/123456789012345678/aB3xY9zQaB3xY9zQ",
	"discord-bot-token":  "MTIzNDU2Nzg5MDEyMzQ1Njc4.aB3xY9.zQaB3xY9zQaB3xY9zQaB3xY9zQaB3",
	"teams-webhook":      "https://acme.webhook.office.com/webhookb2/aB3xY9zQ/IncomingWebhook/aB3xY9zQ",
	"telegram-bot-token": "123456789:AA" + rep("aB3xY9zQ", 4),
	"sendgrid-api-key":   "SG." + rep("aB3xY9zQ", 2) + "." + rep("aB3xY9zQ", 3),
	"mailgun-api-key":    "key-" + rep("0123456789abcdef", 2),
	"mailchimp-api-key":  rep("0123456789abcdef", 2) + "-us14",
	"twilio-api-key":     "SK" + rep("0123456789abcdef", 2),

	// Payments and commerce.
	"stripe-api-key":         "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
	"stripe-webhook-secret":  "whsec_" + rep("aB3xY9zQ", 3),
	"square-token":           "sq0atp-" + rep("aB3xY9zQ", 3),
	"braintree-access-token": "access_token$production$abcdefgh12345678$" + rep("0123456789abcdef", 2),
	"shopify-token":          "shpat_" + rep("0123456789abcdef", 2),
	"atlassian-api-token":    "ATATT3" + rep("aB3xY9zQ", 3),
	"linear-api-key":         "lin_api_" + rep("aB3xY9zQ", 4),
	"notion-token":           "secret_" + rep("aB3xY9zQ", 5),
	"asana-pat":              "1/1234567890123456:" + rep("0123456789abcdef", 2),
	"dropbox-token":          "sl." + rep("aB3xY9zQ", 17),
	"figma-token":            "figd_" + rep("aB3xY9zQ", 6),
	"postman-api-key":        "PMAK-" + rep("0123456789ab", 2) + "-" + rep("0123456789ab", 2) + "0123456789",
	"newrelic-key":           "NRAK-" + rep("ABCDEFGHI", 3),
	"grafana-token":          "glsa_" + rep("aB3xY9zQ", 4) + "_aB3xY9zQ",
	"databricks-token":       "dapi" + rep("0123456789abcdef", 2),
	"sentry-dsn":             "https://" + rep("0123456789abcdef", 2) + "@o1.ingest.sentry.io/1234567",
	"okta-token":             "00" + "aB3xY9zQwErTyUiOpAsDfGhJkLzXcVbNmQ1w2E3r",
	"hex-private-key-0x":     "0x" + rep("0123456789abcdef", 4),
	"anthropic-api-key":      "sk-ant-api03-" + rep("aB3xY9zQ", 11),
	"openai-api-key":         "sk-proj-" + rep("aB3xY9zQ", 4),
	"openai-api-key-legacy":  "sk-" + rep("aB3xY9zQ", 5),
	"huggingface-token":      "hf_" + rep("aB3xY9zQ", 5),
	"replicate-token":        "r8_" + rep("aB3xY9zQ", 5),
}

func TestEveryRuleMatchesItsOwnFormat(t *testing.T) {
	for _, r := range Rules() {
		sample, ok := samples[r.ID]
		if !ok {
			t.Errorf("rule %q has no sample: every rule needs one, or a typo in it is invisible", r.ID)
			continue
		}
		t.Run(r.ID, func(t *testing.T) {
			// The prefilters and the pattern have to agree, and the
			// prefilters run first, so a disagreement disables the rule
			// outright. A MinLen set one character too high, or a Contains
			// spelled with the wrong case, silently switches it off while
			// leaving a perfectly good regex in the file.
			if !ruleApplies(r, strings.ToLower(sample)) {
				t.Fatalf("prefilter rejects the rule's own sample (Contains=%q MinLen=%d, sample is %d chars): the rule can never fire",
					r.Contains, r.MinLen, len(sample))
			}
			if _, _, ok := r.find(sample); !ok {
				t.Fatalf("pattern does not match its own sample %q", sample)
			}
			got := DetectValue(sample)
			if got.Rule != r.ID {
				t.Errorf("sample was attributed to %q at %.2f, not to %q",
					got.Rule, got.Confidence, r.ID)
			}
			if got.Category != r.Category {
				t.Errorf("category = %q, want %q", got.Category, r.Category)
			}
		})
	}
}

// ruleApplies mirrors the unexported prefilter so the test exercises the same
// gate the detector does.
func ruleApplies(r Rule, lower string) bool {
	return r.applies(lower)
}

// A rule's confidence has to survive contact with Redact, or the ladder is
// documentation rather than behavior.
func TestConfidenceDecidesRedaction(t *testing.T) {
	// Above the cut: redacted by a default scanner.
	for _, value := range []string{
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_1234567890abcdefghijklmnopqrstuvwx",
		"sk_live_4eC39HqLyjWDarjtT1zdp7dc",
	} {
		if _, redacted := Redact("anything", value); !redacted {
			t.Errorf("%q cleared the default cut but survived", value)
		}
	}

	// Below the cut on purpose. A certificate is public material and a
	// 0x-prefixed hash is indistinguishable from a wallet key, so both are
	// reported only to a caller that asked for the fuzzy tail.
	tail := map[string]string{
		"certificate-pem":    "-----BEGIN CERTIFICATE-----",
		"hex-private-key-0x": "0x" + rep("0123456789abcdef", 4),
	}
	for rule, value := range tail {
		f := DetectValue(value)
		if f.Rule != rule {
			t.Fatalf("%s: detected as %q", rule, f.Rule)
		}
		if f.Confidence >= DefaultMinConfidence {
			t.Errorf("%s scores %.2f, which is at or above the default cut", rule, f.Confidence)
		}
		if _, redacted := Redact("body", value); redacted {
			t.Errorf("%s was redacted at the default cut", rule)
		}
		if _, redacted := NewScanner(ConfidenceLow).Redact("body", value); !redacted {
			t.Errorf("%s survived a scanner that asked for the tail", rule)
		}
	}
}

// The registry as a whole: every group wired in, every ID unique, every rule
// complete.

// Rules() hands out a copy. The registry being one shared implementation is the
// reason this package exists, so a caller inspecting it must not be able to
// edit it.
func TestRulesAreNotModifiableByCallers(t *testing.T) {
	got := Rules()
	if len(got) == 0 {
		t.Fatal("no rules")
	}
	id := got[0].ID
	got[0].ID = "clobbered"
	got[0].Confidence = 0
	if again := Rules(); again[0].ID != id {
		t.Errorf("the registry was modified through Rules(): %q", again[0].ID)
	}
}

// TestEveryRuleGroupIsRegistered is the guard the split into rules_*.go needs.
//
// The failure mode it exists for is silent and total: add rules_foo.go with a
// fooRules group, forget the line in slices.Concat, and every rule in it stops
// existing. Nothing else notices — the package compiles, the sample test only
// iterates what the registry already contains, and the scanner reports "no
// credentials found" in exactly the same words as one that checked.
//
// Reading the source is unusual for a test, but it is the only place the
// mistake is visible: a package-level var that nobody references is legal Go.
func TestEveryRuleGroupIsRegistered(t *testing.T) {
	files, err := filepath.Glob("rules_*.go")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := os.ReadFile("rules.go")
	if err != nil {
		t.Fatal(err)
	}
	declared := regexp.MustCompile(`(?m)^var (\w+Rules) = \[\]Rule\{`)

	var groups int
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range declared.FindAllSubmatch(src, -1) {
			groups++
			name := string(m[1])
			if !strings.Contains(string(registry), "\t"+name+",") {
				t.Errorf("%s declares %s, which rules.go never adds to the registry: "+
					"every rule in it is dead", f, name)
			}
		}
	}
	if groups == 0 {
		t.Fatal("found no rule groups; this test has stopped testing anything")
	}
	t.Logf("%d rule groups, %d rules", groups, len(Rules()))
}

// A duplicated ID makes two rules indistinguishable in a report, a baseline and
// a suppression list. It is an easy mistake when a provider is added by copying
// the entry above it.
func TestRuleIDsAreUnique(t *testing.T) {
	seen := make(map[string]bool)
	for _, r := range Rules() {
		if seen[r.ID] {
			t.Errorf("duplicate rule ID %q", r.ID)
		}
		seen[r.ID] = true
	}
}

// Confidence outside 0..1 would break every threshold comparison silently.
func TestRuleConfidenceIsInRange(t *testing.T) {
	for _, r := range Rules() {
		if r.Confidence <= 0 || r.Confidence > 1 {
			t.Errorf("%s has confidence %v, outside (0, 1]", r.ID, r.Confidence)
		}
		if r.ID == "" || r.Description == "" || r.Category == "" || r.Pattern == nil {
			t.Errorf("%s is missing a required field: %+v", r.ID, r)
		}
	}
}
