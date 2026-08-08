// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import (
	"strings"
	"testing"
)

func TestRedact_ByName(t *testing.T) {
	sensitive := []string{
		"DB_PASSWORD", "password", "STRIPE_SECRET_KEY", "apiKey", "API_KEY",
		"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "AUTH_HEADER", "SENTRY_DSN",
		"DATABASE_URL", "CLIENT_SECRET", "SESSION_SEED", "JWT_SIGNING_KEY",
		"SLACK_WEBHOOK", "PRIVATE_KEY_PEM", "TLS_CERT", "PASSPHRASE",
	}
	for _, name := range sensitive {
		if got, redacted := Redact(name, "plain-looking-value"); !redacted {
			t.Errorf("%s should be redacted by name, got %q", name, got)
		}
	}

	// Names that merely mention a key but identify a non-secret must survive:
	// downstream checks read them (e.g. "is this function using a customer key?").
	safe := map[string]string{
		"KMS_KEY_ARN":    "arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
		"KMS_KEY_ID":     "abcd-1234",
		"PUBLIC_KEY_URL": "https://example.com/keys.json",
		"BUCKET_NAME":    "my-app-assets",
		"LOG_LEVEL":      "debug",
		"REGION":         "us-east-1",
	}
	for name, value := range safe {
		if got, redacted := Redact(name, value); redacted {
			t.Errorf("%s=%q should not be redacted, got %q", name, value, got)
		}
	}
}

func TestRedact_ByValueShape(t *testing.T) {
	// Innocuous names carrying real credentials — the case name matching alone
	// never catches.
	cases := map[string]string{
		"UPLOADER":    "AKIAIOSFODNN7EXAMPLE",
		"CONFIG_BLOB": "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----",
		// Also the shape of a projected Kubernetes service-account token.
		"IDENTITY": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		"HEADER":   "Bearer sk-abcdef0123456789abcdef",
		"CI":       "ghp_1234567890abcdefghijklmnopqrstuvwx",
		"NOTIFY":   "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
		"BACKEND":  "postgres://app:s3cr3tpassword@db.internal:5432/app",
		"DIGEST":   "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"OPAQUE":   "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MEFCQ0RFRkdI",
	}
	for name, value := range cases {
		got, redacted := Redact(name, value)
		if !redacted {
			t.Errorf("%s=%q should be redacted by value shape", name, value)
		}
		if got != RedactedMarker {
			t.Errorf("%s: redacted value should be the marker, got %q", name, got)
		}
	}
}

func TestRedact_KeepsOrdinaryConfiguration(t *testing.T) {
	// Values a reader expects to get back out of the stored copy. Over-redaction
	// is cheap but not free: these are the fields checks and dependency mapping
	// rely on.
	cases := map[string]string{
		"BUCKET":       "prod-eu-west-1-assets",
		"FUNCTION_ARN": "arn:aws:lambda:us-east-1:123456789012:function:checkout-worker",
		"ENDPOINT":     "https://api.internal.example.com/v2/checkout",
		"TIMEOUT":      "30",
		"IMAGE":        "123456789012.dkr.ecr.us-east-1.amazonaws.com/app:1.4.2",
		"image":        "ghcr.io/acme/checkout:1.14.2",
		"nodeName":     "ip-10-0-3-14.ec2.internal",
		"PATH_PREFIX":  "/srv/app/current/shared/config",
		"EMPTY":        "",
	}
	for name, value := range cases {
		if got, redacted := Redact(name, value); redacted {
			t.Errorf("%s=%q should be kept, got %q", name, value, got)
		}
	}
}

// RedactInline: a credential inside a larger string.

// TestRedactInlineScrubsEmbeddedSecrets pins content scanning.
//
// Name and shape matching both examine a whole value, so neither catches a
// secret that is one line of a script. An EC2 user-data block or a GCE
// startup-script is an ordinary place to find an inline assignment, and
// wholesale capture persists them verbatim.
func TestRedactInlineScrubsEmbeddedSecrets(t *testing.T) {
	secrets := []struct{ in, mustNotContain string }{
		{"#!/bin/bash\nexport DB_PASSWORD=hunter2-real\napt-get update\n", "hunter2-real"},
		{"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY\n", "wJalrXUtnFEMI"},
		{"api_token: ghp_1234567890abcdefghijklmnop\n", "ghp_1234567890abcdefghijklmnop"},
	}
	for _, tc := range secrets {
		out := RedactInline(tc.in)
		if strings.Contains(out, tc.mustNotContain) {
			t.Errorf("an embedded secret survived: %q", out)
		}
		if !strings.Contains(out, RedactedMarker) {
			t.Errorf("nothing was redacted in %q -> %q", tc.in, out)
		}
	}

	// Non-secrets must survive, or a scrubbed script is unreadable and the
	// operator loses the ability to see what it does.
	keep := "LOG_LEVEL=info\nREGION=us-east-1\n"
	if out := RedactInline(keep); out != keep {
		t.Errorf("harmless assignments were redacted: %q -> %q", keep, out)
	}
}

// TestRedactInlineReachesIntoAQueryString is the regression for the leak that
// put a live credential in a shipped package.
//
// One scan of the whole string matches "https:" first and takes the entire URL
// as that name's value. The match is consumed, so nothing after it is examined
// and X-Amz-Signature went through intact — in an AWS transport error that
// reached both the stored record and an exported archive. The fix lives
// here rather than at the two call sites that had patched it, because a
// security control with three copies is a gap fixed in one and left open in the
// others.
func TestRedactInlineReachesIntoAQueryString(t *testing.T) {
	const sig = "sigDONOTSHIPa41b9c"
	in := "RequestError: url https://s3.amazonaws.com/b/k?X-Amz-Signature=" + sig
	out := RedactInline(in)

	if strings.Contains(out, sig) {
		t.Errorf("the presigned signature survived: %q", out)
	}
	// Only the signature goes. An operator reading a failed module needs to see
	// which call failed against what, so the message around it has to survive.
	want := "RequestError: url https://s3.amazonaws.com/b/k?X-Amz-Signature=" + RedactedMarker
	if out != want {
		t.Errorf("redaction was not surgical:\n got  %q\n want %q", out, want)
	}
}

// TestRedactInlineKeepsASecretSpanningASeparatorWhole pins the pass ordering,
// which is the part that is easy to get backwards.
//
// The whole-string scan has to run BEFORE the query split. A credential whose
// value legitimately contains "?" or "&" is one value; splitting first would
// hand the detector "PASSWORD=abc", "def" and "ghi", redact the first and
// publish the other two — a worse leak than the one being fixed, and one that
// looks redacted in the output.
func TestRedactInlineKeepsASecretSpanningASeparatorWhole(t *testing.T) {
	out := RedactInline("PASSWORD=abc?def&ghi could not be used")
	for _, leak := range []string{"abc", "def", "ghi"} {
		if strings.Contains(out, leak) {
			t.Errorf("a split value leaked %q: %q", leak, out)
		}
	}
	if want := "PASSWORD=" + RedactedMarker + " could not be used"; out != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

// TestRedactInlineRedactsOnlyTheCredentialParameter keeps the split honest in
// the other direction. A query string is mostly ordinary parameters, and an
// operator diagnosing a failure reads them: which object, which version, which
// expiry. Redacting the whole query because one parameter was a credential
// would make the message useless.
func TestRedactInlineRedactsOnlyTheCredentialParameter(t *testing.T) {
	in := "https://s3.amazonaws.com/b/k?versionId=abc123&X-Amz-Signature=deadbeefcafe&X-Amz-Expires=900"
	want := "https://s3.amazonaws.com/b/k?versionId=abc123&X-Amz-Signature=" + RedactedMarker + "&X-Amz-Expires=900"
	if out := RedactInline(in); out != want {
		t.Errorf("got  %q\nwant %q", out, want)
	}
}

// TestRedactInlineLeavesAnOrdinaryURLAlone is the cost side of the same fix.
// Splitting a string exposes every query parameter to the detector, so a URL
// carrying no credential is the case that proves the split did not turn into
// blanket redaction of anything with a "?" in it.
func TestRedactInlineLeavesAnOrdinaryURLAlone(t *testing.T) {
	for _, keep := range []string{
		"https://s3.us-east-1.amazonaws.com/bucket/key?versionId=3&partNumber=2",
		"GET https://ec2.eu-west-1.amazonaws.com/?Action=DescribeInstances&Version=2016-11-15",
		"arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
	} {
		if out := RedactInline(keep); out != keep {
			t.Errorf("an ordinary string was altered:\n got  %q\n want %q", out, keep)
		}
	}
}
