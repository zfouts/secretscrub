// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import (
	"strings"
	"testing"
)

// RedactText: rewriting a document, and removing exactly what a scan reports.

// A credential whose value legitimately contains a query separator must be
// replaced whole before any split can cut it in half and publish the tail.
func TestScanKeepsASecretSpanningASeparatorWhole(t *testing.T) {
	clean := RedactText("PASSWORD=abc?def&ghi")
	for _, leak := range []string{"abc", "def", "ghi"} {
		if strings.Contains(clean, leak) {
			t.Errorf("%q survived in %q", leak, clean)
		}
	}
}

func TestRedactTextKeepsEverythingElseByteForByte(t *testing.T) {
	clean := RedactText(envFile)
	for _, keep := range []string{"# deployment", "export AWS_ACCESS_KEY_ID=", "LOG_LEVEL=info", "REGION=us-east-1"} {
		if !strings.Contains(clean, keep) {
			t.Errorf("%q was lost:\n%s", keep, clean)
		}
	}
	for _, gone := range []string{"AKIAIOSFODNN7EXAMPLE", "hunter2", "AIzaSyD-1234567890abcdefghijklmnopqrstuv"} {
		if strings.Contains(clean, gone) {
			t.Errorf("%q survived:\n%s", gone, clean)
		}
	}
	// Quoting survives, so the file it came from still parses.
	if !strings.Contains(clean, `api-key: "`+RedactedMarker+`"`) {
		t.Errorf("the quotes around a redacted value were eaten:\n%s", clean)
	}
	if !strings.HasSuffix(clean, "\n") {
		t.Error("the trailing newline was lost")
	}
	// Idempotent: a second pass changes nothing.
	if again := RedactText(clean); again != clean {
		t.Errorf("a second pass changed the output:\n%s", again)
	}
}

// Replacing only the header of a PEM block produces a file that reads as
// scrubbed while still holding the key. The body is the secret.
func TestRedactTextRemovesAWholePEMBlock(t *testing.T) {
	const key = `some preamble
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy
vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9
-----END RSA PRIVATE KEY-----
trailing text
`
	clean := RedactText(key)
	for _, gone := range []string{"MIIEowIBAAKCAQEAy8Dbv8prpJ", "vGZlGJpmn65"} {
		if strings.Contains(clean, gone) {
			t.Errorf("key material survived:\n%s", clean)
		}
	}
	// The shape of the file survives, so a reader can see what was removed.
	for _, keep := range []string{"some preamble", "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----", "trailing text"} {
		if !strings.Contains(clean, keep) {
			t.Errorf("%q was lost:\n%s", keep, clean)
		}
	}
	if n := strings.Count(clean, RedactedMarker); n != 1 {
		t.Errorf("the body was replaced with %d markers, want one for the block:\n%s", n, clean)
	}
}

// A GCP service account key writes its private key onto one line with the
// newlines escaped, so the block handling that catches a .pem file never sees a
// BEGIN and an END on separate lines. The assignment beside it is what saves
// this, and the value it claims has to be the whole escaped key rather than the
// header that announced it.
func TestRedactTextRemovesAnEscapedPEMOnOneLine(t *testing.T) {
	const key = `{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n-----END PRIVATE KEY-----\n","client_email":"svc@acme.iam.gserviceaccount.com"}`

	got := ScanText("key.json", key)
	if len(got) != 1 || got[0].Key != "private_key" {
		t.Fatalf("got %d findings, want one under private_key:\n%+v", len(got), got)
	}

	clean := RedactText(key)
	if strings.Contains(clean, "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ") {
		t.Errorf("the key body survived:\n%s", clean)
	}
	// The structure survives, so the file still parses and still says what it
	// is. Only the value changed.
	if !strings.Contains(clean, `"type":"service_account"`) ||
		!strings.Contains(clean, `"client_email":"svc@acme.iam.gserviceaccount.com"`) {
		t.Errorf("structural fields were rewritten:\n%s", clean)
	}
	if !strings.Contains(clean, `"private_key":"`+RedactedMarker+`"`) {
		t.Errorf("the key was not replaced cleanly:\n%s", clean)
	}
}

// A template reference is not a credential, and rewriting it breaks the file it
// appears in while protecting nothing. This is the one place a rewrite removes
// less than a scan reports, so it is pinned in both directions.
func TestRedactTextLeavesTemplateReferencesIntact(t *testing.T) {
	const tmpl = "password: ${DB_PASSWORD}\ntoken: {{ .Values.token }}\n"
	if clean := RedactText(tmpl); clean != tmpl {
		t.Errorf("a template was rewritten:\n got  %q\n want %q", clean, tmpl)
	}
	if got := ScanText("values.yaml", tmpl); len(got) == 0 {
		t.Error("a committed placeholder was not reported at all")
	} else if got[0].Rule != RulePlaceholder {
		t.Errorf("reported as %q, want %q", got[0].Rule, RulePlaceholder)
	}
}

// RedactInline serves the tree walker and runs against captured provider
// payloads, where a false positive destroys a stored field. The text path
// is allowed to be more permissive; it must not have made the other one so.
func TestTheTextPathDidNotLoosenRedactInline(t *testing.T) {
	for _, keep := range []string{
		"https://s3.us-east-1.amazonaws.com/bucket/key?versionId=3&partNumber=2",
		"GET https://ec2.eu-west-1.amazonaws.com/?Action=DescribeInstances&Version=2016-11-15",
		"arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
		"LOG_LEVEL=info\nREGION=us-east-1\n",
	} {
		if out := RedactInline(keep); out != keep {
			t.Errorf("an ordinary string was altered:\n got  %q\n want %q", out, keep)
		}
	}
}

// A PEM BEGIN marker quoted inside a line is not the start of a block, and
// treating it as one was a data-destruction bug rather than a missed finding.
//
// The rewriter used to write the marker line out verbatim and then swallow
// every line after it into a single marker, waiting for an END that never
// came. The credential survived and the rest of the file did not, which under
// -redact -w meant a truncated file.
func TestAQuotedPEMMarkerDoesNotSwallowTheFile(t *testing.T) {
	const doc = `{
  "note": "-----BEGIN PGP SIGNATURE-----",
  "region": "us-east-1",
  "replicas": 3,
  "endpoint": "https://api.internal.example.com/v2/checkout"
}
`
	clean := RedactText(doc)

	// Everything after the marker line survives.
	for _, keep := range []string{
		`"region": "us-east-1"`, `"replicas": 3`,
		`"endpoint": "https://api.internal.example.com/v2/checkout"`, "}",
	} {
		if !strings.Contains(clean, keep) {
			t.Errorf("%q was swallowed:\n%s", keep, clean)
		}
	}
	// And the marker itself is redacted rather than written out verbatim.
	if strings.Contains(clean, "BEGIN PGP SIGNATURE") {
		t.Errorf("the marker survived redaction:\n%s", clean)
	}
	if strings.Count(clean, "\n") != strings.Count(doc, "\n") {
		t.Errorf("the line count changed:\n%s", clean)
	}
	// The rewritten document scans clean, which is the contract.
	if got := ScanText("a.json", clean); len(got) != 0 {
		t.Errorf("the rewritten document still reports %+v", got)
	}
}

// The same for a marker embedded in prose, and for one indented inside a block
// scalar, which is how a key legitimately appears in YAML.
func TestPEMDelimitersAreRecognisedOnlyOnTheirOwnLine(t *testing.T) {
	log := "error: the file began with -----BEGIN CERTIFICATE----- and was rejected\nnext line survives\n"
	if clean := RedactText(log); !strings.Contains(clean, "next line survives") {
		t.Errorf("a marker in prose swallowed the next line:\n%s", clean)
	}

	// An indented delimiter is still a delimiter: YAML block scalars indent the
	// whole key, and the body after it is real key material.
	yaml := "key: |\n  -----BEGIN RSA PRIVATE KEY-----\n  MIIEowIBAAKCAQEAy8Dbv8prpJ\n  -----END RSA PRIVATE KEY-----\ntrailing: kept\n"
	clean := RedactText(yaml)
	if strings.Contains(clean, "MIIEowIBAAKCAQEAy8Dbv8prpJ") {
		t.Errorf("indented key material survived:\n%s", clean)
	}
	if !strings.Contains(clean, "trailing: kept") {
		t.Errorf("the line after the block was swallowed:\n%s", clean)
	}
}
