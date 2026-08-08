// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import (
	"strings"
	"testing"
)

const envFile = `# deployment
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
DB_PASSWORD=hunter2
api-key: "AIzaSyD-1234567890abcdefghijklmnopqrstuv"
LOG_LEVEL=info
REGION=us-east-1
`

func TestScanTextLocatesEachFinding(t *testing.T) {
	got := ScanText("deploy.env", envFile)
	if len(got) != 3 {
		t.Fatalf("got %d findings, want 3:\n%+v", len(got), got)
	}
	want := []struct {
		rule string
		line int
		key  string
	}{
		// No key on the first: "access_key_id" is on the allowlist, because a
		// key's ID is a reference to a credential rather than one, so the name
		// tier declines to speak and the shape rule answers on its own.
		{"aws-access-key-id", 2, ""},
		{RuleCredentialName, 3, "DB_PASSWORD"},
		{"google-api-key", 4, "api-key"},
	}
	for i, w := range want {
		f := got[i]
		if f.Rule != w.rule || f.Line != w.line || f.Key != w.key {
			t.Errorf("finding %d = %s at line %d under %q, want %s at %d under %q",
				i, f.Rule, f.Line, f.Key, w.rule, w.line, w.key)
		}
		if f.Path != "deploy.env" {
			t.Errorf("finding %d lost its path: %q", i, f.Path)
		}
		// The column has to point AT the credential, not at the line, or a
		// reviewer following the report lands in the wrong place.
		line := strings.Split(envFile, "\n")[f.Line-1]
		if f.Column < 1 || f.Column > len(line) {
			t.Errorf("finding %d column %d is outside its line", i, f.Column)
		}
		if !strings.HasPrefix(line[f.Column-1:], f.Secret) {
			t.Errorf("finding %d column %d does not point at %q", i, f.Column, f.Secret)
		}
	}
}

// A URL hides an assignment from a single pass: the scan meets "https:" first,
// takes the whole remainder as that name's value, and never looks inside. The
// signature on a presigned request is exactly what gets missed.
func TestScanReachesIntoAQueryString(t *testing.T) {
	const line = "RequestError: https://s3.amazonaws.com/b/k?versionId=abc123&X-Amz-Signature=deadbeefcafe1234&X-Amz-Expires=900"
	got := ScanText("err.log", line)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1:\n%+v", len(got), got)
	}
	if got[0].Key != "X-Amz-Signature" {
		t.Errorf("found %q, want the signature parameter", got[0].Key)
	}

	clean := RedactText(line)
	if strings.Contains(clean, "deadbeefcafe1234") {
		t.Errorf("the signature survived redaction: %q", clean)
	}
	want := "RequestError: https://s3.amazonaws.com/b/k?versionId=abc123&X-Amz-Signature=" +
		RedactedMarker + "&X-Amz-Expires=900"
	if clean != want {
		t.Errorf("redaction altered more than the signature:\n got  %q\n want %q", clean, want)
	}
}

// Findings and rewrites are the same score read at the same cut, so raising the
// cut has to move both together.
func TestScannerCutAppliesToBothHalves(t *testing.T) {
	const line = `db_password = "changeme"`
	strict := NewScanner(0.7)
	if got := strict.ScanText("x", line); len(got) != 0 {
		t.Errorf("a placeholder was reported above its score: %+v", got)
	}
	if got := defaultScanner.ScanText("x", line); len(got) != 1 {
		t.Errorf("the placeholder was not reported at the default cut: %+v", got)
	}
	if clean := strict.RedactText(line); clean != line {
		t.Errorf("a strict scanner rewrote a line it would not report: %q", clean)
	}
}

func TestScanReaderAgreesWithScanText(t *testing.T) {
	fromReader, err := ScanReader("deploy.env", strings.NewReader(envFile))
	if err != nil {
		t.Fatalf("ScanReader: %v", err)
	}
	fromText := ScanText("deploy.env", envFile)
	if len(fromReader) != len(fromText) {
		t.Fatalf("reader found %d, text found %d", len(fromReader), len(fromText))
	}
	for i := range fromText {
		if fromReader[i] != fromText[i] {
			t.Errorf("finding %d differs:\n reader %+v\n text   %+v", i, fromReader[i], fromText[i])
		}
	}
}
