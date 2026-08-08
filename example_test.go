// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub_test

import (
	"fmt"

	"github.com/zfouts/secretscrub"
)

// Redact answers for a single key/value pair. The key is treated as naming the
// value directly.
func ExampleRedact() {
	fmt.Println(secretscrub.Redact("DB_PASSWORD", "hunter2"))
	fmt.Println(secretscrub.Redact("region", "us-east-1"))
	// Output:
	// <redacted> true
	// us-east-1 false
}

// RedactTree walks a decoded payload. Structure is preserved and only leaf
// strings are examined, so a name that is not a credential survives next to one
// that is.
func ExampleRedactTree() {
	payload := map[string]any{
		"name":   "checkout",
		"region": "us-east-1",
		"env": map[string]any{
			"LOG_LEVEL":   "info",
			"DB_PASSWORD": "hunter2",
			// An innocuous name holding a real credential: caught by shape,
			// which is what name matching alone would miss.
			"UPLOADER": "AKIAIOSFODNN7EXAMPLE",
		},
	}

	clean := secretscrub.RedactTree("", payload).(map[string]any)
	env := clean["env"].(map[string]any)
	for _, row := range [][2]any{
		{"name", clean["name"]},
		{"region", clean["region"]},
		{"LOG_LEVEL", env["LOG_LEVEL"]},
		{"DB_PASSWORD", env["DB_PASSWORD"]},
		{"UPLOADER", env["UPLOADER"]},
	} {
		fmt.Printf("%-12v %v\n", row[0], row[1])
	}
	// Output:
	// name         checkout
	// region       us-east-1
	// LOG_LEVEL    info
	// DB_PASSWORD  <redacted>
	// UPLOADER     <redacted>
}

// Detect is Redact without the redaction: the same decision, reported with the
// score and the rule that produced it.
func ExampleDetect() {
	for _, pair := range [][2]string{
		{"uploader", "AKIAIOSFODNN7EXAMPLE"},
		{"db_password", "hunter2"},
		{"db_password", "changeme"},
		{"region", "us-east-1"},
	} {
		f := secretscrub.Detect(pair[0], pair[1])
		if !f.Found() {
			fmt.Printf("%-12s no finding\n", pair[0])
			continue
		}
		fmt.Printf("%-12s %-28s %v %s\n", pair[0], f.Rule, f.Confidence, f.Masked())
	}
	// Output:
	// uploader     aws-access-key-id            0.98 AKIA************
	// db_password  credential-name              0.80 ************
	// db_password  credential-name-placeholder  0.55 ************
	// region       no finding
}

// ScanText reports where each credential is, which is what a scanner or a
// pre-commit hook needs.
func ExampleScanText() {
	const env = `# deployment
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
LOG_LEVEL=info
`
	for _, f := range secretscrub.ScanText("deploy.env", env) {
		fmt.Printf("%s:%d:%d %s (%v)\n", f.Path, f.Line, f.Column, f.Rule, f.Confidence)
	}
	// Output:
	// deploy.env:2:19 aws-access-key-id (0.98)
}

// RedactText rewrites a whole document. Everything that is not a credential
// survives byte for byte, including quoting, so the file still parses.
func ExampleRedactText() {
	const cfg = `api-key: "AIzaSyD-1234567890abcdefghijklmnopqrstuv"
region: us-east-1
`
	fmt.Print(secretscrub.RedactText(cfg))
	// Output:
	// api-key: "<redacted>"
	// region: us-east-1
}

// A Scanner is a threshold. Raising it drops the maybes and keeps the
// certainties; the same cut applies to reporting and to rewriting.
func ExampleNewScanner() {
	const env = "API_KEY=changeme\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"

	for _, min := range []secretscrub.Confidence{secretscrub.DefaultMinConfidence, 0.9} {
		found := secretscrub.NewScanner(min).ScanText("app.env", env)
		fmt.Printf("at %v: %d finding(s)\n", min, len(found))
	}
	// Output:
	// at 0.50: 2 finding(s)
	// at 0.90: 1 finding(s)
}

// RedactInline finds a credential inside a larger string, such as an error
// message, and reaches into query parameters to do it.
func ExampleRedactInline() {
	fmt.Println(secretscrub.RedactInline(
		"put failed: https://s3.example.com/b/k?versionId=3&X-Amz-Signature=deadbeefcafe1234"))
	// Output:
	// put failed: https://s3.example.com/b/k?versionId=3&X-Amz-Signature=<redacted>
}

// Rules reports what the detector looks for. The registry is a copy, so
// inspecting it cannot change what the detector does.
func ExampleRules() {
	for _, r := range secretscrub.Rules() {
		if r.ID == "aws-access-key-id" {
			fmt.Printf("%s %s %v\n", r.ID, r.Category, r.Confidence)
		}
	}
	// Output:
	// aws-access-key-id cloud 0.98
}

// Detect returns its verdict whatever it scores, so a caller can see what was
// ruled out. Scanner.Meets applies the cut.
func ExampleScanner_Meets() {
	// A PEM certificate is public material, so it sits below the default cut.
	f := secretscrub.DetectValue("-----BEGIN CERTIFICATE-----")
	fmt.Printf("%s %v\n", f.Rule, f.Confidence)

	fmt.Println("default:", secretscrub.NewScanner(0).Meets(f))
	fmt.Println("asking for the tail:", secretscrub.NewScanner(secretscrub.ConfidenceLow).Meets(f))
	// Output:
	// certificate-pem 0.40
	// default: false
	// asking for the tail: true
}
