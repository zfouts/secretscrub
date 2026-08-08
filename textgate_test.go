// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import (
	"strings"
	"testing"
)

// The text gate: why a source file needs a stricter prior than an API payload.

// The detector's tiers are calibrated for a decoded API response. Applied
// unchanged to source code they produce thousands of findings — "token" and
// "key" are words programs use constantly for things that are not credentials,
// and a repository is full of digests and fixtures that are random by design.
// These are the shapes that forced the text-specific gate; every one of them
// appeared in the Go standard library.
func TestSourceCodeIsNotAWallOfFindings(t *testing.T) {
	code := strings.Join([]string{
		`nextToken := s.readHeader()`,
		`s.maxTokenSize = 256`,
		`w.d.tokens = tokens`,
		`state.secret = hs.masterSecret`,
		`m := map[token.Token]string{token.ADD: "all numeric", token.XOR: "all integer"}`,
		`const MaxScanTokenSize = 64 * 1024`,
		`GIT_AUTHOR_NAME=Go Gopher`,
		`GOPRIVATE=vcs-test.golang.org/private`,
		`hash := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"`,
		`s.token = nil`,
	}, "\n")
	if got := ScanText("x.go", code); len(got) != 0 {
		t.Errorf("ordinary source produced %d findings:\n%+v", len(got), got)
	}

	// The gate narrows the prior, it does not switch the detector off. A
	// credential written into the same file is still found.
	real := code + "\n" + `password: "hunter2"` + "\n" + `key = "ghp_1234567890abcdefghijklmnopqrstuvwx"`
	got := ScanText("x.go", real)
	if len(got) != 2 {
		t.Fatalf("got %d findings, want the two real ones:\n%+v", len(got), got)
	}
}
