// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const leaky = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD=hunter2\nLOG_LEVEL=info\n"

// exec runs the command and returns its status and the two streams, so a test
// asserts on what a caller in CI would actually see.
func exec(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func writeTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "deploy.env"), []byte(leaky), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("LOG_LEVEL=info\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Vendored code is somebody else's to rotate, and a scanner that buries the
	// findings a user can act on is a scanner they turn off.
	vendor := filepath.Join(dir, "node_modules")
	if err := os.MkdirAll(vendor, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendor, "dep.env"), []byte(leaky), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The exit status is the whole interface in CI: 1 means "there are credentials
// here", and a pipeline that cannot tell that from an error is one that either
// blocks on nothing or passes on everything.
func TestExitStatusReportsWhatHappened(t *testing.T) {
	dir := writeTree(t)

	if code, out, _ := exec(t, dir); code != 1 {
		t.Errorf("scan with findings exited %d, want 1\n%s", code, out)
	}
	if code, out, _ := exec(t, filepath.Join(dir, "clean.txt")); code != 0 {
		t.Errorf("clean scan exited %d, want 0\n%s", code, out)
	}
	if code, _, _ := exec(t, "-exit-zero", dir); code != 0 {
		t.Errorf("-exit-zero still exited %d", code)
	}
	if code, _, errOut := exec(t, "-format", "yaml", dir); code != 2 {
		t.Errorf("an unknown format exited %d, want 2 (%s)", code, errOut)
	}
	if code, _, _ := exec(t, filepath.Join(dir, "does-not-exist")); code != 2 {
		t.Errorf("a missing path exited %d, want 2", code)
	}
}

func TestVendoredCodeIsSkippedUnlessAsked(t *testing.T) {
	dir := writeTree(t)

	_, out, _ := exec(t, dir)
	if strings.Contains(out, "node_modules") {
		t.Errorf("vendored code was scanned by default:\n%s", out)
	}
	_, all, _ := exec(t, "-all", dir)
	if !strings.Contains(all, "node_modules") {
		t.Errorf("-all did not reach vendored code:\n%s", all)
	}
	_, excluded, _ := exec(t, "-exclude", "*.env", dir)
	if strings.Contains(excluded, "deploy.env") {
		t.Errorf("-exclude did not take:\n%s", excluded)
	}
}

// A report is a thing people paste into tickets and chat. Copying the
// credential into it moves the problem rather than finding it.
func TestReportsNeverCarryTheSecret(t *testing.T) {
	dir := writeTree(t)

	for _, format := range []string{"text", "json", "sarif"} {
		_, out, _ := exec(t, "-format", format, dir)
		if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("%s output printed the credential:\n%s", format, out)
		}
		if !strings.Contains(out, "AKIA") {
			t.Errorf("%s output kept nothing to recognize the credential by:\n%s", format, out)
		}
	}
	// The exception is explicit, and only for a human at a terminal.
	_, shown, _ := exec(t, "-show-secrets", dir)
	if !strings.Contains(shown, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("-show-secrets did not show it:\n%s", shown)
	}
}

func TestJSONOutputIsMachineReadable(t *testing.T) {
	dir := writeTree(t)
	_, out, _ := exec(t, "-format", "json", dir)

	var doc struct {
		Detector string `json:"detector"`
		Scanned  int    `json:"scanned_files"`
		Findings []struct {
			Path       string  `json:"path"`
			Line       int     `json:"line"`
			Rule       string  `json:"rule"`
			Confidence float64 `json:"confidence"`
			Masked     string  `json:"masked"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if doc.Detector != "secretscrub" || doc.Scanned != 2 {
		t.Errorf("detector %q over %d files", doc.Detector, doc.Scanned)
	}
	if len(doc.Findings) != 2 {
		t.Fatalf("got %d findings, want 2:\n%s", len(doc.Findings), out)
	}
	for _, f := range doc.Findings {
		if f.Line == 0 || f.Rule == "" || f.Confidence <= 0 || f.Masked == "" {
			t.Errorf("incomplete finding: %+v", f)
		}
	}
}

// Raising the bar has to remove the maybes and keep the certainties, or the
// score is decorative.
func TestMinConfidenceFilters(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.env")
	if err := os.WriteFile(path, []byte(leaky+"API_KEY=changeme\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, loose, _ := exec(t, "-quiet", path)
	_, strict, _ := exec(t, "-quiet", "-min-confidence", "0.9", path)
	if strings.Count(loose, "\n") <= strings.Count(strict, "\n") {
		t.Errorf("raising the cut did not reduce the findings:\n--- default\n%s\n--- strict\n%s", loose, strict)
	}
	if !strings.Contains(strict, "aws-access-key-id") {
		t.Errorf("a certain finding was filtered out:\n%s", strict)
	}
	if strings.Contains(strict, "placeholder") {
		t.Errorf("a placeholder survived a 0.9 cut:\n%s", strict)
	}
}

func TestRedactRewritesInPlace(t *testing.T) {
	dir := writeTree(t)
	path := filepath.Join(dir, "deploy.env")

	// Without -w the file is untouched and the result goes to stdout, so a
	// caller can look before committing to it.
	_, out, _ := exec(t, "-redact", path)
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("redacted output still held the key:\n%s", out)
	}
	if raw, _ := os.ReadFile(path); string(raw) != leaky {
		t.Errorf("the file was rewritten without -w:\n%s", raw)
	}

	if code, _, errOut := exec(t, "-redact", "-w", "-quiet", path); code != 0 {
		t.Fatalf("in-place redact exited %d: %s", code, errOut)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, gone := range []string{"AKIAIOSFODNN7EXAMPLE", "hunter2"} {
		if strings.Contains(got, gone) {
			t.Errorf("%q survived the rewrite:\n%s", gone, got)
		}
	}
	if !strings.Contains(got, "LOG_LEVEL=info") {
		t.Errorf("ordinary configuration was lost:\n%s", got)
	}
	// The rewritten file scans clean, which is the only claim that matters.
	if code, _, _ := exec(t, path); code != 0 {
		t.Errorf("the rewritten file still scans dirty:\n%s", got)
	}
}

// A scanner you cannot review is one you have to trust. -rules is how it says
// what it looks for.
func TestRulesAreListable(t *testing.T) {
	code, out, _ := exec(t, "-rules")
	if code != 0 {
		t.Fatalf("-rules exited %d", code)
	}
	for _, want := range []string{"aws-access-key-id", "CLOUD", "shape rules"} {
		if !strings.Contains(out, want) {
			t.Errorf("-rules output is missing %q:\n%s", want, out)
		}
	}

	code, jsonOut, _ := exec(t, "-rules", "-format", "json")
	if code != 0 {
		t.Fatalf("-rules -format json exited %d", code)
	}
	var list []struct {
		ID         string  `json:"id"`
		Confidence float64 `json:"confidence"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &list); err != nil {
		t.Fatalf("rule list is not JSON: %v", err)
	}
	if len(list) < 50 {
		t.Errorf("only %d rules listed", len(list))
	}
}

// A compiled object holds credentials no one edits, wrapped in byte soup that
// produces findings no one can act on.
func TestBinaryFilesAreSkipped(t *testing.T) {
	dir := t.TempDir()
	blob := append([]byte("AKIAIOSFODNN7EXAMPLE\x00"), bytes.Repeat([]byte{0x01}, 64)...)
	if err := os.WriteFile(filepath.Join(dir, "a.bin"), blob, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := exec(t, dir); code != 0 {
		t.Errorf("a binary file produced findings (exit %d):\n%s", code, out)
	}
}
