// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zfouts/secretscrub"
)

// withStdin swaps os.Stdin for the duration of a call, so the stdin paths can
// be tested without a subprocess.
func withStdin(t *testing.T, content string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = orig })

	go func() {
		_, _ = w.WriteString(content)
		_ = w.Close()
	}()
	fn()
	_ = r.Close()
}

// With no paths it reads standard input, which is how it gets used as a filter:
// `git diff | secretscrub` and `secretscrub -redact < in > out`.
func TestStdin(t *testing.T) {
	t.Run("scan", func(t *testing.T) {
		var code int
		var out, errOut string
		withStdin(t, "K=AKIAIOSFODNN7EXAMPLE\n", func() {
			code, out, errOut = exec(t)
		})
		if code != 1 {
			t.Errorf("exit %d, want 1 (%s)", code, errOut)
		}
		if !strings.Contains(out, "(stdin)") {
			t.Errorf("the finding was not attributed to stdin:\n%s", out)
		}
		if !strings.Contains(out, "aws-access-key-id") {
			t.Errorf("the credential was not reported:\n%s", out)
		}
	})

	t.Run("redact", func(t *testing.T) {
		var out string
		withStdin(t, "K=AKIAIOSFODNN7EXAMPLE\nLOG=info\n", func() {
			_, out, _ = exec(t, "-redact")
		})
		if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("the credential survived:\n%s", out)
		}
		if !strings.Contains(out, "LOG=info") {
			t.Errorf("ordinary configuration was lost:\n%s", out)
		}
	})
}

// The three ways the command answers without scanning anything.
func TestInformationalFlags(t *testing.T) {
	if code, out, _ := exec(t, "-version"); code != 0 || !strings.Contains(out, appName) {
		t.Errorf("-version exited %d with %q", code, out)
	}
	// -h is flag.ErrHelp, which is success and prints the usage to stderr.
	code, _, errOut := exec(t, "-h")
	if code != 0 {
		t.Errorf("-h exited %d", code)
	}
	for _, want := range []string{"usage:", "exit status", "-min-confidence"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("usage is missing %q:\n%s", want, errOut)
		}
	}
	// An unknown flag is an error, not a scan.
	if code, _, _ := exec(t, "-no-such-flag"); code != 2 {
		t.Errorf("an unknown flag exited %d, want 2", code)
	}
}

// Errors have to reach the exit status. A scanner that reports success on a
// file it could not read is worse than one that fails.
func TestUnreadableInputIsAnError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which can read anything")
	}
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "locked.env")
	if err := os.WriteFile(path, []byte(leaky), 0o000); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := exec(t, path); code != 2 {
		t.Errorf("an unreadable file exited %d, want 2 (%s)", code, errOut)
	}
	if code, _, _ := exec(t, "-redact", path); code != 2 {
		t.Errorf("-redact on an unreadable file exited %d, want 2", code)
	}
}

// A file past -max-size is skipped rather than scanned, and skipping is not an
// error.
func TestOversizedFilesAreSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.env")
	if err := os.WriteFile(path, []byte(leaky+strings.Repeat("x", 4096)), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := exec(t, "-max-size", "64", path); code != 0 {
		t.Errorf("an oversized file exited %d, want 0:\n%s", code, out)
	}
	// -redact leaves it alone rather than truncating it.
	if _, _, _ = exec(t, "-redact", "-w", "-max-size", "64", path); true {
		raw, _ := os.ReadFile(path)
		if !strings.Contains(string(raw), "AKIAIOSFODNN7EXAMPLE") {
			t.Error("an oversized file was rewritten anyway")
		}
	}
}

// -redact -w on an already-clean file must not rewrite it, so mtimes and diffs
// stay quiet on repeat runs.
func TestRedactWriteSkipsUnchangedFiles(t *testing.T) {
	dir := t.TempDir()
	clean := filepath.Join(dir, "clean.env")
	if err := os.WriteFile(clean, []byte("LOG_LEVEL=info\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(clean)
	if err != nil {
		t.Fatal(err)
	}
	code, out, _ := exec(t, "-redact", "-w", clean)
	if code != 0 {
		t.Errorf("exit %d", code)
	}
	if strings.Contains(out, "redacted") {
		t.Errorf("a clean file was reported as rewritten:\n%s", out)
	}
	if !strings.Contains(out, "0 file(s) rewritten") {
		t.Errorf("summary missing:\n%s", out)
	}
	after, err := os.Stat(clean)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Error("a clean file was rewritten")
	}
}

// -redact -w reports what it changed, and the file keeps its mode.
func TestRedactWriteReportsAndPreservesMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.env")
	if err := os.WriteFile(path, []byte(leaky), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := exec(t, "-redact", "-w", path)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(out, "redacted ") || !strings.Contains(out, "1 file(s) rewritten") {
		t.Errorf("output did not report the rewrite:\n%s", out)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("mode became %v, want 0600", perm)
		}
	}
}

// oneLine keeps a finding to a single output line. The text scanner works line
// by line, so a finding's secret does not contain a newline today; this guards
// the report against a caller that hands it one, which the library API allows
// because Redact and RedactTree work on whole values.
func TestOneLine(t *testing.T) {
	for in, want := range map[string]string{
		"AKIAIOSFODNN7EXAMPLE":                     "AKIAIOSFODNN7EXAMPLE",
		"-----BEGIN KEY-----\nMIIE\n-----END-----": "-----BEGIN KEY-----…",
		"has\rcarriage":                            "hascarriage",
		"":                                         "",
	} {
		if got := oneLine(in); got != want {
			t.Errorf("oneLine(%q) = %q, want %q", in, got, want)
		}
	}
}

// A PEM block spans lines in the file, but the report still points at one
// place and prints one line.
func TestPEMFindingReportsOneLine(t *testing.T) {
	dir := t.TempDir()
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAy8Dbv8prpJ\n-----END RSA PRIVATE KEY-----\n"
	if err := os.WriteFile(filepath.Join(dir, "id_rsa"), []byte(pem), 0o644); err != nil {
		t.Fatal(err)
	}
	_, out, _ := exec(t, "-show-secrets", dir)
	if n := strings.Count(out, "private-key-pem"); n != 1 {
		t.Errorf("expected one finding, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, ":1:1") {
		t.Errorf("the finding did not point at line 1:\n%s", out)
	}
}

// -exclude matches the whole path as well as the base name, because both are
// what people type.
func TestExcludeMatchesPathAndBase(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "vendored")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "a.env"), []byte(leaky), 0o644); err != nil {
		t.Fatal(err)
	}
	// By base name.
	if _, out, _ := exec(t, "-exclude", "a.env", dir); strings.Contains(out, "a.env") {
		t.Errorf("base-name exclude did not take:\n%s", out)
	}
	// By full path glob, which also proves a directory can be pruned.
	if _, out, _ := exec(t, "-exclude", filepath.Join(dir, "vendored"), dir); strings.Contains(out, "a.env") {
		t.Errorf("path exclude did not take:\n%s", out)
	}
}

// A named file is scanned even when an -exclude would have pruned its
// directory, and a path given twice is scanned once.
func TestCollectDeduplicatesAndAcceptsFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.env")
	if err := os.WriteFile(path, []byte(leaky), 0o644); err != nil {
		t.Fatal(err)
	}
	_, out, _ := exec(t, path, path, dir)
	if n := strings.Count(out, "aws-access-key-id"); n != 1 {
		t.Errorf("the same file was scanned %d times:\n%s", n, out)
	}
}

func TestWorkerCountIsClamped(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{-1, 1}, {0, 1}, {1, 1}, {8, 8}, {16, 16}, {64, 16},
	} {
		if got := clampWorkers(tc.in); got != tc.want {
			t.Errorf("clampWorkers(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
	if got := workers(); got < 1 || got > 16 {
		t.Errorf("workers() = %d, outside the clamp", got)
	}
}

// main is three statements, and the only way to run them is to be the process.
// The subprocess re-exec is the standard way to reach it.
func TestMainRunsAndExits(t *testing.T) {
	if os.Getenv("SECRETSCRUB_TEST_MAIN") == "1" {
		os.Args = []string{appName, "-version"}
		main()
		return
	}
	cmd := osexec.Command(os.Args[0], "-test.run=TestMainRunsAndExits")
	cmd.Env = append(os.Environ(), "SECRETSCRUB_TEST_MAIN=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("main() exited with %v:\n%s", err, out)
	}
	if !strings.Contains(string(out), appName) {
		t.Errorf("main() did not print the version:\n%s", out)
	}
}

// failWriter stands in for a closed pipe or a full disk: the case where the
// report cannot be written at all.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

// A broken stdin is not a clean scan. `secretscrub < /dev/full` and a closed
// pipe both land here, and reporting success would be a lie.
func TestBrokenStdinIsAnError(t *testing.T) {
	broken := func(t *testing.T) {
		t.Helper()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		// Closing the read end makes every read fail.
		_ = r.Close()
		_ = w.Close()
		orig := os.Stdin
		os.Stdin = r
		t.Cleanup(func() { os.Stdin = orig })
	}
	broken(t)
	if code, _, _ := exec(t); code != 2 {
		t.Errorf("scan from a broken stdin exited %d, want 2", code)
	}
	broken(t)
	if code, _, _ := exec(t, "-redact"); code != 2 {
		t.Errorf("redact from a broken stdin exited %d, want 2", code)
	}
}

// A path that does not exist is an error on both halves of the command.
func TestMissingPathIsAnErrorForRedactToo(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	if code, _, _ := exec(t, "-redact", missing); code != 2 {
		t.Errorf("-redact on a missing path exited %d, want 2", code)
	}
}

// A file that can be read but not written. -redact -w has to report the
// failure rather than silently leaving the credential in place.
func TestRedactWriteFailureIsReported(t *testing.T) {
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("needs POSIX permissions and a non-root user")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "readonly.env")
	if err := os.WriteFile(path, []byte(leaky), 0o444); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := exec(t, "-redact", "-w", path)
	if code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
	if !strings.Contains(errOut, "readonly.env") {
		t.Errorf("the failure did not name the file:\n%s", errOut)
	}
	// And it did not half-write it.
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "AKIAIOSFODNN7EXAMPLE") {
		t.Error("the file was modified despite the reported failure")
	}
}

// A directory the walker cannot descend into is an error rather than a silently
// short scan, which would report "no credentials found" for a tree it never
// read.
func TestUnreadableDirectoryIsAnError(t *testing.T) {
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("needs POSIX permissions and a non-root user")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "a.env"), []byte(leaky), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	if code, _, _ := exec(t, dir); code != 2 {
		t.Errorf("an unreadable directory exited %d, want 2", code)
	}
	if code, _, _ := exec(t, "-redact", dir); code != 2 {
		t.Errorf("-redact over an unreadable directory exited %d, want 2", code)
	}
}

// scanFile is where a per-file failure is decided. The CLI reaches most of it,
// but not the cases that need a path which is not an ordinary readable file.
func TestScanFileErrors(t *testing.T) {
	s := secretscrub.NewScanner(0)

	if _, err := scanFile(s, filepath.Join(t.TempDir(), "absent"), 1<<20); err == nil {
		t.Error("a missing file returned no error")
	}
	// A directory opens but does not read.
	if _, err := scanFile(s, t.TempDir(), 1<<20); err == nil {
		t.Error("a directory returned no error")
	}
	// Oversized is skipped, not an error, and yields nothing.
	dir := t.TempDir()
	big := filepath.Join(dir, "big.env")
	if err := os.WriteFile(big, []byte(leaky), 0o644); err != nil {
		t.Fatal(err)
	}
	found, err := scanFile(s, big, 4)
	if err != nil || len(found) != 0 {
		t.Errorf("oversized file gave %d findings, err %v", len(found), err)
	}
}

// looksBinary reads the head of a file, and a read that fails is not "text".
func TestLooksBinaryPropagatesReadErrors(t *testing.T) {
	if _, _, err := looksBinary(errReader{}); err == nil {
		t.Error("a failing reader returned no error")
	}
	// A short file is fine, not an unexpected EOF.
	binary, head, err := looksBinary(strings.NewReader("hello"))
	if err != nil || binary || string(head) != "hello" {
		t.Errorf("short read gave (%v, %q, %v)", binary, head, err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

// The report writers have to surface a write failure, or a full disk looks like
// a clean scan.
func TestReportWriteFailuresSurface(t *testing.T) {
	findings := secretscrub.ScanText("x.env", "K=AKIAIOSFODNN7EXAMPLE\n")
	if len(findings) == 0 {
		t.Fatal("no findings to report")
	}
	for _, format := range []string{"json", "sarif"} {
		if err := report(failWriter{}, options{format: format}, findings, 1); err == nil {
			t.Errorf("%s reported success to a failing writer", format)
		}
	}
	if code := printRules(failWriter{}, options{format: "json"}); code == 0 {
		t.Error("printRules reported success to a failing writer")
	}
}

// A finding with no path is rendered as stdin. The command always sets one, so
// this guards the report against a library caller that does not.
func TestWriteTextLabelsAPathlessFinding(t *testing.T) {
	var b strings.Builder
	f := secretscrub.Detect("db_password", "hunter2")
	f.Line, f.Column = 1, 1
	if err := writeText(&b, options{}, []secretscrub.Finding{f}, 1); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "(stdin)") {
		t.Errorf("a finding with no path was not labelled:\n%s", b.String())
	}
}

// Two findings on the same line differ only by column, which is the last arm of
// the sort.
func TestFindingsOnOneLineSortByColumn(t *testing.T) {
	dir := t.TempDir()
	line := `a="AKIAIOSFODNN7EXAMPLE" b="ghp_1234567890abcdefghijklmnopqrstuvwx"` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "two.env"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	_, out, _ := exec(t, dir)
	aws := strings.Index(out, "aws-access-key-id")
	gh := strings.Index(out, "github-token")
	if aws < 0 || gh < 0 {
		t.Fatalf("both findings should be reported:\n%s", out)
	}
	if aws > gh {
		t.Errorf("findings on one line are not in column order:\n%s", out)
	}
}
