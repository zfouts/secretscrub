// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/zfouts/secretscrub"
)

func report(w io.Writer, opt options, findings []secretscrub.Finding, scanned int) error {
	switch opt.format {
	case "json":
		return writeJSON(w, findings, scanned)
	case "sarif":
		return writeSARIF(w, findings)
	case "text", "":
		return writeText(w, opt, findings, scanned)
	}
	return fmt.Errorf("unknown -format %q: want text, json or sarif", opt.format)
}

func writeText(w io.Writer, opt options, findings []secretscrub.Finding, scanned int) error {
	for _, f := range findings {
		where := f.Path
		if where == "" {
			where = "(stdin)"
		}
		secret := f.Masked()
		if opt.showSecrets {
			secret = f.Secret
		}
		fmt.Fprintf(w, "%s:%d:%d\n", where, f.Line, f.Column)
		fmt.Fprintf(w, "  %-32s %v  %s\n", f.Rule, f.Confidence, f.Category)
		if f.Key != "" {
			fmt.Fprintf(w, "  %s = %s\n", f.Key, oneLine(secret))
		} else {
			fmt.Fprintf(w, "  %s\n", oneLine(secret))
		}
		fmt.Fprintln(w)
	}
	if opt.quiet {
		return nil
	}
	if len(findings) == 0 {
		fmt.Fprintf(w, "no credentials found in %d file(s)\n", scanned)
		return nil
	}
	fmt.Fprintf(w, "%d credential(s) in %d file(s), scanned %d\n",
		len(findings), countPaths(findings), scanned)
	return nil
}

// oneLine keeps a finding to a single output line. A PEM header or a value with
// a newline in it would otherwise break the "one finding, one place" shape the
// text output promises.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + "…"
	}
	return s
}

func countPaths(findings []secretscrub.Finding) int {
	seen := make(map[string]bool, len(findings))
	for _, f := range findings {
		seen[f.Path] = true
	}
	return len(seen)
}
