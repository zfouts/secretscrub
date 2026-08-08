// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

// Command secretscrub finds credentials in files and, on request, removes them.
//
// The detector it runs is the library's, unmodified. That is the point of
// shipping the command from the same module rather than writing a scanner
// beside it: the file this command calls clean and the payload the library
// would redact are judged by the same rules, so the two can never disagree
// about what counts as a credential.
//
// Usage:
//
//	secretscrub [flags] [path ...]
//
// With no paths it reads standard input. Directories are walked. Findings go to
// standard output; the exit status is 1 when there were any, 2 on error.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/zfouts/secretscrub"
)

// version is stamped at build time:
//
//	go build -ldflags "-X main.version=$(git describe --tags)" ./cmd/secretscrub
//
// It is reported alongside every finding set, because a scan is only as good as
// the pattern set that produced it and a reader has to be able to tell whether
// a clean report came from a current detector or an old one.
var version = "dev"

// appName is what the command calls itself in usage, errors and reports.
const appName = "secretscrub"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	var (
		opt         options
		showRules   bool
		showVersion bool
	)
	fset := flag.NewFlagSet("secretscrub", flag.ContinueOnError)
	fset.SetOutput(stderr)
	fset.StringVar(&opt.format, "format", "text", "output format: text, json or sarif")
	fset.Float64Var(&opt.minConfidence, "min-confidence", float64(secretscrub.DefaultMinConfidence),
		"report findings at or above this confidence, from 0 to 1")
	fset.Int64Var(&opt.maxSize, "max-size", 8<<20, "skip files larger than this many bytes")
	fset.Var(&opt.excludes, "exclude", "skip paths matching this glob (repeatable)")
	fset.BoolVar(&opt.redact, "redact", false, "write the input back with its credentials replaced, instead of reporting")
	fset.BoolVar(&opt.write, "w", false, "with -redact, rewrite each file in place instead of writing to stdout")
	fset.BoolVar(&opt.all, "all", false, "descend into vendored and version-control directories too")
	fset.BoolVar(&opt.showSecrets, "show-secrets", false, "print the credential in full rather than masked")
	fset.BoolVar(&opt.quiet, "quiet", false, "print findings only, with no summary")
	fset.BoolVar(&opt.exitZero, "exit-zero", false, "exit 0 even when credentials were found")
	fset.BoolVar(&showRules, "rules", false, "list the detection rules and exit")
	fset.BoolVar(&showVersion, "version", false, "print the version and exit")
	fset.Usage = func() {
		fmt.Fprintf(stderr, "secretscrub finds credentials in files and, with -redact, removes them.\n\n")
		fmt.Fprintf(stderr, "usage: secretscrub [flags] [path ...]\n\n")
		fmt.Fprintf(stderr, "With no paths it reads standard input.\n\n")
		fset.PrintDefaults()
		fmt.Fprintf(stderr, "\nexit status: 0 clean, 1 credentials found, 2 error\n")
	}
	if err := fset.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	switch {
	case showVersion:
		fmt.Fprintf(stdout, "%s %s\n", appName, version)
		return 0
	case showRules:
		return printRules(stdout, opt)
	}

	scanner := secretscrub.NewScanner(secretscrub.Confidence(opt.minConfidence))
	paths := fset.Args()

	if opt.redact {
		return redactPaths(scanner, opt, paths, stdout, stderr)
	}
	return scanPaths(scanner, opt, paths, stdout, stderr)
}
