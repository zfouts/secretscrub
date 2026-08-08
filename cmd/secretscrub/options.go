// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package main

import "strings"

// Command-line options.

// skipDirs are directories a scan should not descend into by default.
//
// They are not skipped because they cannot hold credentials — node_modules
// absolutely can — but because they hold code the scanned repository does not
// own. A finding there is somebody else's to rotate, and burying the ones the
// user can act on underneath thousands they cannot is how a scanner gets turned
// off. --all overrides this.
var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true,
	"node_modules": true, "vendor": true, ".terraform": true,
	".venv": true, "venv": true, "__pycache__": true,
	".gradle": true, ".idea": true, ".mypy_cache": true, ".pytest_cache": true,
}

type options struct {
	format        string
	minConfidence float64
	maxSize       int64
	excludes      multiFlag
	redact        bool
	write         bool
	all           bool
	showSecrets   bool
	quiet         bool
	exitZero      bool
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
