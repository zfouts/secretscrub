// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/zfouts/secretscrub"
)

func redactPaths(scanner *secretscrub.Scanner, opt options, paths []string, stdout, stderr io.Writer) int {
	if len(paths) == 0 {
		text, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(stderr, "secretscrub: stdin: %v\n", err)
			return 2
		}
		fmt.Fprint(stdout, scanner.RedactText(string(text)))
		return 0
	}

	files, err := collect(paths, opt)
	if err != nil {
		fmt.Fprintf(stderr, "secretscrub: %v\n", err)
		return 2
	}
	status := 0
	changed := 0
	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil {
			fmt.Fprintf(stderr, "secretscrub: %s: %v\n", path, err)
			status = 2
			continue
		}
		if info.Size() > opt.maxSize {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "secretscrub: %s: %v\n", path, err)
			status = 2
			continue
		}
		clean := scanner.RedactText(string(raw))
		if !opt.write {
			fmt.Fprint(stdout, clean)
			continue
		}
		if clean == string(raw) {
			continue
		}
		if err := os.WriteFile(path, []byte(clean), info.Mode().Perm()); err != nil {
			fmt.Fprintf(stderr, "secretscrub: %s: %v\n", path, err)
			status = 2
			continue
		}
		changed++
		if !opt.quiet {
			fmt.Fprintf(stdout, "redacted %s\n", path)
		}
	}
	if opt.write && !opt.quiet {
		fmt.Fprintf(stdout, "%d file(s) rewritten\n", changed)
	}
	return status
}
