// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// Expanding the paths on the command line into the files to scan.

// collect expands the given paths into the files to scan.
func collect(paths []string, opt options) ([]string, error) {
	var out []string
	seen := make(map[string]bool)
	for _, root := range paths {
		info, err := os.Stat(root)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			if !excluded(root, opt) && !seen[root] {
				seen[root] = true
				out = append(out, root)
			}
			continue
		}
		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if !opt.all && skipDirs[d.Name()] && path != root {
					return filepath.SkipDir
				}
				if excluded(path, opt) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || excluded(path, opt) || seen[path] {
				return nil
			}
			seen[path] = true
			out = append(out, path)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

// excluded reports whether a path matches any -exclude glob, against both the
// whole path and its base name, because both are what people type.
func excluded(path string, opt options) bool {
	base := filepath.Base(path)
	for _, pattern := range opt.excludes {
		if ok, _ := filepath.Match(pattern, path); ok {
			return true
		}
		if ok, _ := filepath.Match(pattern, base); ok {
			return true
		}
	}
	return false
}

// workers is how many files are scanned at once.
func workers() int { return clampWorkers(runtime.GOMAXPROCS(0)) }

// clampWorkers bounds the pool. Separate from workers so the bounds can be
// tested: GOMAXPROCS on the test machine is one value, and the branches that
// matter are the two it is not.
//
// The ceiling is there because the work is IO-bound on file reads; past a
// point more goroutines buy nothing and cost scheduler time and memory.
func clampWorkers(n int) int {
	if n < 1 {
		return 1
	}
	if n > 16 {
		return 16
	}
	return n
}
