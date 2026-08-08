// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"

	"github.com/zfouts/secretscrub"
)

func scanPaths(scanner *secretscrub.Scanner, opt options, paths []string, stdout, stderr io.Writer) int {
	var (
		findings []secretscrub.Finding
		scanned  int
		failed   bool
	)

	if len(paths) == 0 {
		text, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(stderr, "secretscrub: stdin: %v\n", err)
			return 2
		}
		findings = scanner.ScanText("(stdin)", string(text))
		scanned = 1
	} else {
		files, err := collect(paths, opt)
		if err != nil {
			fmt.Fprintf(stderr, "secretscrub: %v\n", err)
			return 2
		}
		scanned = len(files)
		var (
			mu sync.Mutex
			wg sync.WaitGroup
		)
		work := make(chan string)
		for range workers() {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for path := range work {
					found, err := scanFile(scanner, path, opt.maxSize)
					mu.Lock()
					if err != nil {
						fmt.Fprintf(stderr, "secretscrub: %s: %v\n", path, err)
						failed = true
					}
					findings = append(findings, found...)
					mu.Unlock()
				}
			}()
		}
		for _, path := range files {
			work <- path
		}
		close(work)
		wg.Wait()
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Column < findings[j].Column
	})

	if err := report(stdout, opt, findings, scanned); err != nil {
		fmt.Fprintf(stderr, "secretscrub: %v\n", err)
		return 2
	}
	switch {
	case failed:
		return 2
	case len(findings) > 0 && !opt.exitZero:
		return 1
	}
	return 0
}

func scanFile(scanner *secretscrub.Scanner, path string, maxSize int64) ([]secretscrub.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxSize {
		return nil, nil
	}
	binary, head, err := looksBinary(f)
	if err != nil {
		return nil, err
	}
	if binary {
		// A credential in a compiled object is not one anybody edits, and the
		// byte soup around it produces findings nobody can act on.
		return nil, nil
	}
	rest, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return scanner.ScanText(path, string(head)+string(rest)), nil
}

// looksBinary reads the head of a file and reports whether it holds a NUL,
// returning the bytes it consumed so the caller need not seek.
func looksBinary(r io.Reader) (binary bool, head []byte, err error) {
	head = make([]byte, 8<<10)
	n, err := io.ReadFull(r, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return false, nil, err
	}
	head = head[:n]
	for _, b := range head {
		if b == 0 {
			return true, head, nil
		}
	}
	return false, head, nil
}
