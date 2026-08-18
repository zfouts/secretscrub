// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub_test

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/zfouts/secretscrub"
)

// TestVersionIsWellFormed pins the shape a consumer parses.
func TestVersionIsWellFormed(t *testing.T) {
	if !regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`).MatchString(secretscrub.Version) {
		t.Errorf("Version = %q, want a v-prefixed semver as the module is tagged",
			secretscrub.Version)
	}
}

// TestVersionMatchesTheGitTag is the reason a hand-maintained constant is
// acceptable here.
//
// A version that drifts from the tag is worse than no version at all: a
// consumer recording it alongside redacted data would be answering "which
// redaction produced this" confidently and wrongly, which is the one failure
// this constant exists to prevent.
//
// The check is skipped outside a git checkout — a consumer running `go test`
// against the module cache has no repository to ask, and failing there would
// make this package untestable downstream.
func TestVersionMatchesTheGitTag(t *testing.T) {
	tags, err := exec.Command("git", "tag", "--list", "v*").Output()
	if err != nil {
		t.Skipf("not a git checkout (%v); nothing to compare against", err)
	}
	list := strings.Fields(string(tags))
	if len(list) == 0 {
		t.Skip("no version tags in this checkout")
	}

	// The constant must name a tag that exists. Comparing against the LATEST
	// tag instead would fail on every commit after a release and before the
	// next one, which trains people to ignore it.
	for _, tag := range list {
		if tag == secretscrub.Version {
			return
		}
	}
	t.Errorf("Version = %q, which is not among this repository's tags (%s).\n"+
		"    A consumer records this next to data it scrubbed, so a constant that names no "+
		"release makes that record unresolvable.",
		secretscrub.Version, strings.Join(list, ", "))
}

// TestVersionIsNotBehindTheLatestTag catches the likelier mistake: tagging a
// release and forgetting to move the constant.
//
// It compares against the highest tag rather than requiring equality on every
// commit, and reports rather than guesses when the ordering is not obvious.
func TestVersionIsNotBehindTheLatestTag(t *testing.T) {
	out, err := exec.Command("git", "tag", "--list", "v*", "--sort=-v:refname").Output()
	if err != nil {
		t.Skipf("not a git checkout (%v)", err)
	}
	list := strings.Fields(string(out))
	if len(list) == 0 {
		t.Skip("no version tags")
	}
	if latest := list[0]; latest != secretscrub.Version {
		t.Errorf("the newest tag is %s and Version is %q. If %s was just released, move the "+
			"constant; a release that ships the previous version string tells every consumer "+
			"the wrong thing about what scrubbed their data.",
			latest, secretscrub.Version, latest)
	}
}
