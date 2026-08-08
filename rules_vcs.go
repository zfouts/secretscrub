// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import "regexp"

// vcsRules recognize source forge and package registry tokens.
var vcsRules = []Rule{
	{
		ID: "github-token", Category: CategoryVCS, Confidence: 0.98,
		Description: "GitHub personal access, OAuth, user, server or refresh token",
		Contains:    "gh",
		Pattern:     regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{16,}\b`),
	},
	{
		ID: "github-fine-grained-pat", Category: CategoryVCS, Confidence: 0.99,
		Description: "GitHub fine-grained personal access token",
		Contains:    "github_pat_",
		Pattern:     regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`),
	},
	{
		ID: "gitlab-token", Category: CategoryVCS, Confidence: 0.97,
		Description: "GitLab personal, deploy, runner, pipeline or agent token",
		Contains:    "gl",
		Pattern:     regexp.MustCompile(`\bgl(?:pat|dt|rt|cbt|ft|soat|imt|agent|ptt)-[A-Za-z0-9_-]{20,}\b`),
	},
	{
		ID: "npm-token", Category: CategoryVCS, Confidence: 0.98,
		Description: "npm registry access token",
		Contains:    "npm_",
		Pattern:     regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),
	},
	{
		ID: "pypi-token", Category: CategoryVCS, Confidence: 0.99,
		Description: "PyPI upload token",
		Contains:    "pypi-ageichlwas5vcmc",
		Pattern:     regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b`),
	},
	{
		ID: "rubygems-token", Category: CategoryVCS, Confidence: 0.98,
		Description: "RubyGems API key",
		Contains:    "rubygems_",
		Pattern:     regexp.MustCompile(`\brubygems_[a-f0-9]{48}\b`),
	},
	{
		ID: "docker-hub-pat", Category: CategoryVCS, Confidence: 0.97,
		Description: "Docker Hub personal access token",
		Contains:    "dckr_pat_",
		Pattern:     regexp.MustCompile(`\bdckr_pat_[A-Za-z0-9_-]{20,}\b`),
	},
	{
		ID: "nuget-api-key", Category: CategoryVCS, Confidence: 0.92,
		Description: "NuGet API key",
		Contains:    "oy2",
		Pattern:     regexp.MustCompile(`\boy2[a-z0-9]{43}\b`),
	},
	{
		ID: "jfrog-token", Category: CategoryVCS, Confidence: 0.95,
		Description: "JFrog Artifactory API key or access token",
		Contains:    "akcp",
		Pattern:     regexp.MustCompile(`\bAKCp[A-Za-z0-9]{50,}\b`),
	},
	{
		ID: "sonarqube-token", Category: CategoryCI, Confidence: 0.95,
		Description: "SonarQube user, analysis or project token",
		Contains:    "sq",
		Pattern:     regexp.MustCompile(`\bsq[apu]_[a-f0-9]{40}\b`),
	},
}
