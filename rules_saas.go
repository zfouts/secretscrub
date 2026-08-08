// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import "regexp"

// Application platform, API and model provider credentials.
var saasRules = []Rule{
	{
		ID: "atlassian-api-token", Category: CategorySaaS, Confidence: 0.97,
		Description: "Atlassian (Jira, Confluence) API token",
		Contains:    "atatt3",
		Pattern:     regexp.MustCompile(`\bATATT3[A-Za-z0-9_=-]{20,}\b`),
	},
	{
		ID: "linear-api-key", Category: CategorySaaS, Confidence: 0.97,
		Description: "Linear API key",
		Contains:    "lin_api_",
		Pattern:     regexp.MustCompile(`\blin_api_[A-Za-z0-9]{32,}\b`),
	},
	{
		// No prefilter: the two prefixes share no literal, and a filter that
		// covers only one of them silently switches the other off.
		ID: "notion-token", Category: CategorySaaS, Confidence: 0.95,
		Description: "Notion integration token",
		Pattern:     regexp.MustCompile(`\b(?:secret_|ntn_)[A-Za-z0-9]{35,}\b`),
		MinLen:      39, // "ntn_" + 35
	},
	{
		ID: "asana-pat", Category: CategorySaaS, Confidence: 0.92,
		Description: "Asana personal access token",
		Contains:    "/",
		Pattern:     regexp.MustCompile(`\b\d/\d{16}:[a-f0-9]{32}\b`),
	},
	{
		ID: "dropbox-token", Category: CategorySaaS, Confidence: 0.95,
		Description: "Dropbox short-lived access token",
		Contains:    "sl.",
		Pattern:     regexp.MustCompile(`\bsl\.[A-Za-z0-9_-]{130,}\b`),
	},
	{
		ID: "figma-token", Category: CategorySaaS, Confidence: 0.95,
		Description: "Figma personal access token",
		Contains:    "figd_",
		Pattern:     regexp.MustCompile(`\bfigd_[A-Za-z0-9_-]{40,}\b`),
	},
	{
		ID: "postman-api-key", Category: CategorySaaS, Confidence: 0.98,
		Description: "Postman API key",
		Contains:    "pmak-",
		Pattern:     regexp.MustCompile(`\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b`),
	},
	{
		ID: "newrelic-key", Category: CategorySaaS, Confidence: 0.97,
		Description: "New Relic user, account, insights or REST key",
		Contains:    "nr",
		Pattern:     regexp.MustCompile(`\bNR(?:AK|AA|II|IQ|RA)-[A-Za-z0-9]{27}\b`),
	},
	{
		ID: "grafana-token", Category: CategorySaaS, Confidence: 0.95,
		Description: "Grafana Cloud access policy or service account token",
		Contains:    "gl",
		Pattern:     regexp.MustCompile(`\bgl(?:c|sa)_[A-Za-z0-9_]{32,}\b`),
	},
	{
		ID: "databricks-token", Category: CategorySaaS, Confidence: 0.95,
		Description: "Databricks personal access token",
		Contains:    "dapi",
		Pattern:     regexp.MustCompile(`\bdapi[a-f0-9]{32}(?:-\d)?\b`),
	},
	{
		ID: "sentry-dsn", Category: CategorySaaS, Confidence: 0.9,
		Description: "Sentry DSN; the public key authorizes event submission",
		Contains:    "sentry.io",
		Pattern:     regexp.MustCompile(`(?i)https://[0-9a-f]{32}(?::[0-9a-f]{32})?@[a-z0-9.-]*sentry\.io/\d+`),
	},
	{
		ID: "okta-token", Category: CategorySaaS, Confidence: 0.8,
		Description: "Okta API token",
		Contains:    "00",
		Pattern:     regexp.MustCompile(`\b00[A-Za-z0-9_-]{40}\b`),
		MinEntropy:  4.0,
	},
}

// aiRules recognize model provider keys.
var aiRules = []Rule{
	{
		ID: "anthropic-api-key", Category: CategoryAI, Confidence: 0.99,
		Description: "Anthropic API key",
		Contains:    "sk-ant-",
		Pattern:     regexp.MustCompile(`\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b`),
	},
	{
		ID: "openai-api-key", Category: CategoryAI, Confidence: 0.97,
		Description: "OpenAI project, service account or admin key",
		Contains:    "sk-",
		Pattern:     regexp.MustCompile(`\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}\b`),
	},
	{
		ID: "openai-api-key-legacy", Category: CategoryAI, Confidence: 0.9,
		Description: "OpenAI legacy API key",
		Contains:    "sk-",
		Pattern:     regexp.MustCompile(`\bsk-[A-Za-z0-9]{32,}\b`),
	},
	{
		ID: "huggingface-token", Category: CategoryAI, Confidence: 0.96,
		Description: "Hugging Face user access token",
		Contains:    "hf_",
		Pattern:     regexp.MustCompile(`\bhf_[A-Za-z0-9]{34,}\b`),
	},
	{
		ID: "replicate-token", Category: CategoryAI, Confidence: 0.94,
		Description: "Replicate API token",
		Contains:    "r8_",
		Pattern:     regexp.MustCompile(`\br8_[A-Za-z0-9]{37,}\b`),
	},
}
