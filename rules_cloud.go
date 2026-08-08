// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import "regexp"

// cloudRules recognize cloud provider control-plane credentials, and the
// infrastructure tooling that holds them.
var cloudRules = []Rule{
	// ----------------------------------------------------------------------- AWS

	{
		ID: "aws-access-key-id", Category: CategoryCloud, Confidence: 0.98,
		Description: "AWS access key id",
		Pattern:     regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|APKA)[A-Z0-9]{16}\b`),
		MinLen:      20, // a 4-character prefix + 16
	},
	{
		ID: "aws-mws-token", Category: CategoryCloud, Confidence: 0.97,
		Description: "Amazon Marketplace Web Service auth token",
		Contains:    "amzn.mws.",
		Pattern:     regexp.MustCompile(`\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`),
	},

	// --------------------------------------------------------------------- Azure

	{
		ID: "azure-storage-account-key", Category: CategoryCloud, Confidence: 0.98,
		Description: "Azure Storage shared account key",
		Contains:    "accountkey=",
		Pattern:     regexp.MustCompile(`(?i)AccountKey=([A-Za-z0-9+/=]{60,})`),
		Secret:      1,
	},
	{
		ID: "azure-shared-access-key", Category: CategoryCloud, Confidence: 0.95,
		Description: "Azure Service Bus / Event Hub shared access key",
		Contains:    "sharedaccesskey=",
		Pattern:     regexp.MustCompile(`(?i)SharedAccessKey=([A-Za-z0-9+/=]{20,})`),
		Secret:      1,
	},
	{
		ID: "azure-sas-signature", Category: CategoryCloud, Confidence: 0.9,
		Description: "Azure shared access signature",
		Contains:    "sig=",
		Pattern:     regexp.MustCompile(`(?i)[?&]sig=([A-Za-z0-9%+/=]{40,})`),
		Secret:      1,
	},
	{
		ID: "azure-ad-client-secret", Category: CategoryCloud, Confidence: 0.92,
		Description: "Microsoft Entra (Azure AD) application client secret",
		Contains:    "8q~",
		Pattern:     regexp.MustCompile(`\b[A-Za-z0-9_~.-]{3}8Q~[A-Za-z0-9_~.-]{31,34}\b`),
	},

	// ----------------------------------------------------------------------- GCP

	{
		ID: "google-api-key", Category: CategoryCloud, Confidence: 0.97,
		Description: "Google API key",
		Contains:    "aiza",
		Pattern:     regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{30,}\b`),
	},
	{
		ID: "google-oauth-refresh-token", Category: CategoryCloud, Confidence: 0.92,
		Description: "Google OAuth refresh token",
		Contains:    "1//",
		Pattern:     regexp.MustCompile(`\b1//[0-9A-Za-z_-]{30,}\b`),
	},
	// There is deliberately no rule for `"type": "service_account"`. It
	// identifies the FILE, not a credential: the secret in a GCP service
	// account key is its private_key field, which private-key-pem already
	// catches at 0.99. A rule matching the type line would report a finding
	// that names nothing to rotate, and a rewrite acting on it would replace a
	// structural field and leave behind JSON that no longer parses.
	{
		ID: "firebase-cloud-messaging-key", Category: CategoryCloud, Confidence: 0.95,
		Description: "Firebase Cloud Messaging server key",
		Contains:    ":apa91b",
		Pattern:     regexp.MustCompile(`\bAAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{100,}\b`),
	},

	// -------------------------------------------------------------- other clouds

	{
		ID: "alibaba-access-key-id", Category: CategoryCloud, Confidence: 0.9,
		Description: "Alibaba Cloud access key id",
		Contains:    "ltai",
		Pattern:     regexp.MustCompile(`\bLTAI[A-Za-z0-9]{12,20}\b`),
	},
	{
		ID: "digitalocean-token", Category: CategoryCloud, Confidence: 0.98,
		Description: "DigitalOcean personal access, OAuth or refresh token",
		Contains:    "_v1_",
		Pattern:     regexp.MustCompile(`\bdo[oprs]_v1_[a-f0-9]{64}\b`),
	},
	{
		ID: "cloudflare-origin-ca-key", Category: CategoryCloud, Confidence: 0.92,
		Description: "Cloudflare origin CA key",
		Contains:    "v1.0-",
		Pattern:     regexp.MustCompile(`\bv1\.0-[a-f0-9]{24}-[0-9a-zA-Z_-]{140,}\b`),
	},
	{
		ID: "hashicorp-vault-token", Category: CategoryCI, Confidence: 0.95,
		Description: "HashiCorp Vault service or batch token",
		Contains:    "hv",
		Pattern:     regexp.MustCompile(`\bhv[bsr]\.[A-Za-z0-9_-]{24,}\b`),
	},
	{
		ID: "terraform-cloud-token", Category: CategoryCI, Confidence: 0.98,
		Description: "Terraform Cloud / Enterprise API token",
		Contains:    ".atlasv1.",
		Pattern:     regexp.MustCompile(`\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{20,}\b`),
	},
}
