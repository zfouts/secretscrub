// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import "regexp"

// The credentials no provider stamps its name on: bearer tokens, connection
// strings, password hashes, and key material, which announces its own format
// instead.
//
// genericRules also carry the fuzzy tail, whose shapes are shared with things
// that are not credentials at all.
var genericRules = []Rule{
	// ------------------------------------------------------------ generic bearer

	{
		ID: "jwt", Category: CategoryGeneric, Confidence: 0.9,
		Description: "JSON Web Token, including a projected Kubernetes service-account token",
		Contains:    "eyj",
		Pattern:     regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]+`),
	},
	{
		// Anchored at BOTH ends, and the token's charset is spelled out. The
		// open-ended version of this rule (`^(?:bearer|basic|token)\s+\S{8,}`)
		// is correct for a field value, which is a whole string by definition,
		// and wrong for a line of a document, where it fires on every sentence
		// that starts with the word "Basic".
		ID: "authorization-header", Category: CategoryGeneric, Confidence: 0.88,
		Description: "Authorization header value pasted into a field",
		Pattern:     regexp.MustCompile(`(?i)^(?:bearer|basic|token)\s+[A-Za-z0-9+/=_.~-]{8,}$`),
		MinLen:      14, // 5 for "basic" + a space + 8
	},
	{
		ID: "authorization-header-inline", Category: CategoryGeneric, Confidence: 0.9,
		Description: "Authorization header with a credential, written inline",
		Contains:    "authorization",
		Pattern: regexp.MustCompile(
			`(?i)authorization["'\s:=]{1,10}(?:bearer|basic|token)\s+([A-Za-z0-9+/=_.~-]{8,})`),
		Secret: 1,
	},
	{
		ID: "url-embedded-credentials", Category: CategoryDatabase, Confidence: 0.92,
		Description: "credentials embedded in a URL as scheme://user:password@host",
		Contains:    "://",
		Pattern:     regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]+:[^\s/@]+@`),
	},
	{
		ID: "jdbc-password", Category: CategoryDatabase, Confidence: 0.95,
		Description: "password in a JDBC connection string",
		Contains:    "jdbc:",
		Pattern:     regexp.MustCompile(`(?i)jdbc:[a-z0-9]+://\S*[?&;]password=([^\s&;"']+)`),
		Secret:      1,
	},
	{
		ID: "unix-password-hash", Category: CategoryGeneric, Confidence: 0.9,
		Description: "crypt(3) password hash as written by htpasswd or /etc/shadow",
		Contains:    "$",
		Pattern:     regexp.MustCompile(`\$(?:2[aby]|apr1|1|5|6|y)\$[./A-Za-z0-9$]{16,}`),
	},

	// ---------------------------------------------------------------- fuzzy tail

	//
	// Below DefaultMinConfidence on purpose. Each of these fires on a shape an
	// identifier also has, so reporting one by default would bury the findings
	// that matter. A caller that has asked for the tail — a pre-commit hook, an
	// audit of a repository about to be published — lowers the threshold and
	// gets them.

	{
		ID: "hex-private-key-0x", Category: CategoryPrivateKey, Confidence: 0.45,
		Description: "0x-prefixed 256-bit hex value, the shape of a wallet private key",
		Contains:    "0x",
		Pattern:     regexp.MustCompile(`\b0x[a-fA-F0-9]{64}\b`),
	},
}

// keyMaterialRules recognize asymmetric key material: formats that announce
// what they are.
var keyMaterialRules = []Rule{
	{
		ID: "private-key-pem", Category: CategoryPrivateKey, Confidence: 0.99,
		Description: "PEM-encoded private key block",
		Contains:    "private key",
		Pattern:     regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`),
	},
	{
		ID: "pgp-message", Category: CategoryPrivateKey, Confidence: 0.7,
		Description: "PGP message or key block",
		Contains:    "-----begin pgp",
		Pattern:     regexp.MustCompile(`-----BEGIN PGP (?:MESSAGE|PRIVATE KEY BLOCK|SIGNATURE)-----`),
	},
	{
		// Below the default cut deliberately. A certificate is the public half
		// of a key pair — that is what makes it a certificate — so redacting one
		// protects nothing and costs the reader the chain, the issuer and the
		// expiry. It stays in the registry because a repository full of them is
		// still worth being told about when somebody asks, and because a PEM
		// block mislabelled as a certificate is a real way to hide a key.
		ID: "certificate-pem", Category: CategoryPrivateKey, Confidence: ConfidenceLow,
		Description: "PEM certificate, which is public material rather than a secret",
		Contains:    "-----begin certificate",
		Pattern:     regexp.MustCompile(`-----BEGIN CERTIFICATE-----`),
	},
	{
		ID: "putty-private-key", Category: CategoryPrivateKey, Confidence: 0.97,
		Description: "PuTTY private key file",
		Contains:    "putty-user-key-file",
		Pattern:     regexp.MustCompile(`PuTTY-User-Key-File-\d+:`),
	},
	{
		ID: "age-secret-key", Category: CategoryPrivateKey, Confidence: 0.99,
		Description: "age encryption secret key",
		Contains:    "age-secret-key-1",
		Pattern:     regexp.MustCompile(`\bAGE-SECRET-KEY-1[0-9A-Z]{50,}\b`),
	},
	{
		ID: "kubeconfig-client-key", Category: CategoryPrivateKey, Confidence: 0.95,
		Description: "kubeconfig embedded client key",
		Contains:    "client-key-data",
		Pattern:     regexp.MustCompile(`(?i)client-key-data\s*[:=]\s*["']?([A-Za-z0-9+/=]{40,})`),
		Secret:      1,
	},
}
