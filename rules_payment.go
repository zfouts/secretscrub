// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import "regexp"

// paymentRules recognize credentials that move money.
var paymentRules = []Rule{
	{
		ID: "stripe-api-key", Category: CategoryPayment, Confidence: 0.98,
		Description: "Stripe secret, restricted or publishable key",
		Contains:    "_",
		Pattern:     regexp.MustCompile(`\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b`),
	},
	{
		ID: "stripe-webhook-secret", Category: CategoryPayment, Confidence: 0.97,
		Description: "Stripe webhook signing secret",
		Contains:    "whsec_",
		Pattern:     regexp.MustCompile(`\bwhsec_[A-Za-z0-9]{20,}\b`),
	},
	{
		ID: "square-token", Category: CategoryPayment, Confidence: 0.97,
		Description: "Square access or application secret",
		Contains:    "sq0",
		Pattern:     regexp.MustCompile(`\bsq0(?:atp|csp|idp)-[A-Za-z0-9_-]{20,}\b`),
	},
	{
		ID: "braintree-access-token", Category: CategoryPayment, Confidence: 0.98,
		Description: "Braintree production access token",
		Contains:    "access_token$production$",
		Pattern:     regexp.MustCompile(`\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b`),
	},
	{
		ID: "shopify-token", Category: CategoryPayment, Confidence: 0.98,
		Description: "Shopify access token, shared secret or private app password",
		Contains:    "shp",
		Pattern:     regexp.MustCompile(`\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b`),
	},
}
