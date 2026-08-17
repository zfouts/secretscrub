// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import "testing"

// The name tiers: what a field name is allowed to decide on its own.

// TestRedact_KubernetesReferencesSurvive covers the shape Kubernetes objects
// are full of: a field that POINTS at a credential without containing one. The
// pointer is an edge in the dependency graph, so redacting it
// costs real signal and protects nothing.
func TestRedact_KubernetesReferencesSurvive(t *testing.T) {
	refs := map[string]string{
		"secretName":                     "checkout-tls",
		"secretKeyRef":                   "checkout-creds",
		"imagePullSecrets":               "ghcr-pull",
		"keyName":                        "database-password",
		"cert-manager.io/cluster-issuer": "letsencrypt-prod",
	}
	for name, value := range refs {
		if got, redacted := Redact(name, value); redacted {
			t.Errorf("%s=%q names a secret rather than holding one, got %q", name, value, got)
		}
	}
}

// TestRedact_ProviderEnumsSurvive is the regression test for the defect that
// motivated the hard/soft name split.
//
// "key" and "encrypt" match as bare substrings, and RedactTree carries a
// parent's name down to its leaves, so naming an ARM block "encryption" was
// enough to replace everything inside it with the marker. That is not a display
// problem: downstream code reads the stored payload, so "<redacted>" reached a
// comparison against "Microsoft.Keyvault" and answered false. A CMK-encrypted
// storage account was reported as confidently unencrypted, which is strictly
// worse than reporting it as unknown.
//
// Every value here is a real enum or reference a downstream check reads.
func TestRedact_ProviderEnumsSurvive(t *testing.T) {
	enums := map[string]string{
		// Azure ARM.
		"keySource":           "Microsoft.Keyvault",
		"encryptionType":      "EncryptionAtRestWithCustomerKey",
		"protectorType":       "ServiceManaged",
		"minimumTlsVersion":   "TLS1_2",
		"diskEncryptionSetId": "/subscriptions/0000/resourceGroups/rg/providers/des",
		// AWS.
		"SSEAlgorithm":   "aws:kms",
		"KeyState":       "Enabled",
		"KeyUsage":       "ENCRYPT_DECRYPT",
		"KeyManager":     "CUSTOMER",
		"KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
		// Kubernetes and GCP.
		"sessionAffinity":       "ClientIP",
		"authorizationMode":     "RBAC",
		"privateIpGoogleAccess": "true",
	}
	for name, value := range enums {
		if got, redacted := Redact(name, value); redacted {
			t.Errorf("provider enum %s=%q was redacted as a secret, got %q", name, value, got)
		}
	}
}

// TestRedact_OperatorAuthoredNamesStayStrong guards the exception that keeps the
// split safe. A person who names a variable TLS_CERT put a certificate in it;
// a provider that names a field certificateSource did not. Casing is what tells
// the two populations apart, so the promotion rule is pinned here.
func TestRedact_OperatorAuthoredNamesStayStrong(t *testing.T) {
	for _, name := range []string{
		"AUTH_HEADER", "TLS_CERT", "PRIVATE_KEY_PEM", "SESSION_SEED",
		"JWT_SIGNING_KEY", "ssh-private-key",
	} {
		if got, redacted := Redact(name, "plain-looking-value"); !redacted {
			t.Errorf("operator-authored %s should be redacted, got %q", name, got)
		}
	}
	// Still allowlisted, still readable: downstream checks need these.
	for _, name := range []string{"KMS_KEY_ARN", "PUBLIC_KEY_URL", "KMS_KEY_ID"} {
		if got, redacted := Redact(name, "arn:aws:kms:us-east-1:1:key/abcd"); redacted {
			t.Errorf("%s should survive the allowlist, got %q", name, got)
		}
	}
}

// TestRedact_AllowlistBeatsTheValueTest covers the fields that name a credential
// while holding a reference to one, or a published vocabulary that merely looks
// encoded. Both were being silenced, and both are what downstream checks read.
//
// Found on a live account: HttpTokens is how an account proves it is on IMDSv2,
// and it was redacted wholesale because "token" is a credential word. An ELB TLS
// policy name was redacted or not depending on its LENGTH —
// "ELBSecurityPolicy-TLS-1-0-2015-04" is 33 characters and cleared the entropy
// floor, "ELBSecurityPolicy-2016-08" is 25 and did not.
func TestRedact_AllowlistBeatsTheValueTest(t *testing.T) {
	readable := map[string]string{
		"HttpTokens":  "required",
		"SslPolicy":   "ELBSecurityPolicy-TLS-1-0-2015-04",
		"SslPolicy13": "ELBSecurityPolicy-TLS13-1-2-2021-06",
		"KmsKeyId":    "arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
	}
	for name, value := range readable {
		if got, redacted := Redact(name, value); redacted {
			t.Errorf("%s=%q was silenced, got %q", name, value, got)
		}
	}

	// The allowlist is narrow: it does not make the detector lenient generally.
	if _, redacted := Redact("description", "dGhpcyBpcyBhIHNlY3JldCB2YWx1ZSBoZXJlMTIz"); !redacted {
		t.Error("the value test stopped working on an ordinary field")
	}
	if _, redacted := Redact("adminPassword", "hunter2"); !redacted {
		t.Error("a weak credential survived its own name")
	}
	// An allowlisted PARENT says nothing about its children.
	if _, redacted := RedactInherited("SslPolicy", "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"); !redacted {
		t.Error("an allowlisted parent name suppressed a child's value test")
	}
}

// Identifiers must survive redaction. They are high-entropy by construction —
// that is what makes them identifiers — and possession of one authorizes
// nothing.
//
// This is not a cosmetic loss. A caller that reads an identifier out of a
// response BEFORE redacting it ends up holding the real value in one place and
// the marker in the other, so the stored copy silently stops being able to
// reproduce what was seen. Every value below is a real one, from a live account.
func TestIdentifiersSurviveRedaction(t *testing.T) {
	cases := []struct{ key, value string }{
		// Cloudflare: 32 hex characters, which is exactly hexRunPattern.
		{"id", "4d87c09dd243c73c6fce67bdae31018f"},
		{"zone_id", "0662f9f9a461455fb69689226d098b98"},
		{"account_id", "16b02e442b825e89ac228c060ddfac1d"},
		// A Worker script's deployed revision.
		{"etag", "9f2a1c4e8b7d6f3a5c1e9b8d7f6a4c2e1b9d8f7a"},
		{"tag", "3ee2774a1a445d3f4bd9f3d09977bc2c"},
		// The AWS shape the exemption was originally written for.
		{"canonicaluser", "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"},
		// Other providers' spellings of the same idea.
		{"uuid", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"},
		{"subscription_id", "d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5"},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			got, redacted := Redact(tc.key, tc.value)
			if redacted {
				t.Errorf("%s was redacted; an identifier is not a credential", tc.key)
			}
			if got != tc.value {
				t.Errorf("%s = %q, want it unchanged", tc.key, got)
			}
		})
	}
}

// The exemption bypasses only the value-shape tier. A name carrying a security
// word is caught one tier earlier, so widening the identifier rule must not have
// opened a hole for a credential that happens to be called an id.
//
// The boundary is not "everything ending in _id survives". These names are
// redacted by IsSensitiveName before identityContainer is ever consulted, and
// that ordering is what makes the widening safe.
func TestCredentialsNamedLikeIdentifiersAreStillRedacted(t *testing.T) {
	cases := []struct{ key, value string }{
		{"secret_id", "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY01"},
		{"cert_id", "bcf41278906a9b9a3a2eec5044ad10d4"},
		{"token_id", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdef"},
		{"password_id", "hunter2hunter2hunter2hunter2hunter2"},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			if _, redacted := Redact(tc.key, tc.value); !redacted {
				t.Errorf("%s survived redaction; a security word in the name must still win", tc.key)
			}
		})
	}
}

// access_key_id and api_key_id survive, and did before this change too: the
// allowlist treats a key's ID as a REFERENCE to a credential rather than as one,
// which is the same reason a check can read an encryption key's ARN. Asserted so
// that a future widening of the identifier rule cannot be blamed for behavior it
// did not introduce, and so the distinction stays written down.
func TestKeyIdentifiersWereAlreadyAllowlisted(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"access_key_id", "AKIAIOSFODNN7EXAMPLE"},
		{"api_key_id", "9f2a1c4e8b7d6f3a5c1e9b8d7f6a4c2e"},
	} {
		if _, redacted := Redact(tc.key, tc.value); redacted {
			t.Errorf("%s is redacted; it is a reference to a credential, not one", tc.key)
		}
	}
}

// The suffix rule must not swallow ordinary words that merely end in the same
// letters, or a genuinely sensitive field could be exempted by its spelling.
func TestIdentifierSuffixDoesNotOverreach(t *testing.T) {
	for _, name := range []string{"valid", "pyramid", "hybrid", "candid", "credentials"} {
		if identityContainer(name) {
			t.Errorf("%q was treated as an identifier container", name)
		}
	}
	for _, name := range []string{"id", "zone_id", "account_id", "uuid", "etag", "owner"} {
		if !identityContainer(name) {
			t.Errorf("%q was not treated as an identifier container", name)
		}
	}
}

// The whole tree, in the shape a Cloudflare zone listing arrives in. The nested
// account.id and plan.id were redacted alongside the top-level one, so the fix
// has to hold at depth.
func TestZonePayloadKeepsItsIdentifiers(t *testing.T) {
	zone := map[string]any{
		"id":     "4d87c09dd243c73c6fce67bdae31018f",
		"name":   "example.com",
		"status": "active",
		"account": map[string]any{
			"id":   "16b02e442b825e89ac228c060ddfac1d",
			"name": "Acme",
		},
		"plan": map[string]any{"id": "0feeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "name": "Free"},
	}
	out, ok := RedactTree("", zone).(map[string]any)
	if !ok {
		t.Fatal("RedactTree did not return a map")
	}
	if out["id"] != zone["id"] {
		t.Errorf("the zone's own id was redacted: %v", out["id"])
	}
	acct, _ := out["account"].(map[string]any)
	if acct == nil || acct["id"] != "16b02e442b825e89ac228c060ddfac1d" {
		t.Errorf("the nested account id was redacted: %v", out["account"])
	}
	plan, _ := out["plan"].(map[string]any)
	if plan == nil || plan["id"] != "0feeeeeeeeeeeeeeeeeeeeeeeeeeeeee" {
		t.Errorf("the nested plan id was redacted: %v", out["plan"])
	}
}

// A field called a name holds a name, and a name is the single thing an
// record of a thing exists to carry.
//
// Cloudflare's Pages projects forced this: production_script_name is
// "pages-worker--6305616-production", exactly 32 characters of [a-z0-9-], which
// is indistinguishable from an encoded token by shape alone. It is the same
// false positive safeNameFragments already documents for TLS policy names —
// whether a value survives must not come down to how long it happens to be.
func TestNamesSurviveRedaction(t *testing.T) {
	cases := []struct{ key, value string }{
		{"production_script_name", "pages-worker--6305616-production"},
		{"name", "pages-worker--7294046-production"},
		{"display_name", "a-very-long-generated-display-name-here"},
		{"bucket_name", "org-prod-artifacts-eu-west-1-replica"},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			got, redacted := Redact(tc.key, tc.value)
			if redacted {
				t.Errorf("%s was redacted; a name is not a credential", tc.key)
			}
			if got != tc.value {
				t.Errorf("%s = %q, want it unchanged", tc.key, got)
			}
		})
	}
}

// The name exemption bypasses only the value-shape tier, so a security word in
// the name still wins. Without this the widening would be a hole rather than a
// correction.
//
// secret_name and every *key*_name spelling are deliberately absent: they are in
// safeNameFragments and were surviving long before this change, on the same
// reasoning that keeps a CMK's ARN readable — a Kubernetes secretRef NAMES a
// Secret rather than holding one, and a downstream check has to be able to read it.
func TestSecretsNamedLikeNamesAreStillRedacted(t *testing.T) {
	for _, key := range []string{"password_name", "credential_name", "passphrase_name", "auth_name"} {
		if _, redacted := Redact(key, "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY01"); !redacted {
			t.Errorf("%s survived redaction; a security word in the name must still win", key)
		}
	}
}

// The issuing authority names WHO signed a certificate; it is a published,
// closed vocabulary and not key material. "cert" in the name was redacting the
// six-letter enum, so every report bound to that field rendered <redacted> on
// every row it could ever have.
func TestCertificateAuthoritySurvives(t *testing.T) {
	for _, v := range []string{"google", "lets_encrypt", "digicert", "ssl_com"} {
		if got, redacted := Redact("certificate_authority", v); redacted {
			t.Errorf("certificate_authority=%q was redacted (got %q)", v, got)
		}
	}
	// The material itself must still go. The allowlist is for the authority's
	// NAME, not for anything else with "certificate" in its key.
	pem := "MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ"
	if _, redacted := Redact("certificate_body", pem); !redacted {
		t.Error("certificate_body survived redaction")
	}
	if _, redacted := Redact("private_key", pem); !redacted {
		t.Error("private_key survived redaction")
	}
}

// The role name AWS Identity Center generates for a permission set, which the
// entropy fallback was scoring at 0.77–0.81 on the strength of its 16-hex
// suffix.
//
// The name half could not save it: identityContainer matches "_name" and
// snake_case, and the SDK spells the field "RoleName". So it was redacted under
// RoleName while the identical string survived one field over inside its own
// Arn — and these are exactly the roles an access review has to read.
func TestAWSReservedSSONamesSurvive(t *testing.T) {
	cases := []struct{ key, value string }{
		{"RoleName", "AWSReservedSSO_AdministratorAccess_1a2b3c4d5e6f7890"},
		{"InstanceProfileName", "AWSReservedSSO_ReadOnly_9f8e7d6c5b4a3210"},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			got, redacted := Redact(tc.key, tc.value)
			if redacted {
				t.Errorf("%s was redacted; an AWS-generated role name is not a credential", tc.key)
			}
			if got != tc.value {
				t.Errorf("%s = %q, want it unchanged", tc.key, got)
			}
		})
	}
	// Exempting the generated name must not exempt the field. A real credential
	// under the same key is still caught by the generic fallback, which is the
	// only tier that can catch one with no marker in it at all.
	if _, redacted := Redact("RoleName", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"); !redacted {
		t.Error("an AWS secret access key survived under RoleName")
	}
}

// An identifier name may overrule a guess from randomness. It may not overrule
// a format that says what it is.
//
// identityContainer bypassed the whole shape tier, so every one of these was
// published verbatim under a name the exemption covers — an RSA private key
// under "Name", an AKIA key under "DisplayName". A PEM header is not a
// measurement of entropy that a field name can outweigh.
func TestIdentityExemptionDoesNotOverruleAnAnchoredFormat(t *testing.T) {
	values := []struct{ what, value string }{
		{"pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----"},
		{"aws-access-key-id", "AKIAIOSFODNN7EXAMPLE"},
		{"github-token", "ghp_16C7e42F292c6912E7710c838347Ae178B4a"},
		{"jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc123"},
	}
	for _, key := range []string{"Name", "DisplayName", "name", "id", "resource_id"} {
		for _, v := range values {
			t.Run(key+"/"+v.what, func(t *testing.T) {
				if _, redacted := Redact(key, v.value); !redacted {
					t.Errorf("%s=%s survived redaction; an anchored format outranks a name", key, v.what)
				}
			})
		}
	}
	// The generic fallbacks are still exempt under those names, which is the
	// whole point of the exemption and the reason identifiers stay readable.
	for _, tc := range []struct{ key, value string }{
		{"id", "4d87c09dd243c73c6fce67bdae31018f"},
		{"name", "pages-worker--6305616-production"},
	} {
		if _, redacted := Redact(tc.key, tc.value); redacted {
			t.Errorf("%s=%q was redacted; the entropy tiers must stay exempt", tc.key, tc.value)
		}
	}
}
