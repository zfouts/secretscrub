// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import "testing"

// The value tiers: what a value says about itself, and the exemptions that
// keep an identifier, a resource path or a date from being mistaken for one.

// TestRedact_SemiOpaqueValuesUnderSecurityNames covers the tier the split adds:
// a security-related name does not redact on its own, but it lowers the bar the
// value must clear, so medium-length encoded material under such a name still
// dies.
func TestRedact_SemiOpaqueValuesUnderSecurityNames(t *testing.T) {
	if got, redacted := Redact("encryptionKey", "aGVsbG8gd29ybGQxMjM0NTY3ODkw"); !redacted {
		t.Errorf("encoded material under a security name survived: %q", got)
	}
	// The same value under a name with no security meaning is ordinary config
	// and is left alone until it clears the full 32-character opaque test.
	if got, redacted := Redact("description", "aGVsbG8gd29ybGQxMjM0NTY3ODkw"); redacted {
		t.Errorf("ordinary configuration was redacted: %q", got)
	}
}

// TestRedact_GCPResourceReferencesSurvive covers the last of the over-matches
// found while migrating to raw-first collection.
//
// GCP names other resources by path, and those paths are long, mixed-case and
// slash-dense enough to clear the opaque-token test. The behaviour was
// arbitrary rather than merely wrong: "network" survived and "subnetwork" did
// not, because one fell the right side of an entropy threshold. Instance
// sizing, network placement and boot image are the substance of the record, and
// under raw-first there is no curated copy to fall back on.
func TestRedact_GCPResourceReferencesSurvive(t *testing.T) {
	refs := map[string]string{
		"machineType": "zones/us-central1-a/machineTypes/e2-small",
		"network":     "projects/acme-prod/global/networks/default",
		"subnetwork":  "projects/acme-prod/regions/us-central1/subnetworks/default",
		"sourceImage": "projects/debian-cloud/global/images/debian-11-bullseye-v20240110",
		"diskType":    "projects/acme-prod/zones/us-central1-a/diskTypes/pd-balanced",
		"parent":      "organizations/123456789012",
	}
	for name, value := range refs {
		if got, redacted := Redact(name, value); redacted {
			t.Errorf("resource reference %s=%q was redacted, got %q", name, value, got)
		}
	}

	// The exemption is anchored on the leading collection segment, so a
	// credential that merely contains slashes is untouched by it.
	for name, value := range map[string]string{
		"description": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"note":        "AIzaSyD-1234567890abcdefghijklmnopqrstuv",
	} {
		if _, redacted := Redact(name, value); !redacted {
			t.Errorf("a credential escaped through the resource-reference exemption: %s=%q", name, value)
		}
	}
}

// TestRedact_TimestampsAboutCredentialsSurvive covers a name that carries a
// credential word while holding a date.
//
// APIs name the audit trail after the thing it audits, so "password" and
// "accesskey" appear in the names of the fields that say WHEN a credential was
// last used, changed or rotated. The name tier redacts on the name alone, which
// is right for the credential and wrong for the date beside it: the fleet IAM
// audit's "Console Last Used" column, the identity card and the stale-credential
// rules all read exactly these fields, and every one of them was being graded
// against "<redacted>".
func TestRedact_TimestampsAboutCredentialsSurvive(t *testing.T) {
	cases := map[string]string{
		"PasswordLastUsed":              "2026-07-01T00:00:00Z",
		"PasswordLastChanged":           "2024-11-03T09:15:42Z",
		"PasswordNextRotation":          "2026-11-03",
		"password_last_used":            "2026-07-01T00:00:00+00:00",
		"AccessKeyLastUsed":             "2026-06-30T23:59:59.123Z",
		"SecretLastRotated":             "2025-01-15 04:05:06",
		"CredentialReportGeneratedTime": "2026-07-01T00:00:00-07:00",
		"token_expires_at":              "2026-08-01T12:00:00Z",
	}
	for name, value := range cases {
		if got, redacted := Redact(name, value); redacted {
			t.Errorf("%s=%q states when, not what; got %q", name, value, got)
		}
	}

	// The credential itself still goes, under the same names. The exemption is
	// the value's shape, so it protects nothing that is not a date.
	for name, value := range map[string]string{
		"PasswordLastUsed":  "hunter2",
		"AccessKeyLastUsed": "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY01",
		"password":          "2026-07-01T00:00:00Z but also swordfish",
		"api_key":           "2026-07-01-AKIAIOSFODNN7EXAMPLE",
	} {
		if _, redacted := Redact(name, value); !redacted {
			t.Errorf("a credential escaped through the timestamp exemption: %s=%q", name, value)
		}
	}
}
