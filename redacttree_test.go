// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import (
	"strings"
	"testing"
)

// RedactTree: walking a decoded payload.

// TestRedactTreeKeepsTheLabel pins the fix for the most misleading failure this
// walker can produce.
//
// Several label fields ("key", "name") match the sensitive-name list on their
// own. Without special handling the walker scrubbed the LABEL and published the
// value beside it, producing a record that reads as redacted while carrying the
// credential in plain sight.
func TestRedactTreeKeepsTheLabel(t *testing.T) {
	// The GCE metadata.items shape.
	in := map[string]any{"key": "startup-script", "value": "export DB_PASSWORD=hunter2-real"}
	out, _ := RedactTree("", in).(map[string]any)

	if out["key"] != "startup-script" {
		t.Errorf("the label was redacted (%v); a label names a value, it is not one", out["key"])
	}
	if v, _ := out["value"].(string); strings.Contains(v, "hunter2-real") {
		t.Errorf("the secret survived beside a scrubbed label: %q", v)
	}
}

// TestRedactTree_ParentNameDoesNotSilenceChildren pins the propagation half of
// the same defect. A block named for a security feature must not turn its
// members into markers, while a leaf that names a credential itself still must.
func TestRedactTree_ParentNameDoesNotSilenceChildren(t *testing.T) {
	in := map[string]any{
		"encryption": map[string]any{
			"keySource": "Microsoft.Keyvault",
			"type":      "EncryptionAtRestWithCustomerKey",
		},
		"transparentDataEncryption": map[string]any{"status": "Enabled"},
		// A list under a credential-named parent: the elements describe the
		// request, they are not tokens.
		"tokenRequests": []any{
			map[string]any{"audience": "vault", "expirationSeconds": "3600"},
		},
		"osProfile": map[string]any{
			"adminUsername": "azureuser",
			"adminPassword": "hunter2",
		},
	}
	out, ok := RedactTree("properties", in).(map[string]any)
	if !ok {
		t.Fatal("RedactTree did not return a map")
	}

	enc := out["encryption"].(map[string]any)
	if got := enc["keySource"]; got != "Microsoft.Keyvault" {
		t.Errorf("encryption.keySource was silenced by its parent: %q", got)
	}
	if got := enc["type"]; got != "EncryptionAtRestWithCustomerKey" {
		t.Errorf("encryption.type was silenced by its parent: %q", got)
	}
	if got := out["transparentDataEncryption"].(map[string]any)["status"]; got != "Enabled" {
		t.Errorf("TDE status was silenced by its parent: %q", got)
	}
	req := out["tokenRequests"].([]any)[0].(map[string]any)
	if got := req["audience"]; got != "vault" {
		t.Errorf("tokenRequests.audience was silenced by its parent: %q", got)
	}

	// The other direction: a leaf whose own name asserts a credential is still
	// redacted, however weak the value looks.
	prof := out["osProfile"].(map[string]any)
	if got := prof["adminPassword"]; got != RedactedMarker {
		t.Errorf("adminPassword survived: %q", got)
	}
	if got := prof["adminUsername"]; got != "azureuser" {
		t.Errorf("adminUsername was redacted: %q", got)
	}
}

// TestRedactTree_AWSTagPairShape covers a {Name, Value} spelling the pair rules
// did not know about.
//
// A name-based detector is blind to a list of named records: the key it sees is
// the literal "TagValue" and the operator's name sits in a sibling. KMS spells
// the pair TagKey/TagValue rather than the Key/Value that EC2 and ELB use, so a
// tag called "secret" published its value verbatim while the label beside it was
// scrubbed — a row that reads as redacted while carrying the credential. Found
// by an end-to-end redaction test against a live account.
func TestRedactTree_AWSTagPairShape(t *testing.T) {
	in := map[string]any{
		"Tags": []any{
			map[string]any{"TagKey": "secret", "TagValue": "s3cr3t-value"},
			map[string]any{"TagKey": "env", "TagValue": "prod"},
		},
	}
	out := RedactTree("", in).(map[string]any)["Tags"].([]any)

	first := out[0].(map[string]any)
	if first["TagValue"] != RedactedMarker {
		t.Errorf("a credential under TagKey=secret survived: %q", first["TagValue"])
	}
	if first["TagKey"] != "secret" {
		t.Errorf("the label was redacted instead of the value: %q", first["TagKey"])
	}

	// An ordinary tag must stay readable, or tagging stops being usable at all.
	second := out[1].(map[string]any)
	if second["TagKey"] != "env" || second["TagValue"] != "prod" {
		t.Errorf("an ordinary tag was redacted: %v", second)
	}
}

// TestRedactTree_IdentityBlocksSurvive is the regression test for an
// over-redaction found by running the parity gate against a real AWS account.
//
// An S3 canonical user id is 64 hex characters, so hexRunPattern matched it and
// every bucket ACL stored its Owner and Grantee ids as the marker. "Which
// account is this bucket granted to" is the cross-account exposure question the
// ACL exists to answer, and it was unanswerable.
//
// The block also has to carry its own name down. The walker propagates only
// names that mean something, so Owner.ID was being judged under the enclosing
// call name — "GetBucketAcl" — which says nothing about what its members are.
func TestRedactTree_IdentityBlocksSurvive(t *testing.T) {
	const canonicalID = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
	in := map[string]any{
		"GetBucketAcl": map[string]any{
			"Owner": map[string]any{"ID": canonicalID, "DisplayName": "acme-prod"},
			"Grants": []any{
				map[string]any{
					"Grantee":    map[string]any{"ID": canonicalID, "Type": "CanonicalUser"},
					"Permission": "FULL_CONTROL",
				},
			},
		},
	}
	acl := RedactTree("", in).(map[string]any)["GetBucketAcl"].(map[string]any)

	if got := acl["Owner"].(map[string]any)["ID"]; got != canonicalID {
		t.Errorf("bucket owner identity was silenced: %v", got)
	}
	grantee := acl["Grants"].([]any)[0].(map[string]any)["Grantee"].(map[string]any)
	if got := grantee["ID"]; got != canonicalID {
		t.Errorf("grantee identity was silenced, so a cross-account grant is invisible: %v", got)
	}

	// The exemption is for identifiers, not for anything that happens to sit
	// near one: a credential under its own name inside the same block still dies.
	withSecret := map[string]any{
		"Owner": map[string]any{"ID": canonicalID, "password": "hunter2"},
	}
	owner := RedactTree("", withSecret).(map[string]any)["Owner"].(map[string]any)
	if owner["password"] != RedactedMarker {
		t.Errorf("a credential inside an identity block survived: %v", owner["password"])
	}
}

// TestRedactTreeKeepsIAMTimestamps walks the shape a stored AWS response really
// has. ListUsers returns the timestamp as a sibling of the user's name and
// arn, so the whole row has to come back readable — a user whose last console
// login reads as the marker is indistinguishable from one who has never logged
// in at all, and the dormant-account finding turns on that difference.
func TestRedactTreeKeepsIAMTimestamps(t *testing.T) {
	payload := map[string]any{
		"Users": []any{
			map[string]any{
				"UserName":            "deploy-bot",
				"Arn":                 "arn:aws:iam::123456789012:user/deploy-bot",
				"CreateDate":          "2023-02-11T18:04:00Z",
				"PasswordLastUsed":    "2026-07-01T00:00:00Z",
				"PasswordLastChanged": "2025-05-06T11:22:33Z",
			},
		},
	}
	out, _ := RedactTree("ListUsers", payload).(map[string]any)
	users, _ := out["Users"].([]any)
	if len(users) != 1 {
		t.Fatalf("expected one user, got %v", out["Users"])
	}
	user, _ := users[0].(map[string]any)
	for _, field := range []string{"PasswordLastUsed", "PasswordLastChanged", "CreateDate"} {
		if user[field] != payload["Users"].([]any)[0].(map[string]any)[field] {
			t.Errorf("%s was redacted: %v", field, user[field])
		}
	}
}
