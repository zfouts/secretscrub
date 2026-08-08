// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import "strings"

// credentialNameFragments name a field whose value IS a credential. A match is
// enough to redact on its own, whatever the value looks like.
//
// Matched case-insensitively as substrings, so check what else a fragment hits
// before adding one. This tier is the only thing that catches a weak secret: a
// value under "password" is a credential even when it is "hunter2", and no
// shape test will ever say so.
var credentialNameFragments = []string{
	"apikey", "api_key", "accesskey", "access_key", "secretkey", "secret_key",
	"bearer", "client_secret", "clientsecret",
	"cred", "dsn", "jwt", "otp", "passphrase", "passwd", "password", "pwd",
	"secret", "token", "webhook",
	// Connection strings routinely carry an inline password.
	"connection_string", "connectionstring", "conn_str", "database_url", "db_url", "db_uri",
}

// securityNameFragments name a field that RELATES to a security feature
// without being a credential itself. A match lowers the bar the value has to
// clear; it never redacts on its own.
//
// The distinction between this list and credentialNameFragments is
// load-bearing. Cloud APIs use these words overwhelmingly for enums,
// references and flags — "encryption.keySource": "Microsoft.Keyvault",
// "KeyState": "Enabled", "encryption.type": "EncryptionAtRestWithCustomerKey".
// Redacting on the name alone replaced every one of those with the marker, and
// because RedactTree propagates a parent's name to its leaves, naming a block
// "encryption" was enough to silence everything inside it.
//
// That is not a display bug. Anything reading the stored copy then compares
// against "<redacted>" rather than against "Microsoft.Keyvault" and gets
// false — a customer-key-encrypted account reported as confidently
// unencrypted, which is strictly worse than reporting it as unknown. Redaction
// protects credentials; it may not decide that "Enabled" is one.
var securityNameFragments = []string{
	"auth", "cert", "cipher", "encrypt", "key", "nonce", "private",
	"salt", "seed", "session", "sign", "ssh",
	// "licen" deliberately covers both the US and British spellings.
	"licen",
}

// safeNameFragments name a field that contains a credential word but describes
// a non-secret. Checked before both other lists, and a match short-circuits the
// value test too.
//
// A field can be named for a credential while holding a reference to one, and
// the reference is what downstream code reads: a check for a missing encryption
// key needs that key's ARN. Letting the value test override the allowlist would
// put the problem back, since an ARN or a policy name that happens to look
// opaque would be silenced by the very rule the allowlist disables.
var safeNameFragments = []string{
	"key_arn", "keyarn", "key_id", "keyid", "key_alias", "keyalias",
	"public_key", "publickey", "key_name", "keyname", "signing_profile",
	"secretname", "secret_name", "secretref", "secretkeyref", "keyref",
	"imagepullsecret", "cert-manager.io",
	// These matter most on Kubernetes, where objects point at credentials
	// constantly and almost never carry them: an Ingress names the Secret
	// holding its certificate, a container names the Secret key an environment
	// variable is projected from, a pod names its image-pull Secrets. Those
	// names are edges in a dependency graph, not the credentials themselves.

	// EC2 instance metadata options. "HttpTokens" holds "required" or
	// "optional" and is how an account proves it is on IMDSv2 — one of the
	// most-read EC2 settings there is, and the word "token" was silencing it
	// wholesale.
	"httptokens", "http_tokens",
	// A count or a duration named for a credential is a number about one, not
	// one: token counts, secret rotation intervals, certificate expiry days.
	"tokencount", "token_count", "tokenexpir", "secretcount", "secret_count",
	// TLS policy names are a published, closed vocabulary. They are long and
	// hyphenated enough that the entropy test reads them as encoded material:
	// "ELBSecurityPolicy-TLS-1-0-2015-04" is redacted while
	// "ELBSecurityPolicy-2016-08" survives, so whether a load balancer's most
	// security-relevant field is readable came down to the length of its name.
	"sslpolicy", "ssl_policy", "securitypolicy", "security_policy",
	"tlspolicy", "tls_policy", "ciphersuite", "cipher_suite",
	// The issuing authority is a published, closed vocabulary — "google",
	// "lets_encrypt", "digicert" — and naming who signed a certificate is not
	// the same as holding one. Without this, "cert" in the name redacted the
	// six-letter enum, and every report bound to that field read <redacted> on
	// every row.
	"certificateauthority", "certificate_authority", "certauthority", "cert_authority",
	// WHO wrote a thing, not what authorizes them to. "auth" is on the security
	// list as a substring, so GIT_AUTHOR_NAME and AUTHOR_EMAIL matched it and,
	// being operator-authored, were promoted to the strength of a credential
	// name. The fragments are spelled with their separators on purpose: a bare
	// "author" would allowlist "authorization" too.
	"author_", "_author", "authorname", "authoremail", "authordate",
}

// Classifying a field name: does it assert a credential, merely mention
// security, hold an identifier, or was it written by a person at all.

// IsSensitiveName reports whether a name asserts that its value is a
// credential, such as "password", "api_key" or "client_secret".
//
// A true here is on its own enough to redact. For the weaker "this name
// mentions security" signal, which is not, see [IsSecurityRelatedName].
func IsSensitiveName(name string) bool {
	return matchesFragment(name, credentialNameFragments)
}

// IsSecurityRelatedName reports whether a name relates to a security feature
// without asserting that its value is a credential, such as "encryptionType",
// "keySource" or "certificateMode".
//
// It is a hint that lowers the threshold a value must clear, never a reason to
// redact on its own.
func IsSecurityRelatedName(name string) bool {
	return matchesFragment(name, securityNameFragments)
}

// matchesFragment reports whether name contains any of frags. The safe-name
// allowlist is checked first and takes precedence over both lists.
func matchesFragment(name string, frags []string) bool {
	lower := strings.ToLower(name)
	for _, safe := range safeNameFragments {
		if strings.Contains(lower, safe) {
			return false
		}
	}
	for _, frag := range frags {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	return false
}

// isSafeName reports whether a name is on the allowlist.
func isSafeName(name string) bool {
	lower := strings.ToLower(name)
	for _, safe := range safeNameFragments {
		if strings.Contains(lower, safe) {
			return true
		}
	}
	return false
}

// looksOperatorAuthored reports whether a name was chosen by a person for one
// particular value rather than by a provider for a schema field.
//
// This is what separates "TLS_CERT" from "certificateSource". Both mention a
// certificate, but the first is an environment variable somebody created to
// hold one and the second is a schema enum. For an operator-authored name a
// security-related word is as good as a credential word — nobody calls a
// variable PRIVATE_KEY_PEM and puts a mode flag in it — so it promotes to the
// strength of IsSensitiveName.
//
// The signal is casing, which the two populations do not share. Environment
// variables, tags and parameters are SCREAMING_SNAKE or kebab-case; schema
// field names are camelCase or PascalCase with no separators. The allowlist is
// still checked first, so KMS_KEY_ARN and PUBLIC_KEY_URL stay readable.
func looksOperatorAuthored(name string) bool {
	if strings.ContainsAny(name, "_-") {
		return true
	}
	return name != "" && name == strings.ToUpper(name) &&
		strings.ContainsAny(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

// identityContainer reports whether a name holds an identifier rather than a
// setting or a credential. Such a name exempts its value from the shape tier
// only; a credential word in the name still wins.
//
// Identifiers are high-entropy by construction — that is what makes them
// identifiers — and possession of one authorizes nothing. A Cloudflare zone id
// is 32 hex characters, so the hex rule read every id, zone_id, account.id and
// cert_id in a captured payload as key material. That is worse than losing a
// column: a caller that reads an identifier out of a response BEFORE redacting
// it ends up holding the real value in one place and the marker in the other,
// and the stored copy silently stops being able to reproduce what was seen.
//
// Widening this stays safe because it bypasses only the value tier. A name
// carrying a security word — access_key_id, secret_id, token_id — is already
// caught one tier earlier.
func identityContainer(name string) bool {
	lower := strings.ToLower(name)
	switch lower {
	case "owner", "grantee", "granteeidentifier", "principal", "canonicaluser":
		// The members of an S3 Owner or Grantee — canonical user id, display
		// name, URI, email — name WHO something belongs to. Redacting them
		// loses every ownership and grant relationship in the data.
		return true
	case "id", "uuid", "guid", "etag", "tag":
		// "etag" and "tag" are content digests naming a version of a thing — a
		// deployed revision, an object generation — and possession of one
		// authorizes nothing either.
		return true
	case "name", "displayname", "display_name", "friendlyname", "friendly_name":
		// A field called a name holds a name, and whether it survives must not
		// come down to how long it happens to be. Generated resource names
		// forced this: "pages-worker--6305616-production" is exactly 32
		// characters of [a-z0-9-] and indistinguishable from an encoded token
		// by shape alone.
		return true
	}
	// The spellings providers use for a foreign key and for a label. Matched by
	// suffix rather than enumerated, because the list would otherwise need a
	// line per provider per resource and would be wrong the first time one
	// shipped a new one.
	return strings.HasSuffix(lower, "_id") ||
		strings.HasSuffix(lower, "_uuid") ||
		strings.HasSuffix(lower, "_name")
}

// The {Name, Value} record shape, where the operator's name for a value sits in
// a sibling field rather than in the key a walker sees.

// PairLabel returns the operator-supplied name in a {Name, Value}-shaped
// record, or "" when the map is not that shape.
//
// A name-based detector is structurally blind to this shape. APIs return
// operator-supplied strings either as an object keyed by the operator's own
// name — where the key IS "DB_PASSWORD" and [IsSensitiveName] matches it — or
// as a list of {Name, Value} records, where the key a walker sees is the
// literal "Value" and the operator's name sits in a sibling field. In the
// second shape only value matching remains, which does not catch an ordinary
// password, and the name pass redacts the LABEL while publishing the secret
// beside it. That reads as a scrubbed record and is not one.
//
// Both halves must be present: a lone name labels nothing and a lone value has
// no name to borrow. Matching is case-insensitive because APIs disagree
// ("Key"/"Value" on tags, "name"/"value" on container environments).
func PairLabel(m map[string]any) string {
	var label string
	var hasValue bool
	for k, v := range m {
		switch strings.ToLower(k) {
		case "name", "key", "parameterkey", "tagkey", "outputkey":
			// Only a non-empty string is a usable name.
			if s, ok := v.(string); ok && s != "" {
				label = s
			}
		case "value", "parametervalue", "resolvedvalue", "tagvalue", "outputvalue":
			hasValue = true
		}
	}
	if !hasValue {
		return ""
	}
	return label
}

// IsPairValueKey reports whether a key is the value half of a {Name, Value}
// record, and so should be judged under the name [PairLabel] found.
func IsPairValueKey(k string) bool {
	switch strings.ToLower(k) {
	case "value", "parametervalue", "resolvedvalue", "tagvalue", "outputvalue":
		return true
	}
	return false
}

// isPairLabelKey reports whether a key is the NAME half of a {Name, Value}
// record. Unexported: an implementation detail of RedactTree's pair handling
// rather than a rule a caller should apply on its own.
func isPairLabelKey(k string) bool {
	switch strings.ToLower(k) {
	case "name", "key", "parameterkey", "tagkey", "outputkey":
		return true
	}
	return false
}
