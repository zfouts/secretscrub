// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import (
	"strings"
	"testing"
)

// The registry runs against every leaf of every payload a caller walks, so the
// cost of a value the detector rejects is the number that matters. These
// benchmarks exist to keep an eye on it: a rule added without a Contains
// prefilter shows up here as a jump in BenchmarkDetectOrdinaryValue long before
// anybody notices it in production.

// A value that matches nothing, which is the overwhelmingly common case.
const ordinaryValue = "prod-eu-west-1-assets"

// A value that matches a rule near the end of the registry, so the prefilter
// has to reject almost everything before the match is found.
const matchingValue = "ghp_1234567890abcdefghijklmnopqrstuvwx"

func BenchmarkDetectOrdinaryValue(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		detectShape(ordinaryValue)
	}
}

func BenchmarkDetectMatchingValue(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		detectShape(matchingValue)
	}
}

func BenchmarkDetectHighEntropyValue(b *testing.B) {
	// No rule claims it, so every prefilter runs and then the entropy tier
	// does the work: the worst case for a single value.
	const v = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MEFCQ0RFRkdI"
	b.ReportAllocs()
	for b.Loop() {
		detectShape(v)
	}
}

func BenchmarkRedactByName(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		Redact("DB_PASSWORD", "hunter2")
	}
}

func BenchmarkRedactOrdinaryPair(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		Redact("region", "us-east-1")
	}
}

// benchPayload is the shape of a decoded API response: nested maps, a list of
// records, and mostly leaves that are not credentials.
func benchPayload() map[string]any {
	instances := make([]any, 0, 16)
	for i := 0; i < 16; i++ {
		instances = append(instances, map[string]any{
			"InstanceId":   "i-0123456789abcdef0",
			"InstanceType": "m5.xlarge",
			"State":        map[string]any{"Name": "running", "Code": "16"},
			"Placement":    map[string]any{"AvailabilityZone": "us-east-1a"},
			"Tags": []any{
				map[string]any{"Key": "Name", "Value": "checkout-worker"},
				map[string]any{"Key": "env", "Value": "prod"},
			},
			"MetadataOptions": map[string]any{"HttpTokens": "required"},
		})
	}
	return map[string]any{
		"Reservations": []any{map[string]any{"Instances": instances}},
	}
}

func BenchmarkRedactTree(b *testing.B) {
	payload := benchPayload()
	b.ReportAllocs()
	for b.Loop() {
		RedactTree("", payload)
	}
}

func BenchmarkRedactInline(b *testing.B) {
	const script = "#!/bin/sh\nexport LOG_LEVEL=info\nexport DB_PASSWORD=hunter2\n" +
		"curl -s https://api.example.com/v1/status?token=abc123\n"
	b.ReportAllocs()
	for b.Loop() {
		RedactInline(script)
	}
}

// benchDocument is a file-sized input: mostly ordinary configuration, with one
// credential in it.
func benchDocument() string {
	var b strings.Builder
	for i := 0; i < 200; i++ {
		b.WriteString("log_level: info\nregion: us-east-1\nreplicas: 3\n")
	}
	b.WriteString("api_key: AKIAIOSFODNN7EXAMPLE\n")
	return b.String()
}

func BenchmarkScanText(b *testing.B) {
	doc := benchDocument()
	b.SetBytes(int64(len(doc)))
	b.ReportAllocs()
	for b.Loop() {
		ScanText("bench.yaml", doc)
	}
}

func BenchmarkRedactText(b *testing.B) {
	doc := benchDocument()
	b.SetBytes(int64(len(doc)))
	b.ReportAllocs()
	for b.Loop() {
		RedactText(doc)
	}
}

func BenchmarkShannonEntropy(b *testing.B) {
	const v = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	b.ReportAllocs()
	for b.Loop() {
		shannonEntropy(v)
	}
}

// The obfuscation tier runs on every value no rule claimed, so its cost on a
// value that is NOT an encoding is the number that matters. A value that does
// decode pays a second registry pass, which BenchmarkDetectHighEntropyValue
// above already covers, since that value is valid base64.
func BenchmarkDetectObfuscated(b *testing.B) {
	encoded := "QUtJQUlPU0ZPRE5ON0VYQU1QTEU=" // an AWS key in base64
	b.ReportAllocs()
	for b.Loop() {
		detectObfuscated(encoded)
	}
}

func BenchmarkDetectNotAnEncoding(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		detectObfuscated(ordinaryValue)
	}
}
