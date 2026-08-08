// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	"github.com/zfouts/secretscrub"
)

// SARIF 2.1.0 output, for a CI system that annotates a diff.

// SARIF is what a CI system reads to annotate a diff. The schema is large; only
// the parts a code-scanning UI actually consumes are emitted.
func writeSARIF(w io.Writer, findings []secretscrub.Finding) error {
	type text struct {
		Text string `json:"text"`
	}
	type sarifRule struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		ShortDescription text   `json:"shortDescription"`
	}
	type region struct {
		StartLine   int `json:"startLine"`
		StartColumn int `json:"startColumn"`
	}
	type artifact struct {
		URI string `json:"uri"`
	}
	type physical struct {
		ArtifactLocation artifact `json:"artifactLocation"`
		Region           region   `json:"region"`
	}
	type location struct {
		PhysicalLocation physical `json:"physicalLocation"`
	}
	type result struct {
		RuleID    string             `json:"ruleId"`
		Level     string             `json:"level"`
		Message   text               `json:"message"`
		Locations []location         `json:"locations"`
		Props     map[string]float64 `json:"properties,omitempty"`
	}

	seen := map[string]bool{}
	var declared []sarifRule
	for _, r := range secretscrub.Rules() {
		seen[r.ID] = true
		declared = append(declared, sarifRule{ID: r.ID, Name: r.ID, ShortDescription: text{r.Description}})
	}
	results := make([]result, 0, len(findings))
	for _, f := range findings {
		if !seen[f.Rule] {
			seen[f.Rule] = true
			declared = append(declared, sarifRule{ID: f.Rule, Name: f.Rule, ShortDescription: text{f.Description}})
		}
		level := "warning"
		if f.Confidence >= secretscrub.ConfidenceHigh {
			level = "error"
		}
		msg := fmt.Sprintf("%s (%s, confidence %v): %s", f.Description, f.Category, f.Confidence, f.Masked())
		results = append(results, result{
			RuleID:  f.Rule,
			Level:   level,
			Message: text{msg},
			Locations: []location{{PhysicalLocation: physical{
				ArtifactLocation: artifact{URI: filepath.ToSlash(f.Path)},
				Region:           region{StartLine: f.Line, StartColumn: f.Column},
			}}},
			Props: map[string]float64{"confidence": float64(f.Confidence)},
		})
	}

	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name":    appName,
				"version": version,
				"rules":   declared,
			}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
