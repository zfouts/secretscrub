// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"

	"github.com/zfouts/secretscrub"
)

// JSON output.

// jsonFinding is the wire shape. It carries the masked secret and never the
// real one: a report is a thing people paste into tickets and chat, and a
// scanner that copies the credential into its own output has moved the problem
// rather than found it. -show-secrets is the deliberate exception, and it only
// applies to the text format, where a human is looking at a terminal.
type jsonFinding struct {
	Path       string  `json:"path"`
	Line       int     `json:"line"`
	Column     int     `json:"column"`
	Rule       string  `json:"rule"`
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
	Descriptio string  `json:"description,omitempty"`
	Key        string  `json:"key,omitempty"`
	Masked     string  `json:"masked"`
}

func writeJSON(w io.Writer, findings []secretscrub.Finding, scanned int) error {
	out := struct {
		Detector string        `json:"detector"`
		Version  string        `json:"version"`
		Scanned  int           `json:"scanned_files"`
		Findings []jsonFinding `json:"findings"`
	}{
		Detector: appName,
		Version:  version,
		Scanned:  scanned,
		Findings: make([]jsonFinding, 0, len(findings)),
	}
	for _, f := range findings {
		out.Findings = append(out.Findings, jsonFinding{
			Path: f.Path, Line: f.Line, Column: f.Column,
			Rule: f.Rule, Category: string(f.Category), Confidence: float64(f.Confidence),
			Descriptio: f.Description, Key: f.Key, Masked: f.Masked(),
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
