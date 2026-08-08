// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/zfouts/secretscrub"
)

// The -rules listing: what the detector looks for, and how sure it is.

func printRules(w io.Writer, opt options) int {
	rules := secretscrub.Rules()
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Category != rules[j].Category {
			return rules[i].Category < rules[j].Category
		}
		return rules[i].ID < rules[j].ID
	})
	if opt.format == "json" {
		type out struct {
			ID          string  `json:"id"`
			Category    string  `json:"category"`
			Confidence  float64 `json:"confidence"`
			Description string  `json:"description"`
		}
		list := make([]out, 0, len(rules))
		for _, r := range rules {
			list = append(list, out{r.ID, string(r.Category), float64(r.Confidence), r.Description})
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(list); err != nil {
			return 2
		}
		return 0
	}
	var category secretscrub.Category
	for _, r := range rules {
		if r.Category != category {
			category = r.Category
			fmt.Fprintf(w, "\n%s\n", strings.ToUpper(string(category)))
		}
		fmt.Fprintf(w, "  %-30s %v  %s\n", r.ID, r.Confidence, r.Description)
	}
	fmt.Fprintf(w, "\n%d shape rules, plus name-based detection and entropy scoring.\n", len(rules))
	fmt.Fprintf(w, "Findings are reported at confidence >= %.2f unless -min-confidence says otherwise.\n",
		secretscrub.DefaultMinConfidence)
	return 0
}
