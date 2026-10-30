// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package kev matches an operator-supplied KEV extract to an operator-supplied
// SBOM. No catalog is downloaded. A missing SBOM is needs_human: no SBOM, no
// claim. Matches are findings for a human, not a patch applied by Sentinel.
package kev

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
)

// Component is one SBOM package. PURL is preferred.
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl,omitempty"`
}

// Item is one KEV row the operator exported.
type Item struct {
	CVE     string `json:"cve"`
	PURL    string `json:"purl,omitempty"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
}

type sbomFile struct {
	Components []Component `json:"components"`
}

type kevFile struct {
	Vulnerabilities []Item `json:"vulnerabilities"`
}

// Match compares the two lists.
func Match(sbom []Component, items []Item) failsafe.Result {
	const watcher = "kev"
	if len(sbom) == 0 {
		return failsafe.NeedsHuman(watcher, "no SBOM; refusing to claim the stack is clear of KEV", fmt.Errorf("sbom missing"))
	}
	if len(items) == 0 {
		return failsafe.NeedsHuman(watcher, "no KEV extract; refusing to claim the stack is clear", fmt.Errorf("kev missing"))
	}
	var findings []failsafe.Finding
	for _, c := range sbom {
		for _, it := range items {
			if !hit(c, it) {
				continue
			}
			findings = append(findings, failsafe.Finding{
				ID: "kev-" + it.CVE, Watcher: watcher,
				Title:   "SBOM component matches a KEV row",
				Summary: c.Name + "@" + c.Version + " matches " + it.CVE,
				CIA:     "integrity", Attack: "T1195", Lesson: "L7 supply chain",
				Severity: "high", Asset: c.Name, Detection: "det-kev-sbom",
				Evidence: []failsafe.Evidence{
					{Key: "cve", Value: it.CVE},
					{Key: "purl", Value: c.PURL},
					{Key: "version", Value: c.Version},
				},
			})
		}
	}
	if len(findings) == 0 {
		return failsafe.JustOK(watcher, "no SBOM component matched the supplied KEV extract")
	}
	return failsafe.FromFindings(watcher, "KEV match needs a human", findings, nil)
}

func hit(c Component, it Item) bool {
	if c.PURL != "" && it.PURL != "" && c.PURL == it.PURL {
		return true
	}
	if it.Product != "" && strings.EqualFold(c.Name, it.Product) && c.Version == it.Version {
		return true
	}
	return false
}

// ParseSBOM reads a minimal CycloneDX-shaped JSON document.
func ParseSBOM(raw []byte) ([]Component, error) {
	var f sbomFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	return f.Components, nil
}

// ParseKEV reads a minimal KEV-shaped JSON document.
func ParseKEV(raw []byte) ([]Item, error) {
	var f kevFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	return f.Vulnerabilities, nil
}
