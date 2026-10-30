// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

// Package osv matches an operator-supplied OSV extract to an SBOM.
// Same fail-closed rule as kev: a missing input is needs_human.
package osv

import (
	"fmt"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/watchers/kev"
)

// Item is one advisory row.
type Item struct {
	ID   string `json:"id"`
	PURL string `json:"purl"`
}

// Match compares PURLs.
func Match(sbom []kev.Component, items []Item) failsafe.Result {
	const watcher = "osv"
	if len(sbom) == 0 {
		return failsafe.NeedsHuman(watcher, "no SBOM; refusing to claim the stack is clear of OSV", fmt.Errorf("sbom missing"))
	}
	if len(items) == 0 {
		return failsafe.NeedsHuman(watcher, "no OSV extract", fmt.Errorf("osv missing"))
	}
	var findings []failsafe.Finding
	for _, c := range sbom {
		for _, it := range items {
			if c.PURL != "" && c.PURL == it.PURL {
				findings = append(findings, failsafe.Finding{
					ID: "osv-" + it.ID, Watcher: watcher,
					Title:   "SBOM component matches an OSV row",
					Summary: c.PURL + " matches " + it.ID,
					CIA:     "integrity", Lesson: "L7 supply chain", Severity: "high",
					Asset: c.Name, Detection: "det-osv-sbom",
					Evidence: []failsafe.Evidence{{Key: "id", Value: it.ID}, {Key: "purl", Value: c.PURL}},
				})
			}
		}
	}
	if len(findings) == 0 {
		return failsafe.JustOK(watcher, "no SBOM component matched the supplied OSV extract")
	}
	return failsafe.FromFindings(watcher, "OSV match needs a human", findings, nil)
}
